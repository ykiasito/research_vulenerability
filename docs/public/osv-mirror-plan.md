# OSV.devローカルミラー構築 設計案(2026-08-28作成、同日シニアレビュー15項目を反映して全面改訂、設計のみ・未実装)

**実装状況の要約(2026-08-30追記、`known-limitations.md`と突き合わせ)**: タイトルの「設計のみ・未実装」は執筆当時のものであり、その後実装が進んでいる——`known-limitations.md`は2026-08-29時点で「OSVミラー実装(§9-2 A/B検証ゲート通過・`@Component`切り替え済み)」として、実装バグ2件の修正・実測結果まで記述している。以下の本文(設計案そのもの)は当時の検討過程の記録として変更していない。

**本ドキュメントは設計のみ。実装コード・マイグレーション・設定変更は一切含まない。**

**改訂履歴(2026-08-28)**: シニアレビューのREVISE指摘15項目を反映して全面改訂した。主な変更点: (1) `GHSA-*`除外の根拠を「内容が同一だから」から「`GhsaVulnerabilitySource`が既に同じアドバイザリー集合をカバーしているため」へ訂正(§4-1)、(2) baselineの取得方式を単一`all.zip`から10エコシステム別`{ecosystem}/all.zip`へ変更(§6-1)、(3) deltaのカーソル意味論を`modified_id.csv`側のタイムスタンプに統一(§6-2)、(4) `ghsa_advisories`をLEFT JOINして発行IDを決定する設計へ変更(§5-2・§7-1)、(5) 外部入力検証の節を新設(§8-3)、(6) A/B検証ゲートを実装完了条件として追加(§9-2)、(7) 未検証事項1・2・3・6を解決済みに更新(§9-0)、(8) `GhsaVersionRange`→`OsvVersionRange`等のリネーム完了・`OsvEcosystems`新設を反映(§1-2・§5-3)、(9) `queryPackage()`を`OsvLiveQueryClient`へ分離する設計に変更(§7-2)、(10) 各種実測数値の訂正(§0・§2-1・§3等)。詳細は各節の【シニアレビュー項目N】マーカーを参照。

**改訂履歴(2026-08-28、2回目)**: シニアレビューの2回目REVISE指摘8項目を反映した。(1) `OSV-*`を「対象外(想定)」から「取り込む」で確定、接頭辞除外は`GHSA-`/`MAL-`のみと明記し「約13,600件」を下限値と注記(§0(b)・§2-1・§6-1手順3a)、(2) deltaの打ち切りをtimestampグループの境界でのみ行うよう修正し行の恒久欠落を防止(§6-2手順4・7)、(3) 「ディレクトリ名↔エコシステム別zip収録集合が一致する」という未検証の前提を明示化し、検証項目(§9-1)とフォールバック(§8-3(a))を追加、(4) `OsvVulnerabilitySource`の行番号引用を実測値に修正(§1-1)、(5) `Stage2VulnerabilityResearchService.java`の行番号引用を`:99`に修正し重複排除キー(`VulnFinding.cveOrGhsaId()`)を明記、(6) §2-1「その他」件数の算術ズレを訂正、(7) 実測/推定の出典表記の不整合を解消(§6-1・§11、複数zip間重複の根拠を「未実測、保守的な想定」に訂正)、(8) §2-1の539件・136件の出典を確定できず「未確定、実装スパイクで確認する」と明記し§2-2の重複仮説との整合を注記。

**改訂履歴(2026-08-28、3回目)**: シニアレビューの3回目REVISE指摘4項目を反映した。(1) §6-2手順7のカーソル前進ロジックを、1件ごとの前進(矛盾する記述が同居していた)からtimestampグループアトミックへ全面書き直し——グループ内に1件でも失敗があればそのグループのtimestampまで前進させないと明記し、手順4の打ち切りルールがこのグループアトミック規則の帰結であることを付記した。手順2の厳密不等号(`timestamp > last_cursor`)は維持してよいことも明記(§6-2手順4・7)。(2) §9-0項目1の見出しと§0(a)の除外列挙から`OSV-*`を削除——`OSV-*`の扱いは§2-1側で既に「取り込む」と確定しており、§9-0項目1は実測内容通りNuGet/RubyGemsのみの見出しに修正、§0(a)には「10エコシステムのzipに含まれる`OSV-*`は取り込む」旨を注記した。(3) §9-1の検証項目番号が§9-0・§9-2と重複していたのを4,5,8へ振り直し、§10-1項目1の「2件」を「3件」に修正しディレクトリ名↔エコシステム別zip一致検証を明示的に列挙に加えた(§9-1・§10-1)。(4) `GhsaDocumentUpsertService`の引用行番号を実装コードの実測値へ全面修正した(`upsertGhsaAdvisory` :80-134、id/modifiedガード :81-90、`parseAffectedEntries` :148-173、`parseRangeEvents` :190-236に統一、`deleteByGhsaId` :111、§1-2・§6-3・§11)。

対象は、現在Stage2が`api.osv.dev`への都度ライブAPI問い合わせ(`OsvVulnerabilitySource.java`)でしか参照していないOSV.devのデータを、**GHSAミラー**(`docs/spec/ghsa-mirror-plan.md`として設計され、その後実装が完了して現在本番稼働している`GhsaSyncService`/`GhsaDocumentUpsertService`/`ghsa_advisories`ほか6テーブル)と同じ「バックグラウンド同期＋ローカルミラー＋ミラー専用照会」方式に置き換えるかどうかの設計である。

**重要な前置き**: `docs/spec/ghsa-mirror-plan.md`は文書冒頭で「設計のみ・未実装」と記しているが、**この状態はすでに過去のものである**。調査の過程で、同ドキュメントが設計したGHSAミラーは`GhsaSyncService.java`/`GhsaDocumentUpsertService.java`/`GhsaVulnerabilitySource.java`/`GhsaVulnerabilityLookupRepository.java`/`OsvVersionRange.java`(実装当初の`GhsaVersionRange.java`から改名済み)/`OsvPackageNameNormalizer.java`(実装当初の`GhsaPackageNameNormalizer.java`から改名済み)として**実装済み・複数回のシニアレビューを経て本番稼働中**であることを確認した(`docs/spec/known-limitations.md`の「GHSAミラー実装(2026-08-27)」という2件の記載とも整合)。したがって本ドキュメントは、設計ドキュメントとしての`ghsa-mirror-plan.md`ではなく、**実装済みコードそのもの**を一次テンプレートとして引用する——設計時点の想定と実装後の実際の形が一部異なる箇所(§7で詳述)があるため、実装コードを直接読んで確認した内容を優先する。

---

## 0. 結論を先に

**(a) 883,022件全部をミラーするのは明確に過剰であり、採用しない。** 実測(本ドキュメント作成時に確認、§2)により、対象10エコシステム(npm/PyPI/Maven/Go/NuGet/RubyGems/crates.io/Packagist/Hex/Pub)に関連する構造化レコードは全体の1.6%未満(後述)にとどまる。残り98%超はこのアプリが識別モデルを持たないOS配布パッケージ(Debian/Ubuntu/Alpine/SUSE/Rocky Linux等のCVE)、マルウェア検知フィード(`MAL-*`)、GitHub Actions/Swift/ConanCenter/CRAN等の未対応エコシステムであり、Stage1がこのアプリのCSV行に対して一致させる手段を持たない(**なお、OSS-Fuzz由来と推測される`OSV-*`接頭辞のレコードは、この除外対象には含まれない**——10エコシステムのzipに含まれる`OSV-*`は取り込む、§2-1参照)。

**(b) 10エコシステムへの絞り込みは必須。ただし絞り込むだけでは不十分で、GHSAミラーとの重複を除外することがさらに重要。** OSV.devのbulk exportには、npm/Maven/NuGet/RubyGems/Packagist/Pub向けの脆弱性情報のほぼ全量が、独自ソースとしてではなく**GHSA-reviewedのコンテンツをそのまま個別レコード化したもの**(`GHSA-*.json`、実測34,939件)として含まれている。これは`GhsaSyncService`が既にミラーしている`ghsa_advisories`(実測34,784件、ほぼ同一の母集団)と重複する——ただし「内容が同一だから」ではない(§4-1で訂正)。この重複分を除外し、**OSV.dev自身が一次情報源となっている非GHSA由来のレコードだけ**を対象にすると、対象母数は実測で**約13,600件**(PyPI: `PYSEC-*` 7,368件、Go: `GO-*` 4,358件、crates.io: `RUSTSEC-*` 1,207件、Packagist: `DRUPAL-CONTRIB-*` 539件、Hex: `EEF-CVE-*` 136件——いずれも本ドキュメント作成時に`/tmp/osv-all.zip`から実測、DRUPAL-CONTRIB・EEF-CVEの数字は当初625件・189件としていたものをシニアレビューでの再実測により訂正済み、§2-1)まで絞り込める。**この約13,600件は下限値であり、`OSV-*`(§2-1、シニアレビュー項目1で取り込み対象と確定)等の分だけ実際の件数は増えうる(容量結論(c)は不変)。**

**(c) 容量見積もりの結論: 絞り込み後は無視できる規模。** GHSAミラーの実測値(§3)を基準に単純比例で見積もると、883,022件全量ミラーは(生JSON非保存でも)約1.9GBの増分——現行1837MBに積み増すと約3.7GB(10GBキャップの37%)で技術的には収まるが、その価値のほとんどない98%のために容量を消費するのは正当化できない。10エコシステム限定・GHSA重複除外後の約13,600件(下限値、`OSV-*`等の分だけ増えうる、§2-1)は、同じ基準で見積もって**約30MB**——現行DBサイズの1.6%程度の誤差レベルであり、10GBキャップに対する懸念は実質的に存在しない(仮にこの見積りが5倍外れて150MBになったとしても10GBキャップに対する結論は変わらない、§3)。**結論: 10エコシステムへの絞り込みは行う。GHSA重複除外も行う。**

**(d) GHSAとの重複データの扱い: 除外する(片方に寄せる)。** OSV由来レコードのうち`id`が`GHSA-`で始まるものは、`GhsaSyncService`が既にミラーしている**アドバイザリー集合と重複する**ため、**このOSVミラーには一切取り込まない**——baseline(zip走査)・delta(`modified_id.csv`走査)の両方で、`GHSA-`始まりのIDはパースする前にファイル名/ID文字列だけで弾く(§4-1・§5)。除外の正確な根拠は§4-1を参照——「内容が同一だから」ではなく「`GhsaVulnerabilitySource`が既に同じアドバイザリー集合をカバーしており、Stage2の所見としては重複するため」である。

**(e) 既存`OsvVulnerabilitySource`(ライブAPI版)との関係: `find()`はミラー版に置き換え、`queryPackage()`は当面ライブAPI版のまま残す。** `BundledComponentResearchService`が`queryPackage()`を直接呼ぶ経路(`BundledComponentResearchService.java:242`)は、Stage1が確定した`ecosystem`/`packageName`を前提とする`find()`側の候補検索とは性質が異なり、**レジストリ照合を経ていない、LLM抽出のコンポーネント名の"当て推量"**に対して都度クエリする用途である——ミラー化するとローカルの`(ecosystem, package_name_normalized)`完全一致に頼ることになり、`BundledComponentResearchService`が扱う表記ゆれの大きい抽出結果とは相性が悪い(詳細は§7-2)。

**(f) 【シニアレビューで解決済み】同一IDが`modified_id.csv`上で複数エコシステムディレクトリ(例: `GIT/EEF-CVE-2026-66353`と`Hex/EEF-CVE-2026-66353`)に重複掲載される現象(§2-2)について、両ディレクトリの実際のJSON内容が完全に同一であることをシニアレビューが実測確認した**(バイト単位で完全一致、§4-3・§9・§9-0参照)。どのディレクトリ経由でフェッチしても同一内容であることが前提にできるため、実装時は最大タイムスタンプのディレクトリから1回だけフェッチすればよい(§6-2手順3)。

---

## 0-1. 本設計が踏襲する、このプロジェクトの既存の設計原則

以下は`ghsa-mirror-plan.md`§0-1が確立し、実装(`GhsaSyncService`等)がそのまま体現している原則を、そのまま継承する。

**1. 「見つからなかった」≠「安全と確認された」。** ミラーが未同期/該当パッケージが未発見/レンジ評価が不能(fail-closed)のいずれも、`SourceResult.success(空リスト)`として扱い、「脆弱性なし」と断定しない(`VulnerabilitySource.java`のjavadoc、既存の二分法にそのまま従う)。

**2. 一次情報源としての信頼。** OSV.dev自身が一次情報源とするPyPI Advisory Database(PYSEC)・Go Vulnerability Database(GO)・RustSec Advisory Database(RUSTSEC)・Drupal Security Team(DRUPAL-CONTRIB)・Erlang Ecosystem Foundation(EEF-CVE)は、いずれもLLM生成物ではなく各エコシステムの公式/準公式セキュリティチームが管理する一次情報源であり、`VulnerabilityRepository.upsertAndGetId`(`VulnerabilityRepository.java:26`)経路を使う。`insertIfAbsentAndGetId`(低信頼LLM専用)は使わない。

**3. コスト面: per-item追加LLMコストはゼロ。** ミラー化によりStage2の`find()`はローカルDBクエリのみで完結し、$5/1,000件ブレンドコスト目標に影響しない。

**4. 具体先行・過剰な一般化の回避。** GHSAミラーとOSVミラーは同じOSVスキーマを共有するため、CSAF/GHSA間で見送られた統合とは事情が異なる——本設計は**GHSAミラーが既に実装した汎用コンポーネント(`OsvVersionRange`のバージョン範囲評価、`OsvPackageNameNormalizer`のパッケージ名正規化、`OsvEcosystems`のエコシステム対応表)をそのまま再利用する**ことを積極的に提案する(§5-3)。これは新しい抽象化を作ることではなく、既に存在する、GHSA固有ではない汎用ロジックを二重実装しないという、原則4の裏返しの適用である。

---

## 1. 現状アーキテクチャの要約(コード引用)

### 1-1. `OsvVulnerabilitySource`は現在もper-itemのライブ呼び出し、`find()`と`queryPackage()`の二経路

`OsvVulnerabilitySource.java:24`は`@Component`が付いており、Stage2の`vulnerabilitySources`リストに自動的に含まれる。

- `find()`(`OsvVulnerabilitySource.java:37-46`): `identifiedProduct.getEcosystem()`/`getPackageName()`を`ECOSYSTEM_MAP`(`:32`、npm/pypi/maven/go/nuget/rubygems/crates.io/packagist/hex/pubの10エコシステム、このアプリの内部キー→OSV自身のエコシステム文字列)で変換し、`queryPackage()`へ委譲する。
- `queryPackage()`(`:62-106`): `POST https://api.osv.dev/v1/query`を都度実行、`OsvRateLimiter.awaitTurn()`(`:63`)でペーシングされる。応答の`affected[].ranges[].events[]`から`fixed`イベントを1つだけ拾う(`extractFixedVersion()`、`:111-126`)——ローカルの範囲評価は行わず、OSV.dev自身のサーバーサイド解決(`version`パラメータで完全一致を問い合わせる)に依存している。
- **`BundledComponentResearchService.java:242`が`queryPackage()`を`find()`を経由せず直接呼んでいる**(`osvVulnerabilitySource.queryPackage(osvEcosystem.get(), candidate.componentName(), candidate.version())`)。javadoc(`OsvVulnerabilitySource.java:48-61`)が明記する通り、これは同梱コンポーネント検出(`docs/spec/bundled-package-detection-plan.md`)がStage1のような`IdentifiedProduct`/`ResearchJobItem`を持たない——LLMが抽出した「コンポーネント名の当て推量」だけを持つ——ケース向けの、意図的に用意された第二の入口である。firstReferenceUrl()は`:128-133`。

### 1-2. GHSAミラー(実装済み)がそのまま流用できる汎用コンポーネント【シニアレビュー項目13: リネーム・統合済みの事実を反映】

このドキュメントの当初版は、以下のクラスが`Ghsa`を冠した名前のまま実装されており、OSVミラーからそのまま呼び出すか汎用名へリネームするかを「未決定事項」(§5-3・§10-1)としていた。**その後の別作業でリネーム・統合が完了しており、本改訂はその完了事実を反映する**:

- `OsvVersionRange.matches(rangeType, introducedVersion, fixedVersion, lastAffectedVersion, itemVersion)`(`OsvVersionRange.java`、`GhsaVersionRange`からリネーム済み。`GhsaVulnerabilitySource.java:109`で引き続き呼ばれている)——`VersionUtils`(`VersionUtils.java`)の既知の弱点(プレリリース順序の誤判定・null許容によるfail-open)を回避する、fail-closedなバージョン範囲評価器。OSVスキーマの`range_type`/`introduced`/`fixed`/`last_affected`という語彙そのものに対して書かれており、**GHSA固有のロジックは一切含まない**。
- `OsvPackageNameNormalizer.normalize(ecosystem, rawPackageName)`(`OsvPackageNameNormalizer.java:37-49`、`GhsaPackageNameNormalizer`からリネーム済み)——PyPIはPEP 503正規化、crates.ioは`-`/`_`畳み込み、その他は小文字化。同じくこのアプリの内部エコシステムキー(npm/pypi/maven/...)を引数に取るだけで、GHSA固有の要素はない。
- `OsvEcosystems`(`OsvEcosystems.java`、新設のfinalクラス)——このアプリの内部エコシステムキーとOSV自身のエコシステム文字列(npm/PyPI/Maven/Go/NuGet/RubyGems/crates.io/Packagist/Hex/Pub)の対応表`OSV_TO_INTERNAL`/`INTERNAL_TO_OSV`と、対応するキー集合`SUPPORTED_INTERNAL_KEYS`を持つ。**当ドキュメントの旧版が`OsvVulnerabilitySource`・`GhsaDocumentUpsertService`・`GhsaVulnerabilitySource`の3箇所にそれぞれ独立して存在すると記述していたエコシステム対応表の重複を、このクラスへ統合済み**——`OsvVulnerabilitySource.java:32`の`ECOSYSTEM_MAP`は`OsvEcosystems.INTERNAL_TO_OSV`を、`GhsaDocumentUpsertService.java:67`の`OSV_ECOSYSTEM_TO_INTERNAL`は`OsvEcosystems.OSV_TO_INTERNAL`を、`GhsaVulnerabilitySource.java:74`の`SUPPORTED_ECOSYSTEMS`は`OsvEcosystems.SUPPORTED_INTERNAL_KEYS`を、それぞれ参照する形に置き換わっている。
- `GhsaDocumentUpsertService.upsertGhsaAdvisory()`のOSVイベント対応規則(`parseRangeEvents()`、`GhsaDocumentUpsertService.java:190-236`)——`introduced`/`fixed`/`last_affected`/`limit`イベントの解釈規則そのものがOSVスキーマの仕様であり、GHSA固有ではない(このメソッド自体は`GhsaDocumentUpsertService`に残っており、リネーム対象ではない)。

これらはいずれも「OSVスキーマの構造化データをどう読むか」という汎用ロジックであり、GHSAという特定ソースに紐づいた実装ではない。**本設計は、`OsvVersionRange`・`OsvPackageNameNormalizer`・`OsvEcosystems`をOSVミラーの実装からもそのまま呼び出す**(§5-3で詳述)——これは既に完了した改名・統合作業の上に本設計を乗せる形になり、§5-3・§10-1が挙げていた「リネーム要否」という未決定事項はもはや存在しない。

### 1-3. `VulnerabilitySource`インターフェース

`VulnerabilitySource.java:19-24`——`find(ResearchJobItem, IdentifiedProduct, Long userId)`を実装し、`SourceResult.success`/`SourceResult.failure()`を返す。ミラー化後も同じ契約をそのまま満たせる(§7)。

---

## 2. 実測調査(本ドキュメント作成時に確認、未検証点は明記)

### 2-1. `all.zip`(baseline)の内訳——`/tmp/osv-all.zip`を`unzip -l`で実測

全883,022件(ヘッダ/フッタ込みで`unzip -l`出力883,027行、CVEプロジェクトのCveOrgSyncServiceが既に扱っている約38万件のオーダーを超える規模)のうち、ファイル名接頭辞で実測した内訳:

| 接頭辞 | 件数(実測) | 意味 | 本ミラーの扱い |
|---|---|---|---|
| `GHSA-*.json` | 34,939 | GHSA-reviewedの個別レコード化 | **除外**(§0(d)、`ghsa_advisories`と重複) |
| `PYSEC-*.json` | 7,368 | PyPI Advisory Database(PyPI公式) | 対象 |
| `GO-*.json` | 4,358 | Go Vulnerability Database(Go公式) | 対象 |
| `RUSTSEC-*.json` | 1,207 | RustSec Advisory Database(crates.io) | 対象 |
| `DRUPAL-CONTRIB-*.json` | 539 | Drupalコントリビュートモジュール(Packagist配下) | 対象 |
| `EEF-CVE-*.json` | 136 | Erlang Ecosystem Foundation(Hex) | 対象 |
| `OSV-*.json` | 4,439 | 主にOSS-Fuzz発見のバグ(未検証、後述) | 対象(エコシステム別zipに含まれる場合) |
| その他(Debian/Ubuntu/SUSE/Rocky Linux/AlmaLinux/MinimOS/malware `MAL-*`等) | 約830,036(表の他行からの導出値: 883,022−(34,939+7,368+4,358+1,207+539+136+4,439)) | OS配布パッケージCVE・マルウェア検知等 | 対象外 |

**対象10エコシステムの非GHSA由来レコード合計: 7,368+4,358+1,207+539+136 = 約13,600件(883,022件中1.54%)。この約13,600件は`OSV-*`等を含まない下限値であり、実際の取り込み件数はこの分だけ増えうる(§0(b)、容量結論(§3)は不変)。**

**訂正(シニアレビュー、2026-08-28)**: `DRUPAL-CONTRIB-*`625件・`EEF-CVE-*`189件は当初の実測値だったが、再実測で539件・136件に訂正した。EEF-CVE差分の内訳は判明している——`modified_id.csv`上では`GIT/EEF-CVE-*`という行が190件前後存在するが、`GIT/`配下のレコードは`affected[]`に`Hex`エコシステムを持たないものが混在しており、本ミラーの取り込み対象(`affected[].package.ecosystem == "Hex"`を持つレコード)としてはそのうち136件のみが実際に対象になる(§6-1で述べる通り、baselineは`{ecosystem}/all.zip`個別取得方式に変更したため、この種のディレクトリ跨ぎの数え間違いは実装上は起こりにくくなる——`Hex/all.zip`から直接取得すれば対象外レコードは最初から含まれない)。

**【シニアレビュー項目8、出典の未確定を明記】**この節の見出しは「ファイル名接頭辞で実測した内訳」(`/tmp/osv-all.zip`という全量フラットzipに対する`unzip -l`)としているが、直前の段落が説明する`539件・136件`の再実測の実際の手順(`modified_id.csv`上の`GIT/EEF-CVE-*`行190件前後から`affected[].package.ecosystem == "Hex"`で136件まで絞り込む、という内容に踏み込んだ手順)は、単純なファイル名接頭辞カウントではなく、個々のJSONの`affected[]`を読んだ内容ベースの絞り込みである。**全量フラットzipのファイル名カウントでは`affected[].ecosystem`による絞り込みは原理的に起きない**ため、`539件・136件`という最終的な数字が(a)`/tmp/osv-all.zip`に対する純粋なファイル名接頭辞カウントなのか、(b)`Packagist/all.zip`・`Hex/all.zip`(エコシステム別zip)またはmodified_id.csv+内容フィルタから数えたものなのか、本ドキュメント内の記述だけでは確定できない。**未確定、実装スパイクで確認する**——実装着手時にbaselineスパイクで両方の集計(全量フラットzipのファイル名接頭辞カウントと、エコシステム別zip内の該当プレフィックスファイル数)を取り、一致するかどうかを確認すること。

なお、この未確定と§2-2の「差分65,088行は重複によるものとみて矛盾しない」という仮説との整合について一言添えると: 上記の`GIT/EEF-CVE-*`190件前後のうち136件だけが対象(Hexエコシステムを持つ)という内訳が示す通り、残り54件前後は`GIT/`にしか現れずHexエコシステムを持たない「GIT専用レコード」である可能性があり、65,088行の一部はこの種の「複数ディレクトリへの同一レコードの重複」ではなく「対象外ecosystemのGIT専用レコード」に由来する可能性がある——ただしこの点も未確定であり、65,088行という数字上の矛盾の有無そのものは変わらない。

**【シニアレビュー項目1で確定】`OSV-*`の扱い**: `OSV-*`プレフィックスの4,439件はOSV.dev独自ID発行の慣習(主にOSS-Fuzzのファジング発見)によるものと推測しているが、この中に本アプリの10エコシステムに該当する`affected[].package.ecosystem`を持つレコードが紛れていないかは未検証。**この点は「対象外と確定させるための検証」ではなく「取り込む」で確定する**——`PyPI/all.zip`等のエコシステム別zipに`OSV-*`接頭辞のファイルが実際に含まれているなら、それは当該エコシステムのパッケージに実際に影響するレコードであり本ミラーの対象そのものである(§6-1手順3aの通り、接頭辞除外は`GHSA-`/`MAL-`の2つのみ、それ以外の接頭辞はエコシステム別zipに含まれている時点で取り込み対象とする)。実装時に対象10エコシステムのzip内に`OSV-*`接頭辞のファイルが実在するかどうかを確認するのは、件数把握・§9-1の実処理時間見積もりの精度を上げる目的であり、取り込み可否を左右する検証ではない。

**【シニアレビューで解決済み】NuGet/RubyGemsの非GHSA一次情報源の有無**: 実測の結果ゼロと判明した(§9・§9-0参照)。NuGet 1,877件(`modified_id.csv`のNuGetディレクトリ行、重複除去前)の内訳はGHSA 1,100件+`MAL-*` 777件で全数説明でき、RubyGems 4,657件も同様にGHSA 1,145件+`MAL-*` 3,512件で全数説明できる——NuGet/RubyGems固有の非GHSA一次情報源は存在しない。これにより当初「未検証」としていた懸念は解消済みである(詳細な内訳・検証手順は§9・§9-0)。

### 2-2. `modified_id.csv`(delta)——`https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv`を実データ取得して確認

- サイズ: 48.9MB(タスク指示にあった概算「約46.6MB」とほぼ一致)。
- **ヘッダ行なし**。2列: `<RFC3339タイムスタンプ、ナノ秒精度は行によって桁数が異なる>,<ソースディレクトリ>/<脆弱性ID>`。例: `2026-08-28T04:10:58.243285085Z,Maven/GHSA-m452-q8c9-rg2f`、`2026-08-27T12:01:44Z,crates.io/RUSTSEC-2026-0182`。
- 総行数948,110行。最古のエントリは2003年(`2003-07-06T00:00:00Z,Debian/DSA-340`)まで遡る——**この文書は「直近の変更ログ」ではなく、OSV.devが保持する全レコードそれぞれの"最終更新時刻"を(ソースディレクトリ, ID)単位で1行ずつ列挙した完全なマニフェストである**(OSV.dev公式ドキュメントが想定する使い方——「自分の同期カーソルより新しい行だけを抽出する」——とも整合)。
- **2列目の`<ソースディレクトリ>`は、GCSバケット内の実際の格納パス階層(例: `https://osv-vulnerabilities.storage.googleapis.com/PyPI/PYSEC-2023-1.json`)そのものである**——これはOSVの個別レコード取得APIとして、ライブAPI(`api.osv.dev/v1/vulns/{id}`)を経由せずとも使える。本設計はこちらを採用する(§6-2)。
- **【重要、新規に確認した事実】同一の脆弱性IDが複数のソースディレクトリに重複して出現する**——例: `EEF-CVE-2026-66353`が`GIT/EEF-CVE-2026-66353`と`Hex/EEF-CVE-2026-66353`の両方に個別の行として現れる(訂正: 当初例に挙げていた`npm/GHSA-gj8w-mvpf-x27x`と`Maven/GHSA-m452-q8c9-rg2f`は実際には別々のGHSA IDであり重複掲載の実例になっていなかった、シニアレビューで指摘・訂正)。全948,110行に対し`all.zip`のユニークファイル数は883,022件——差分の65,088行はこの重複によるものとみて数字上矛盾しない。**【シニアレビューで解決済み】** `GIT/EEF-CVE-2026-66353`と`Hex/EEF-CVE-2026-66353`を実際に取得し`diff`で突き合わせたところ、タイムスタンプ・バイト数(3,724バイト)ともに完全一致することを確認した(§4-3・§9・§9-0)——複数ディレクトリに重複出現する行は、どのディレクトリ経由でフェッチしても同一内容である。
- 対象10エコシステムのディレクトリ名一致件数(実測、行単位、重複除去前・`GHSA-`除外前): npm 227,390、PyPI 25,091、Go 8,955、Maven 7,006、Packagist 7,010、crates.io 2,756、RubyGems 4,657、NuGet 1,877、Hex 251、Pub 13(合計285,006/948,110、約30%)。npmが突出しているのは大半が`npm/MAL-*`(マルウェアパッケージ検知、脆弱性ではない)によるもの——このアプリは脆弱性検索を目的としており、`MAL-*`は**スコープ外**として明示的に除外する(§4-1のID接頭辞除外リストに追加)。
- **直近48時間(2026-08-27〜28)の実測変化量**: 対象10エコシステム該当行204件のうち、`GHSA-*`を除いた非GHSA由来行は119件(≒約60件/日、ID単位の重複除去前)。これは1日あたりのdelta呼び出しボリュームの目安として使える(§8)。

---

## 3. 容量見積もり(§0(c)の詳細)

既存GHSAミラー(実装済み、6テーブル)の実測値をそのまま基準に使う。

```
$ docker exec <postgres> psql -U vulncheck -d vulncheck -c \
    "SELECT relname, pg_total_relation_size(relid) FROM pg_catalog.pg_statio_user_tables WHERE relname LIKE 'ghsa_%'"
ghsa_advisories        107 MB
ghsa_affected_packages  21 MB
ghsa_affected_ranges   6968 kB
ghsa_affected_versions  352 kB
ghsa_sync_state          64 kB
ghsa_sync_failures       48 kB
合計                   135.5 MB  (34,784件、インデックス込み、raw_json TEXT列込み)

$ psql ... "SELECT sum(pg_column_size(raw_json)), avg(pg_column_size(raw_json)) FROM ghsa_advisories"
raw_json合計   57 MB (平均1,718バイト/件、TOAST圧縮後のオンディスクサイズ)
```

**本設計は`raw_json`を一切保存しない**(タスクの最重要方針)ため、GHSAミラーの実測値から`raw_json`分を差し引いた**「構造化データのみの実質フットプリント」**を基準に使う:

```
135.5 MB - 57 MB = 78.5 MB / 34,784件 ≈ 2.26 KB/件
(6テーブル全体、インデックス込み、raw_json列を除いた実質サイズ)
```

この2.26KB/件を単純比例で適用する:

| シナリオ | 対象件数 | 見積り増分 | 現行DB(1837MB)に対する比率 |
|---|---|---|---|
| (A) 883,022件全量ミラー | 883,022 | 約1.9 GB | +103%(合計約3.7GB、10GBキャップの37%) |
| (B) 10エコシステム限定・GHSA重複含む(§2-1「対象」欄全部+GHSA-*) | 約48,539(約13,600+34,939) | 約107 MB | +5.8% |
| (C) 10エコシステム限定・GHSA重複除外(本設計の採用案) | 約13,600(下限値、`OSV-*`等の分だけ増えうる) | **約30 MB** | +1.6% |

**結論(§0(c)の再掲)**: シナリオ(C)を採用する。10GBキャップに対する懸念は実質的に存在しない規模であり、絞り込みの主目的は容量ではなく「識別不能なデータを取り込まない」「GHSAミラーとの二重管理を避ける」という設計上の健全性にある。**この見積りが仮に5倍外れて150MBだったとしても、10GBキャップに対する結論(懸念は実質的に存在しない)は変わらない**——以下の前提の精緻化は、結論を覆すためではなく記録目的の注記にとどめる。

**この見積りの前提と限界(簡潔に)**: (1) OSV.dev側の`details`がGHSAより長い場合があり2.26KB/件は概算にすぎない、(2) baseline取り込み時のJSONパース対象は§6-1(item5改訂後)の通り`{ecosystem}/all.zip`個別取得によりGHSA-*/MAL-*を除く各ゾーン内のエントリのみで、旧設計(全量`all.zip`をパースしてからエコシステム判定)より処理対象が絞られる。いずれも§3の結論(シナリオC採用・10GBキャップへの懸念なし)を左右しない誤差レベルの注記であり、実装スパイクでの実測(§9)はこの結論の検証というより処理時間・メモリの実運用上の確認が目的である。

---

## 4. 重複データの扱い: GHSAミラーとの関係(§0(d)の詳細)

### 4-1. 除外ルール: `id`が`GHSA-`で始まるレコードは一切取り込まない

baseline(zip走査)・delta(`modified_id.csv`走査)のいずれも、個別レコードをパースする**前**に、ファイル名/ID文字列だけで次を除外する:

- `GHSA-`始まりのID(§0(d)、`ghsa_advisories`と重複)。
- `MAL-`始まりのID(マルウェアパッケージ検知——脆弱性ではない、§2-2)。

**【シニアレビュー項目1、最重要】この除外ルールがなぜ安全か——書き直し**: 当初の説明は「`GHSA-*.json`の内容は`ghsa_advisories`と同一だから除外しても失われるものがない」というものだったが、これは不正確であり訂正する。シニアレビューが同一アドバイザリー`GHSA-m452-q8c9-rg2f`を両ソースから直接取得して実測したところ、GitHub版(現行`ghsa_advisories.raw_json`)は3,446バイト、OSV.dev版(`Maven/GHSA-m452-q8c9-rg2f.json`)は5,243バイト——**OSV.dev版の方が52%大きい**。差分の正体は`affected[].versions[]`——GHSA自身のAPIレスポンスにはほとんど現れない個別バージョンの完全列挙(§0-1原則の裏取りにもなっている`known-limitations.md`の「`ghsa_affected_versions`はほぼ未使用」という既存記載と符合する)が、OSV.dev版には`2.1.0-RC1`・`3.0.0.Beta1`のようなプレリリース版まで含めて存在する。**つまり2つのJSONは内容として同一ではなく、OSV.dev版の方が情報量が多い。**

除外の正しい根拠は次の通り: **`GhsaVulnerabilitySource`が既に同じアドバイザリー集合をカバーしており、Stage2が発行する所見としては重複するため**——`ghsa_advisories`側が既に同じ`GHSA-*`アドバイザリーについて`SourceResult`を返せる以上、同一アドバイザリーをOSVミラー側でも別レコードとして取り込むと、Stage2の重複排除ロジック(`Stage2VulnerabilityResearchService.java:99`、`VulnFinding.cveOrGhsaId()`の文字列完全一致)がすり抜けた場合に同じ脆弱性が二重表示されうる——除外は「情報が重複しているから安全に捨てられる」のではなく「同じアドバイザリー集合に対して2つの情報源を持つことによる二重管理・二重表示のリスクを避けるため」の運用上の判断である。

**今回のスコープでは除外を維持する**——OSV.dev版が持つ`affected[].versions[]`の追加情報(プレリリース版の個別列挙)を取り込めば`OsvVersionRange`の数値限定fail-closed制約をプレリリース版アイテムについて回避できる可能性があるが(`known-limitations.md`に新規項目として記録、§2参照)、この追加情報を得るために`GHSA-*`分をOSVミラー側にも二重に持ち込むことは今回のスコープ外とする(§10のバックログ項目参照)。

### 4-2. 除外後も残る「間接的な重複」: CVE-ID経由のfinding重複

`GHSA-`始まりでない対象レコード(PYSEC/GO/RUSTSEC/DRUPAL-CONTRIB/EEF-CVE)であっても、そのレコードの`aliases[]`に`CVE-*`が含まれ、かつ同じCVE-IDをNVD/CVE.org/GHSAミラーの別ソースも発見する場合、Stage2の`byId.putIfAbsent`(`Stage2VulnerabilityResearchService.java:99`、重複排除キーは`VulnFinding.cveOrGhsaId()`の文字列完全一致)により自動的に1件へ統合される——これは`GhsaVulnerabilitySource`が既に採用している「CVE-ID優先、ネイティブID(`ghsa_id`)はフォールバックのみ」という方針(`GhsaVulnerabilitySource.java:173-177`の`addFinding`、`id = cveId != null ? cveId : ghsaId`)と同じ精神である。**本OSVミラーのfinding発行の優先順位は§5-2・§7-1で述べる`COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)`(シニアレビュー項目10で修正、`ghsa_advisories`をLEFT JOINして得るCVE-IDも含めた4段構成)であり、これも同じ精神の拡張である**。これにより既存の重複排除の仕組みにそのまま乗る。

### 4-3. 【解決済み】同一IDの複数ディレクトリ重複掲載(§0(f)、§2-2、§9・§9-0)

`modified_id.csv`上で同一の脆弱性IDが複数のエコシステムディレクトリに出現する現象(§2-2)は、baselineの`{ecosystem}/all.zip`個別取得(§6-1、item5改訂後)——各エコシステムのzipがそれぞれ独立にフラット構造を持つ——には実質的に影響しない。問題はdeltaのみで発生しうる: 同一IDについて`GIT/EEF-CVE-2026-66353`と`Hex/EEF-CVE-2026-66353`の両方の変更が記録された場合(`GHSA-`始まりは§4-1で既に除外されるので実際に問題になるのは非GHSA由来IDが複数ディレクトリに重複する場合に限られる)、**このIDに対して2回GETするのは冪等upsertなので無害だが無駄**である。

**シニアレビューが`GIT/EEF-CVE-2026-66353`と`Hex/EEF-CVE-2026-66353`を実際に取得し`diff`で突き合わせたところ、タイムスタンプ・バイト数(3,724バイト)ともに完全一致することを確認した**——どのディレクトリ経由でフェッチしても同一内容であることが確認済みのため、「未確認のまま『どれでも同じ』と決め打ちしない」という当初の留保は解消された。実装時の要求事項(変更なし): `modified_id.csv`を読んだ後、ID単位でグルーピングし、複数ディレクトリに出現する場合は最大のタイムスタンプを採用した上で1回だけフェッチする(どのディレクトリ経由でフェッチするかは任意でよい——内容が同一であることが確認済みのため)。

---

## 5. 提案スキーマ: 新規6テーブル(`ghsa_*`パターンを直接踏襲、raw_json列は持たない)

**GHSAミラー(V19、実装済み)と全く同じ6テーブル構成を踏襲する**——OSVスキーマそのものが同一のため、GHSAミラーが既に確立したテーブル分割(advisories/affected_packages/affected_versions/affected_ranges/sync_state/sync_failures)をそのまま適用できる。**唯一かつ最大の相違点は`osv_advisories`が`raw_json`列を持たないこと**(タスクの最重要方針)。

```sql
-- V25__osv_advisories.sql (マイグレーション番号は実装着手時に
-- `ls backend/src/main/resources/db/migration/` で再確認すること——本ドキュメント作成時点でV24が最新)

-- 1 OSVレコード(GHSA由来を除く)につき1行。raw_jsonは持たない(タスクの方針、V19のghsa_advisoriesとの
-- 唯一の構造的差異)——再導出・デバッグ用途は諦める代わりに、9.25GB規模の生データをDBへ持ち込まない。
-- osv_id: PYSEC-2023-1 / GO-2023-1234 / RUSTSEC-2023-0001 / DRUPAL-CONTRIB-2026-111 / EEF-CVE-2026-12345 など、
-- ソースによって桁数・書式が異なるため、GHSAの VARCHAR(20) より広く VARCHAR(40) を取る。
-- 長さ40を超えるIDは§8-3の入力検証でWARNログを出してスキップし、insert自体を試みない(この列に
-- 収まらない値がそもそもここへ渡ってこないことを保証するのはアプリ側のバリデーション、§8-3)。
CREATE TABLE osv_advisories (
    osv_id          VARCHAR(40) PRIMARY KEY,
    cve_id          VARCHAR(30),               -- aliases[]からCVE-*を抽出(§4-2、finding発行時のID優先順位にも使う)
    ghsa_id         VARCHAR(20),               -- aliases[]にGHSA-*があれば参考情報として保持(§4-2)。
                                                -- このIDで新たにghsa_advisoriesを参照しにいく仕組みは作らない。
    summary         TEXT,
    details         TEXT,
    severity        VARCHAR(20),
    cvss_score      NUMERIC,                   -- GHSAミラーと同じ理由で当面NULL(§5-1)
    withdrawn_at    TIMESTAMPTZ,               -- NOT NULL = 撤回済み。find()対象から除外(ghsa_advisoriesと同型)
    published_at    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL,      -- JSON本文のmodifiedフィールドをそのまま格納するのみ。
                                                -- 【シニアレビュー項目4で訂正】delta同期のカーソルには使わない
                                                -- (カーソルはmodified_id.csv側のタイムスタンプ、osv_sync_state.last_cursor参照)
    html_url        TEXT,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_osv_advisories_updated_at ON osv_advisories (updated_at);

-- osv_affected_packages / osv_affected_versions / osv_affected_ranges は
-- ghsa_affected_packages / ghsa_affected_versions / ghsa_affected_ranges (V19) と列構成・制約とも同一。
-- package_name_normalized には OsvPackageNameNormalizer.normalize() をそのまま再利用する(§1-2、
-- GHSAミラー実装がGhsaPackageNameNormalizerからOsvPackageNameNormalizerへ改名済み)。
CREATE TABLE osv_affected_packages (
    id                       BIGSERIAL PRIMARY KEY,
    osv_id                   VARCHAR(40) NOT NULL REFERENCES osv_advisories(osv_id) ON DELETE CASCADE,
    ecosystem                VARCHAR(30) NOT NULL,
    package_name             TEXT NOT NULL,
    package_name_normalized  TEXT NOT NULL,
    UNIQUE (osv_id, ecosystem, package_name_normalized)
);
CREATE INDEX idx_osv_affected_packages_lookup ON osv_affected_packages (ecosystem, package_name_normalized);
CREATE INDEX idx_osv_affected_packages_advisory ON osv_affected_packages (osv_id);

CREATE TABLE osv_affected_versions (
    affected_package_id  BIGINT NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE,
    version               TEXT NOT NULL,
    PRIMARY KEY (affected_package_id, version)
);
CREATE INDEX idx_osv_affected_versions_package ON osv_affected_versions (affected_package_id);

-- range_type/introduced_version/fixed_version/last_affected_versionの意味論はghsa_affected_rangesと完全に
-- 同一(§1-2、OsvVersionRange.matches()をそのまま再利用できる根拠。GHSAミラー実装が
-- GhsaVersionRangeからOsvVersionRangeへ改名済み)。
CREATE TABLE osv_affected_ranges (
    id                     BIGSERIAL PRIMARY KEY,
    affected_package_id    BIGINT NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE,
    range_type             VARCHAR(16) NOT NULL,
    introduced_version     TEXT,
    fixed_version          TEXT,
    last_affected_version  TEXT,
    CHECK (fixed_version IS NULL OR last_affected_version IS NULL)
);
CREATE INDEX idx_osv_affected_ranges_package ON osv_affected_ranges (affected_package_id);

-- 単一行の同期状態。ghsa_sync_stateとほぼ同型。
-- 【シニアレビュー項目12で訂正】当初「baseline_commit_shaに相当する完全性検証手段がOSV.dev側に
-- 存在しない」としていたが、これは誤りだった——実測でGCSオブジェクトのlast-modified/etag/
-- x-goog-generation/x-goog-hash:md5の各ヘッダが存在することを確認済み(§9・§9-0)。
-- baseline_source_generationは、baseline取得時に10本のzipそれぞれから記録したx-goog-generation
-- (またはetag)を連結・保持する列——後から「このbaselineがどのGCSスナップショット由来か」を
-- 突き合わせられるようにする、デバッグ・監査用途の完全性メタデータ。
-- ただし取り込み可否のゲートとしては引き続き§6-1の「取り込み件数が期待値の90%以上」の
-- 自己較正ゲートを主に使う(このgeneration列は事後の追跡用であり、取り込み時点の判定には使わない)。
CREATE TABLE osv_sync_state (
    id                          SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_loaded             BOOLEAN NOT NULL DEFAULT false,
    sync_in_progress            BOOLEAN NOT NULL DEFAULT false,
    -- 【シニアレビュー項目4・7で訂正】last_cursorは「処理済みosv_advisories.updated_at(JSON内の
    -- modifiedフィールド由来)の最大値」ではない——modified_id.csvのタイムスタンプ列という別の時計
    -- (§6-2)と混同していた誤りを修正した。last_cursorは常にmodified_id.csv側のタイムスタンプ
    -- ドメインで一貫させる: 「処理に成功した行のcsv側タイムスタンプ」まで前進させる(§6-2手順7)。
    -- JSON内のmodifiedフィールドはosv_advisories.updated_at列に格納するだけで、カーソルには使わない。
    last_cursor                 TIMESTAMPTZ,
    last_synced_at              TIMESTAMPTZ,
    last_sync_error             TEXT,
    baseline_source_generation  TEXT,   -- 10本のzipのx-goog-generation(またはetag)を連結して保持(上記コメント参照)
    CHECK (id = 1)
);
INSERT INTO osv_sync_state (id) VALUES (1);

-- ghsa_sync_failuresと同型。ghsa_id列と異なりosv_idは書式が不定(§5の理由と同じ)なので、
-- GHSAの厳格な正規表現バリデーション(GhsaSyncService.GHSA_ID_PATTERN相当)は使えず、
-- 長さ・文字種の緩い妥当性チェックに留める(§8-1)。
CREATE TABLE osv_sync_failures (
    osv_id                VARCHAR(40) PRIMARY KEY,
    consecutive_failures  INT NOT NULL DEFAULT 0,
    last_error            TEXT,
    last_attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dead_lettered_at      TIMESTAMPTZ
);
```

### 5-1. `cvss_score`が常にNULLである理由

GHSAミラーと同じ理由(`known-limitations.md`「GHSAミラー実装(2026-08-27): cvss_scoreは常にNULL」)——OSVスキーマの`severity[]`は生のCVSSベクター文字列のみを持ち、事前計算済み数値スコアを持たない。ベクター文字列パーサは本フェーズのスコープ外。`severity`(テキスト列)は`database_specific.severity`から取得する(GHSAと同型)——ただし**未検証**: PYSEC/GO/RUSTSEC/DRUPAL-CONTRIB/EEF-CVEの各ソースが`database_specific.severity`を一貫して埋めているかどうかは、実装時にサンプルを確認すること(GHSA-reviewedほど一貫していない可能性がある)。

### 5-2. `ghsa_id`列: `ghsa_advisories`をLEFT JOINし、発行IDの決定に使う(【シニアレビュー項目10で撤回・修正】)

`osv_advisories.ghsa_id`は`aliases[]`にGHSA-IDが含まれる場合の相互参照情報として持つ。**当初「この列を使って`ghsa_advisories`を追加でJOINする仕組みは作らない」としていたが、この禁止判断は誤りであり撤回する。**

理由: あるアドバイザリーがCVE-XとGHSA-Yの両方を持つ場合、`ghsa_advisories`側は`cve_id=CVE-X`を保持しているので`GhsaVulnerabilitySource`は`CVE-X`をfinding IDとして発行するが、同じ脆弱性を指すOSVのPYSEC/GO/RUSTSEC等のレコードの`aliases[]`に(何らかの理由で)`CVE-X`が欠けており`GHSA-Y`しか無い場合、本OSVミラーは`GHSA-Y`をfinding IDとして発行してしまう——`Stage2VulnerabilityResearchService`の`byId.putIfAbsent`(`Stage2VulnerabilityResearchService.java:99`、重複排除キーは`VulnFinding.cveOrGhsaId()`の文字列完全一致)はこの2つを別IDとして扱うため、同一脆弱性が2件表示されてしまう。`ghsa_advisories.ghsa_id`は主キーなので、この1本のJOINのコストは事実上ゼロであり、二重表示のリスクの方が高くつく。

**修正後の設計**: `OsvVulnerabilityLookupRepository`の2本の候補検索クエリ(§7-1、`GhsaVulnerabilityLookupRepository`と同型の`findCandidateRanges`/`findCandidateVersions`)の両方に`LEFT JOIN ghsa_advisories g ON g.ghsa_id = o.ghsa_id`を追加する(`ghsa_advisories`側にレコードが無くてもOSV側の候補行自体は必ず返す必要があるためLEFT JOIN——`GhsaVulnerabilityLookupRepository`が自身の候補検索で使っているINNER JOINとは主従が逆であることに注意)。発行するfinding IDは`COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)`で決定する——OSV側のCVE-IDを最優先、無ければGHSAミラー側が持つCVE-ID、それも無ければOSV側の参考GHSA-ID、最後にosv_idネイティブIDへフォールバックする(§7-1で優先順位を更新)。**Java側のループ内で候補ごとに追加クエリを発行することは禁止**——COALESCEはSQL側で解決し、候補行1件につき1回のJDBC結果セット行として返す。

### 5-3. 【シニアレビュー項目13で確定済み】`OsvVersionRange`・`OsvPackageNameNormalizer`・`OsvEcosystems`の直接再利用

§1-2で確認した通り、これらのクラスはOSVスキーマ一般に対する汎用ロジックであり、GHSA固有の要素を持たない。**本設計は、新設する`OsvDocumentUpsertService`(仮称)・ミラー版`OsvVulnerabilitySource`の両方から、これらのクラスをそのまま呼び出す**——`com.vulncheck.app.service.vuln`パッケージ内にあり、`public`メソッドとして既に公開されているため、パッケージをまたいだ呼び出しに支障はない。

当初版はここで「クラス名に`Ghsa`と付いたまま呼ぶか、汎用名へリネームするか」を実装着手時の未決定事項としていたが、**この判断は別作業で既に下されている**——`GhsaVersionRange`→`OsvVersionRange`、`GhsaPackageNameNormalizer`→`OsvPackageNameNormalizer`へのリネームと、3箇所に重複していたエコシステム対応表の`OsvEcosystems`への統合がすべて完了済みで、GHSAミラー側の呼び出し元(`GhsaVulnerabilitySource`/`GhsaDocumentUpsertService`)も新しいクラス名を参照するよう変更済みである(§1-2)。本ドキュメントのOSVミラー設計は、この完了済みの状態を前提にしてよい——§10-1が挙げていた未決定事項のリストからこの項目は削除する。

---

## 6. 提案アーキテクチャ: `OsvSyncService`(仮称、`GhsaSyncService`を直接のテンプレートとする)

### 6-1. baseline: 10エコシステムそれぞれの`{ecosystem}/all.zip`を個別取得する(【シニアレビュー項目5・6・7で全面修正】)

`GhsaSyncService.doSyncBaseline()`(`GhsaSyncService.java:231-356`)と`CveOrgSyncService.syncBaseline()`(`CveOrgSyncService.java:58-97`)がテンプレート。相違点はtarball(gzip+tar)ではなく単純なzipであることと、**単一の`all.zip`(883,022件、1.518GB)を全部ストリーミングするのではなく、対象10エコシステムそれぞれの`{ecosystem}/all.zip`を個別に取得すること**(当初版からの最大の変更点)。

```
1. https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip を、対象10エコシステム分
   (OsvEcosystems.INTERNAL_TO_OSVの値、§1-2)だけ順にストリーミング取得する(プレーンな
   URLConnection、GhsaSyncService#openStream・CveOrgSyncService#downloadと同型、読み取り
   タイムアウト無制限)。{ecosystem}の表記はhttps://osv-vulnerabilities.storage.googleapis.com/
   ecosystems.txtの表記に厳密一致させる——npm/PyPI/Maven/Go/NuGet/RubyGems/crates.io/
   Packagist/Hex/Pub(シニアレビューが実取得して確認済み。OsvEcosystems.INTERNAL_TO_OSVの値が
   そのままこの10文字列)。開始前にsync_in_progressを立てる(§6-4、GhsaSyncServiceの
   AtomicBoolean方式を踏襲)。取得ごとにレスポンスのlast-modified/x-goog-generationヘッダを
   記録しておく(手順5・osv_sync_state.baseline_source_generation、§5・§9・§9-0)。

   実測サイズ(シニアレビュー実測): npm 220,484,837バイト、PyPI 33,922,364バイト、
   Go 11,389,659バイト、Maven 10,144,797バイト、残り6エコシステム(NuGet/RubyGems/crates.io/
   Packagist/Hex/Pub)は合計30MB以下見込み——10本合計で約310MB。単一の`all.zip`(1.518GB)を
   毎回ストリーミングするより取得量が大幅に小さい。
2. 各zipをZipInputStreamで順に読む(単純なzip——java.util.zip.ZipInputStreamで
   CveOrgSyncServiceと同じ扱いができる)。
3. 各エントリについて:
   a. ファイル名が"GHSA-"または"MAL-"で始まる場合は、開かずに(readAllBytesすらせず)スキップする
      (§4-1)。**接頭辞による除外は`GHSA-`/`MAL-`の2つのみ**——`OSV-*`を含むそれ以外の接頭辞は、
      対象エコシステムの`{ecosystem}/all.zip`に含まれている時点で取り込み対象とする(§2-1、
      シニアレビュー項目1で確定)。
   b. それ以外はJSONとしてパースし、共有upsertOsvJson()(§6-3)でupsertする。
      【シニアレビュー項目5で削除】当初はここで「affected[]の中に対象10エコシステムに該当する
      package.ecosystemを持つエントリが1つでもあるか」を個々のレコードを開いてから判定していたが、
      この判定は削除する——手順1で取得元zipのエコシステムが既に確定しているため、baselineの
      ファイル取得フィルタとしては不要(パースしてから捨てるだけの無駄な工程だった)。
      **ただし共有upsertOsvJson()の内部で、対象10エコシステム以外のエコシステムを持つ
      `affected[]`エントリ(1レコードが複数エコシステムのaffected[]を併記する場合)を無視する処理
      自体は、この判定とは別の粒度の話として引き続き残す**(§6-3、シニアレビューの指示通り)。
4. 【シニアレビュー項目6で修正、項目7bで根拠を訂正】完全性ゲート: 分母を「処理したエントリ数」
   ではなく`COUNT(DISTINCT osv_id)`にする——**複数エコシステムの`affected[]`を持つレコードは
   複数のzipに収録されうるため(未実測、保守的な想定)**。§9-0項目2が実測したのは
   `modified_id.csv`上の`GIT/`と`Hex/`という個別オブジェクトの内容が同一であることであって、
   エコシステム別zip間の収録重複そのものではない——この点は未実測のまま保守的に見積もる。
   冪等upsertで正しさ自体は保たれるが、素朴に処理エントリ数を分母にすると重複分だけ水増しされて
   しまう可能性があるため、`COUNT(DISTINCT osv_id)`を使うという判断自体は変更しない。期待値も
   13,600(または当初の
   13,747)のハードコードをやめ、**自己較正方式**にする: 10本のzipそれぞれについてファイル名
   フィルタ(GHSA-/MAL-除外)を通過したエントリのIDを実行時に集合として集め、その和集合の
   ユニークID数を分母とする。実際に`osv_advisories`へupsertできた`DISTINCT osv_id`の件数が
   その90%未満なら、`baseline_loaded`をtrueにせず失敗として扱う(GhsaSyncServiceの
   `COMPLETENESS_THRESHOLD=0.90`をそのまま踏襲、plan §0-1原則1の適用)。
5. 【シニアレビュー項目7で修正】90%以上なら`baseline_loaded=true`をコミットする。
   `last_cursor`の初期値は「このバッチの最大`updated_at`」にしない——これは§6-2で述べる
   時計混同の問題に加え、zipスナップショット生成時刻より後・baseline完了より前に変更された
   レコードを恒久的に取りこぼす欠陥がある。代わりに初期値は**「10本のzipの取得時に手順1で
   記録したlast-modifiedレスポンスヘッダの最小値から、さらに7日引いた値」**とする。
   根拠: `modified_id.csv`は(§2-2の通り)完全マニフェストなのでカーソルは純粋な最適化であり、
   保守的に手前に置いても再処理コストが増えるだけで取りこぼしは起きない。実測ではin-scopeの
   変更は約60件/日(§2-2)なので、7日分の再処理でも約420回のGETに過ぎず無視できるコストである。
   `baseline_source_generation`(§5)にも同じタイミングで10本分のgenerationを記録する。
6. 【トゥームストーン】GhsaSyncServiceの制約踏襲: 今回のbaseline実行で一度も触れられなかった
   (last_synced_atが実行開始時刻より前のまま残っている)行を削除する——ただし今回の実行で
   1件でも失敗があった場合はプルーニング自体をスキップする(GhsaSyncService.java:323-338の
   「シニアレビュー項目1」の教訓——transientな失敗を「もう存在しない」と誤認して削除しない)。
   実行開始時刻はアプリサーバーではなくDBサーバー自身の時計を使う(GhsaAdvisoryRepository#
   currentDatabaseTime、GhsaAdvisoryRepository.java:64-74のjavadocが明記する
   「アプリ/DBコンテナの時計は数百ms単位でずれることが実測されている」という教訓をそのまま踏襲)。
```

**§4-1で述べた通り、GHSA-*/MAL-*の早期スキップは「パースする前にファイル名だけで判定できる」という性質を利用した最適化である**——手順1の変更(エコシステム別zip取得)により、旧設計で懸念していた「848,083件全部を最低1回パースしてエコシステム判定する」という工程自体が不要になった。各エコシステムzip内でGHSA-*/MAL-*を除いた残りのエントリ数が実際のパース対象になる——`CveOrgSyncService`が既に約38万件規模のJSON個別パースをbaseline経路で安全に処理している前例(`CveOrgSyncService.java:29-31`のjavadoc、「baseline ~380k records」)と比べても、この対象母数(npmが最大、§2-2の実測ではnpmの`modified_id.csv`行227,390件のほとんどが`MAL-*`)は同オーダーかそれ以下と見込まれる——**それでも実装スパイクでの処理時間実測は完了条件に含める**(§9)。

### 6-2. delta: `modified_id.csv`を全量取得し、csv側タイムスタンプでカーソル管理する(【シニアレビュー項目4・8で修正、項目3で前提を明示化】)

**【シニアレビュー項目3、未検証の暗黙前提】** 以下の手順2・§8-3(a)は、対象10エコシステムのレコードの更新行が必ず対応する10エコシステムのディレクトリ名(npm/PyPI/Maven/Go/NuGet/RubyGems/crates.io/Packagist/Hex/Pub)で`modified_id.csv`上に現れる、という前提に立っている。これは**未検証の前提**である——もし`{ecosystem}/all.zip`に収録されているのに`modified_id.csv`上は非エコシステムディレクトリ(`GIT/`等)にしか現れないIDが1件でもあれば、そのレコードはbaseline取り込み後、delta側の「directoryが対象10エコシステムのいずれかである」というフィルタ(手順2)に一致せず、永久に更新されなくなる。検証項目は§9-1に追加した。この前提が崩れた場合のフォールバックは§8-3(a)を参照。

```
1. https://osv-vulnerabilities.storage.googleapis.com/modified_id.csv (48.9MB) を毎回全量取得する
   (§2-2の通り増分ファイルではなく全ID分のマニフェストのため、差分だけを返すAPIは存在しない——
   48.9MBの取得自体は軽量な操作として許容する。ストリーム処理・サイズ上限については§8-3参照)。
2. 各行を(timestamp, directory, id)に分解し、次の条件で絞り込む:
   - directoryが対象10エコシステムのディレクトリ名(npm/PyPI/Maven/Go/NuGet/RubyGems/
     crates.io/Packagist/Hex/Pub)のいずれかである(§8-3のallowlist検証をここで適用)
   - idが"GHSA-"、"MAL-"で始まらない(§4-1)、かつ§8-3のID形式検証を通過する
   - **timestamp(csv側の2列目の時刻)> osv_sync_state.last_cursor**
     ——ここでのtimestampは常にmodified_id.csvのタイムスタンプ列であり、個別JSONの
     `modified`フィールド(osv_advisories.updated_atに格納するだけの値、§5)ではない
     (【シニアレビュー項目4】当初版は絞り込み条件をcsv側の時計で書きながら、後段の
     カーソル前進をJSON側の`modified`まで進めるとしており、2つの別々の時計が混在していた
     誤りだった——`GhsaSyncService.java:410,434`が確立している「フィルタと前進を同一の
     時計で行う」という不変条件に反する。以下手順7でcsv側の時計に統一する)。
3. 残った行をidでグルーピングし、複数ディレクトリに重複出現する場合は最大timestampを採用して
   1回だけ処理対象にする(§4-3、【シニアレビューで解決済み】——複数ディレクトリの内容は
   バイト単位で完全一致することを実測確認済みのため、どちらのディレクトリ経由でフェッチしても良い)。
4. 【シニアレビュー項目8で新設、項目2で打ち切り境界を修正】**MAX_DOCUMENTS_PER_DELTA_RUN(定数、
   初期値1,000を推奨)**を設ける——`GhsaSyncService.java:124`の`MAX_PAGES_PER_DELTA_RUN=5`に
   相当するものが、当初版のdelta設計には一切無かった。timestamp昇順に処理し、この上限件数に
   達したら`sawFailure`を立てずに正常終了する——カーソルはそこまで前進させた状態でコミットし、
   残りは次回実行に持ち越す。実測60件/日(§2-2)に対し初期値1,000は約16日分の余裕があり、通常
   運用では上限に達すること自体が稀という想定(達した場合は次回実行が自動的に続きを拾う)。
   **【シニアレビュー項目2、行の恒久欠落防止】打ち切りはtimestampグループの境界でのみ行う**——
   `timestamp > last_cursor`という厳密不等号のフィルタ(手順2)は同一timestampを共有する行が
   複数存在しうることを前提にしており(§2-2が秒精度の行の存在を記録している通り、同値は現実に
   起こりうる)、その途中で打ち切ると残りの同timestamp行は次回以降も`timestamp > last_cursor`に
   より永久に除外されてしまう。したがって、上限件数に達しても、直近に処理したtimestampと同一の
   timestampを持つ行がまだ残っている間は処理を継続し、timestampが変わった時点で初めて打ち切る
   (上限は「ちょうどこの件数で止める」ではなく「この件数を超えたらtimestampが変わるまで続ける」
   という緩い上限になる)。**【3回目シニアレビュー項目Aで補記】この打ち切り規則は独立したルール
   ではなく、手順7が定める「`last_cursor`はtimestampグループ単位でしかコミットしない」という
   グループアトミック規則からそのまま導かれる帰結である**——グループ単位でしかコミットしない以上、
   グループの途中で打ち切ることはできない(打ち切れるのはグループの境界だけ)。手順4と手順7で
   別々の打ち切りルールを二重に定義しているわけではない。
5. timestamp昇順で処理し(手順4の上限まで)、各idについて
   https://osv-vulnerabilities.storage.googleapis.com/{directory}/{id}.json を個別GETする
   (GhsaSyncService#fetchAndUpsertOneのraw.githubusercontent.com個別取得と同型——
   ライブAPI(api.osv.dev/v1/vulns/{id})は使わない。同じGCSバケット上の個別オブジェクト
   パスであり、baselineと完全に同一の供給元・同一のJSON形状であることを保証できるため。
   URL組み立て前の入力検証・バイト上限は§8-3参照)。
6. baselineと同一のupsertOsvJson()(§6-3)を通す。JSON内の`modified`フィールドは
   `osv_advisories.updated_at`に格納するだけで、カーソルには使わない(手順2参照)。
7. 【3回目シニアレビュー項目Aで全面書き直し、timestampグループアトミックへ変更】
   カーソル前進の単位を**timestampグループ単位(グループアトミック)**とする。「1件ごとに
   `last_cursor`をそのレコードのcsv側timestampまで前進させてコミットする」という当初の記述は
   撤回する——1件ごとに前進させると、同一timestamp Tを共有する行が複数ある場合に、途中の1件が
   dead-letter未満の失敗をした場合やプロセスが処理途中で落ちた場合、既にコミット済みの
   `last_cursor=T`によって残りの同timestamp行が次回以降`timestamp > T`(手順2の厳密不等号)で
   恒久的に除外されてしまう(§2-2の恒久欠落問題の再発)。

   1. deltaはtimestampグループ単位で処理する。あるtimestamp T(手順3のグルーピング後の単位)に
      属する行をすべて処理し終えるまで、`last_cursor`には一切触れない。
   2. グループ内の全行が成功(またはdead-letter条件——同一idでN=3回連続失敗——を満たして意図的に
      スキップ)した時点で初めて`last_cursor = T`をコミットする。
   3. グループ内に1件でもdead-letter未満の失敗があれば、そのグループのtimestampまでは前進させず、
      1つ前に完了したグループのtimestampのまま今回の実行を終了する。次回実行は手順2のフィルタ
      (`timestamp > last_cursor`)により当該グループ全体を再取得する——共有upsertOsvJson()
      (§6-3)は冪等なので、同一グループ内で既に成功していた他の行を再処理しても無害である。
   4. 手順4の`MAX_DOCUMENTS_PER_DELTA_RUN`による打ち切りも、この「グループ単位でしかコミット
      しない」という本手順の規則から自動的に導かれる帰結であり、手順4と本手順7とで別々の打ち切り
      ルールを二重に定義しているわけではない(手順4は「グループ境界でのみ打ち切る」という記述を
      維持しつつ、本規則の言い換えである旨を手順4側にも付記した)。
   5. 手順2の絞り込み条件(`timestamp > last_cursor`、厳密不等号)はこのまま維持してよい——
      グループアトミックにコミットする以上、`last_cursor`は常に「完全に処理し終えたグループの
      timestamp」を指すため、次回実行が同一timestampの残り行を取りこぼすことはなく、`>=`
      (以上)へ変更する必要はない。
```

**未検証事項として明記**: `osv-vulnerabilities.storage.googleapis.com`(GCS公開バケット)への個別オブジェクトGETに、GitHubのAPI(60/hour)のような明示的なレート制限が存在するかどうかは、シニアレビューが実測で解消済み(§9・§9-0)——匿名GET十数回で429やスロットリングは発生しなかった。ただし公開バケットの挙動が将来変わる可能性はゼロではないため、§6-4の軽い固定間隔ペーサーの新設自体は推奨のまま残す。

### 6-3. 共有`upsertOsvJson(JsonNode root)`

`GhsaDocumentUpsertService.upsertGhsaAdvisory()`(`GhsaDocumentUpsertService.java:80-134`)と同型の冪等upsert:

- `id`(§5の`osv_id`)と`modified`(`updated_at`)が必須——欠けていれば処理失敗として扱う(`GhsaDocumentUpsertService.java:81-90`と同じガード)。
- `aliases[]`から`CVE-*`と`GHSA-*`をそれぞれ抽出して`cve_id`/`ghsa_id`列へ(§4-2・§5-2)。
- `affected[]`を(内部エコシステム, 正規化パッケージ名)単位でグルーピングしてから`osv_affected_packages`行を作る(`GhsaDocumentUpsertService.java:148-173`の`parseAffectedEntries`と同型、複数の`affected[]`エントリが同じパッケージを指す場合の重複行防止)——**対象10エコシステム以外のエコシステムを持つ`affected[]`エントリは無視する**(1つのレコードが対象/対象外エコシステムを両方含む場合、対象分だけ取り込む——§6-1手順3bで述べた通り、baselineのファイル取得フィルタとしてはこの判定を行わなくなったため、この共有upsert内での判定がこの粒度の唯一の判定になる)。
- `ranges[].events[]`のイベント対応規則は`parseRangeEvents()`(`GhsaDocumentUpsertService.java:190-236`)をそのまま踏襲(`introduced`/`fixed`/`last_affected`/`limit`の扱い、`introduced:"0"`→NULL正規化)。
- 既存の`osv_affected_packages`/`osv_affected_versions`/`osv_affected_ranges`行は`osv_id`で削除してから作り直す(`GhsaDocumentUpsertService.java:111`の`deleteByGhsaId`と同型)。
- **`raw_json`は保存しない**(§5、本設計の唯一の構造的差異)。

### 6-4. 同時実行防止・レート制限・1回あたりの処理件数上限

- `GhsaSyncService`の`AtomicBoolean running`(`GhsaSyncService.java:161`)と同じ、プロセス内単一インスタンス前提の排他制御をそのまま踏襲——このアプリの既存デプロイ前提(単一インスタンス)に合わせる。
- baseline(`{ecosystem}/all.zip`×10)・delta(`modified_id.csv`+個別JSON)ともに、GCS公開バケットへの匿名GETに明示的なレート制限が無いことをシニアレビューが実測確認済み(§6-2・§9・§9-0)。ただし「呼び出し回数×間隔」の概算を怠らないという教訓(`ghsa-mirror-plan.md`§5冒頭)は踏襲し、個別JSON取得(delta、§2-2の実測で1日数十〜100件程度)には`ExternalRegistryRateLimiter`と同様の軽い固定間隔ペーサーを新設することを推奨する——レート制限が無いことの確認は今回の実測十数回に基づくものであり、将来の挙動変化に対する保険として、無警戒に連続GETし続けるのではなく軽いペーサーは維持する。
- **`MAX_DOCUMENTS_PER_DELTA_RUN`(§6-2手順4、初期値1,000を推奨)**——`GhsaSyncService.java:124`の`MAX_PAGES_PER_DELTA_RUN=5`に相当する、1回のdelta実行あたりの処理件数上限。上限に達したら`sawFailure`を立てずに正常終了し、カーソルはそこまで前進させて次回実行に持ち越す。実測60件/日(§2-2)に対し初期値1,000は約16日分の余裕がある。

---

## 7. `VulnerabilitySource`実装の形状

### 7-1. `find()`: ミラー専用照会に置き換える

`GhsaVulnerabilitySource`(`GhsaVulnerabilitySource.java:79-139`)を直接のテンプレートとする:

- クラス名は既存の`OsvVulnerabilitySource`を再利用し、`find()`の中身だけをミラー照会に置き換える(`queryPackage()`側は§7-2の通り`OsvLiveQueryClient`へ分離する)。`ECOSYSTEM_MAP`(`OsvVulnerabilitySource.java:32`、実装は`OsvEcosystems.INTERNAL_TO_OSV`、§1-2)は内部キー→OSV自身のエコシステム文字列という向きなので、`GhsaDocumentUpsertService`の`OSV_ECOSYSTEM_TO_INTERNAL`(逆方向、実装は`OsvEcosystems.OSV_TO_INTERNAL`)とは別に、正規化用には`identifiedProduct.getEcosystem()`(内部キー)をそのまま`osv_affected_packages.ecosystem`と比較すればよく、変換は不要(GHSA側も同じ扱い、`GhsaVulnerabilitySource.java:74`の`SUPPORTED_ECOSYSTEMS`、実装は`OsvEcosystems.SUPPORTED_INTERNAL_KEYS`参照)。
- **候補検索は`GhsaVulnerabilityLookupRepository`と同型の2クエリ構成**(`GhsaVulnerabilityLookupRepository.java:34-80`)——`osv_affected_ranges`側とJOIN(レンジ評価対象、§7の`findCandidateRanges`と同型)、`osv_affected_versions`側は`item.getVersion()`をSQLレベルでフィルタする独立クエリ(`findCandidateVersions`と同型)。**両クエリとも`LEFT JOIN ghsa_advisories g ON g.ghsa_id = o.ghsa_id`を追加する**(§5-2、シニアレビュー項目10で撤回・修正)。候補ごとにN+1で逐次クエリしない。`symfony/symfony`のようなメタパッケージ(`known-limitations.md`)を最悪ケースとして`EXPLAIN ANALYZE`を実装時に確認する(GHSA側で既に確立された規律をそのまま適用)。
- **バージョン範囲評価は`OsvVersionRange.matches(...)`をそのまま呼ぶ**(§1-2・§5-3、`GhsaVersionRange`から改名済み)。新規の評価ロジックを二重実装しない。
- **【シニアレビュー項目10で修正】finding発行のID優先順位**: `COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)`で決定する(§5-2)——OSV側自身の`cve_id`を最優先、無ければLEFT JOINした`ghsa_advisories`側の`cve_id`(OSVのaliases[]がCVE-IDを欠いていてもGHSAミラー側が持っている場合の救済)、それも無ければOSV側の参考`ghsa_id`列、最後に`osv_id`ネイティブID(`PYSEC-...`等)へフォールバックする。当初は`cve_id` > `ghsa_id`(参考列) > `osv_id`という3段構成だったが、`ghsa_advisories`のCOALESCEを追加した4段構成に修正した(§5-2)。
- `withdrawn_at IS NOT NULL`の行はSQLのWHERE句で除外する(GHSAと同型)。
- 見つからなかった場合はすべて`SourceResult.success(空リスト)`(§0-1原則1)。

### 7-2. `queryPackage()`: 当面ライブAPI版のまま残す、かつ`OsvLiveQueryClient`へ分離する(§0(e)の詳細、【シニアレビュー項目14で修正】)

`BundledComponentResearchService.java:242`が直接呼ぶ`queryPackage(osvEcosystem, packageName, version)`は、**Stage1の`IdentifiedProduct`を経由しない、LLM抽出コンポーネント名への都度クエリ**である。ミラーの`osv_affected_packages.package_name_normalized`は`OsvPackageNameNormalizer`によるper-ecosystem正規化(PyPIのPEP 503、crates.ioの`-`/`_`畳み込み等)を前提にしており、これは「レジストリに実在するパッケージ名」を想定した正規化である。`BundledComponentResearchService`が抽出するコンポーネント名は同梱物からの推測(`docs/spec/bundled-package-detection-plan.md`§3-3が既に「トリアージ目的であり精密な判定ではない」と位置づけている)であり、正規化ルールの前提が成立しない可能性がある——例えば大文字小文字混在や、レジストリ表記と異なる同梱物内での命名慣行など。

**本設計の結論**: `queryPackage()`はミラー化せず、現行のライブAPI実装をそのまま維持する。理由は次の2点(【シニアレビュー項目14で1点差し替え】):

1. 同梱コンポーネント検知は`docs/spec/bundled-package-detection-plan.md`§4の通り1アイテムあたり約$0.02の専用予算ゲーティングを既に持つオプトイン機能であり、Stage2の主経路のようなスループット制約(1,000件/3時間)を受けない——ライブAPI呼び出しのレイテンシコストを許容できる。
2. **【差し替え】当初「OSV.dev自身のサーバーサイド完全一致解決の方が表記ゆれに強い」としていたが、この理由は誤りとして削除する。正しい理由は次の通り**: ミラーはin-scope約48,540件(§3、約13,600+34,939)のうち約13,600件(約28%)しかカバーせず、`BundledComponentResearchService`の経路には`IdentifiedProduct`が存在しないため、Stage2の`find()`が持つ`GhsaVulnerabilitySource`によるフォールバック(GHSA分34,939件を別ソースがカバーする、という補完関係)がこの経路には存在しない。`queryPackage()`をミラー化すると、この機能のカバレッジが約72%(34,939/48,540)失われる——ライブAPIはOSV.devの全カバレッジ(GHSA分含む)にサーバー側で問い合わせるため、この欠落が生じない。

**設計変更: 2クラスへ分割する**——現在の`OsvVulnerabilitySource`は`find()`(ミラー照会に置き換える、§7-1)と`queryPackage()`/`extractFixedVersion()`/`firstReferenceUrl()`(ライブAPIのまま、`OsvVulnerabilitySource.java:62-133`)を同一クラスに同居させているが、この構造は`find()`のミラー化後に維持すべきではない——ミラー専用クラスにライブAPI呼び出しのメソッドが残るのは責務の混在になる。

- **`OsvVulnerabilitySource`**: ミラー照会専用に変更する。`RestClient`/`OsvRateLimiter`への依存を持たない(§7-1)。
- **`OsvLiveQueryClient`(新規`@Component`)**: 現在の`queryPackage()`/`extractFixedVersion()`/`firstReferenceUrl()`をそのまま移設する。`RestClient`/`OsvRateLimiter`はこちらに移る。`BundledComponentResearchService`の依存先を`OsvVulnerabilitySource`からこちらへ差し替える(`BundledComponentResearchService.java:97,242`)。

**`OsvRateLimiter`のjavadoc更新が必要になる旨を明記**: 現行の`OsvRateLimiter.java`のjavadocは「`find()`と`queryPackage()`が同じ`/v1/query`エンドポイントを叩くため両者で1つのゲートを共有する」という前提(1アイテムあたり最大8並行スレッド×`MAX_COMPONENTS_PER_ITEM`回)で100ms間隔の導出根拠を書いている。`find()`がミラー化されこのクラスから抜けると、この前提は崩れる——実装時には、**呼び出し元は`OsvLiveQueryClient`(`BundledComponentResearchService`経由)のみ、1アイテムあたり最大`MAX_COMPONENTS_PER_ITEM`回、同梱コンポーネント検知というオプトイン機能に限定される**、という新しい前提でスループット根拠(100ms間隔で許容できる合計待ち時間)を書き直す必要がある——これは本ドキュメントのスコープ外(実装コード変更)だが、`find()`のミラー化と`OsvLiveQueryClient`への分離を実装するタイミングで同時に見直すべき項目として明記しておく。

---

## 8. 部分失敗・完全性への対応

`GhsaSyncService`が確立した規律(§6-1で言及した`derivedGhsaIdFromPath`のバリデーション、`失敗した文書より先にカーソルを進めない`、`sync_in_progress`のtry/finally保証、`unchecked例外も含めて必ずクリーンアップする`広い`catch (RuntimeException e)`)をそのまま踏襲する。OSV固有の追加事項:

### 8-1. `osv_id`の妥当性チェック(GHSAの`GHSA_ID_PATTERN`相当がそのまま使えない)

`GhsaSyncService.GHSA_ID_PATTERN`(`GhsaSyncService.java:137`)は`^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$`という固定書式を前提にしているが、OSVのネイティブIDは書式がソースごとに異なる(`PYSEC-2023-1`、`GO-2023-1234`、`RUSTSEC-2023-0001`、`DRUPAL-CONTRIB-2026-111`、`EEF-CVE-2026-12345`)。**要求事項**: 正規表現による厳格な書式チェックの代わりに、長さ(`osv_sync_failures.osv_id`/`osv_advisories.osv_id`は`VARCHAR(40)`、§5)と使用可能文字(英数字・ハイフンのみ)の緩いチェックに留める——`GhsaSyncService`の該当箇所(`recordFailureAndCheckDeadLetter`、`GhsaSyncService.java:602-626`)がVARCHAR幅超過によるクラッシュを防ぐために導入したのと同じ目的を、より緩いバリデーションで達成する。**長さ40を超えるIDが渡ってきた場合の挙動を明記する**: WARNログを出してスキップし、`osv_advisories`・`osv_sync_failures`いずれへのinsertも試みない(§5、VARCHAR幅超過での例外送出に頼らない)。より厳密な入力検証(URL組み立て前のdirectory/idバリデーション)は§8-3で扱う——本節の緩いチェックはあくまでDBカラム幅に対する保険であり、§8-3のセキュリティ目的の検証とは別の話である。

### 8-2. 撤回(withdrawn)の扱い

`GhsaSyncService`が§6-3で確認した通り(クラスjavadoc`:61-69`)、GHSAでは「decision A(単一パーサ)により、変更検知された文書は常に完全なOSVスキーマ文書を再取得するため、`withdrawn`フィールドも通常の更新と同じ経路で反映される」ことが実装時に判明している。**本設計のdeltaも同じ構造(§6-2、変更検知された`id`について常に完全なJSONを個別取得する)を持つため、同じ理屈がそのまま成立する**——`withdrawn`フィールド専用の別処理は不要。ただしbaselineのトゥームストーン(§6-1)は、`modified_id.csv`にすら現れなくなった完全な除去(reviewed集合からの脱落等)のみを補う、という位置づけもGHSAと同じ。

### 8-3. 外部入力検証(【シニアレビュー項目9で新設】)

`modified_id.csv`の各行から組み立てる`{directory}/{id}.json`というURL(§6-2手順5)は、外部から供給される文字列をそのままURLパス・DBキーに使う経路であり、以下の検証を**URL組み立て・DB書き込みの両方より前に**行う。

**(a) `directory`の検証**: 対象10エコシステムのディレクトリ名(npm/PyPI/Maven/Go/NuGet/RubyGems/crates.io/Packagist/Hex/Pub、`OsvEcosystems.INTERNAL_TO_OSV`の値、§1-2)との**完全一致でのみ**受け付ける固定allowlistとする。文字列連結の前にこの一致を確認し、一致しない行は処理対象から除外する(§6-2手順2で行うディレクトリ絞り込みと同じ検証をここでも徹底する——絞り込みのための判定と、URL組み立て前の安全性検証を同一の検証ロジックとして扱ってよい)。

**【シニアレビュー項目3、フォールバック】§6-2冒頭で明示した「ディレクトリ名↔エコシステム別zip収録集合が一致する」という前提が§9-1の検証で崩れた場合**: delta実行の冒頭で`SELECT osv_id FROM osv_advisories`を1回だけ発行して既知ID集合をメモリに載せ、`directory ∈ allowlist` **または** `id ∈ 既知ID集合` の行を処理対象にする(行ごとのDB問い合わせは禁止、§6-2手順5のN+1と同じ理由で1回のクエリに限定する)。この場合もURL組み立てに使う`directory`は本節(a)の固定allowlist検証を通す必要があるため、実測で確認された追加ディレクトリ(`GIT`等)をallowlistに明示追加する形にする——**検証を緩めてはならない**(allowlistの外側にある任意の`directory`文字列をそのままURLに使ってよい、という意味には決してしない)。

**(b) `id`の検証**: `^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$`にマッチする場合のみ受け付ける。マッチしない行はWARNログを出してスキップし、URL組み立て・DB書き込みのどちらも行わない。**この正規表現だけでは`id.contains("..")`(例: `PYSEC-2023-1..%2Fadmin`のような文字列で正規表現自体は許可される`.`が連続するケース)を弾けない**——正規表現とは別に`id.contains("..")`を明示的にチェックし、該当する行はWARNログを出してスキップする。

**(c) `modified_id.csv`(48.9MB)のストリーム処理**: `readAllBytes`や`split("\n")`のような全量読み込みではなく、**`BufferedReader`で1行ずつ読む**(`CveOrgSyncService`/`GhsaSyncService`が個別JSONの読み込みに使っている境界付きストリーム処理と同じ思想)。加えて、ファイルサイズにも上限(例: 256MB)を設ける——現在の実測サイズ(48.9MB)から見て5倍以上の余裕を持たせた上限であり、上限を超えるレスポンスはストリーミングの途中で処理を打ち切り失敗として扱う。

**(d) 個別JSON取得・zipエントリのバイト上限**: `{directory}/{id}.json`の個別GET(§6-2手順5)、および`{ecosystem}/all.zip`内の各エントリ(§6-1手順2-3)の両方に、`GhsaSyncService.java:128`の`MAX_JSON_DOCUMENT_BYTES`(5MB)と`readBounded`(`GhsaSyncService.java:849`)相当のバイト上限を適用する——上限を超えるエントリ/レスポンスは、内容を最後まで読み切らずに失敗として扱う(GHSAミラーが既に確立した「巨大な単一文書によるメモリ枯渇を避ける」規律をそのまま踏襲)。

---

## 9. 検証事項一覧(【シニアレビュー項目12で1・2・3・6を解決済みに更新、項目11でA/B検証ゲートを追加】)

### 9-0. 解決済み(シニアレビューが実測して結論を確定)

1. **NuGet/RubyGemsの非GHSA一次情報源の有無 → ゼロと判明**。NuGet 1,877件(`modified_id.csv`のNuGetディレクトリ行、重複除去前)はGHSA 1,100件+`MAL-*` 777件で全数説明でき、RubyGems 4,657件も同様にGHSA 1,145件+`MAL-*` 3,512件で全数説明できた——NuGet/RubyGems固有の非GHSA一次情報源は存在しない(§2-1)。
2. **同一IDが複数エコシステムディレクトリに重複出現する場合の内容同一性 → 完全一致と確認**。`EEF-CVE-2026-66353`を`GIT/`と`Hex/`の両方から取得し`diff`で突き合わせたところ、3,724バイトで完全バイト一致(タイムスタンプも同一)——どのディレクトリ経由で取得しても同一内容である(§2-2・§4-3・§6-2手順3)。
3. **`osv-vulnerabilities.storage.googleapis.com`への連続GETに対するレート制限/スロットリングの有無 → 発生しないことを実測確認**。匿名GET十数回で429やスロットリングは発生しなかった——公開バケットへの匿名GETは一般にAPIレート制限の対象外という理解と整合する(§6-2・§6-4)。ただし将来の挙動変化に対する保険として軽い固定間隔ペーサーは維持する(§6-4)。
6. **バルクエクスポートの生成時刻メタデータの有無 → 存在すると確認**。GCSオブジェクトの`last-modified`/`etag`/`x-goog-generation`/`x-goog-hash:md5`の各ヘッダが実測で存在することを確認した。これにより「完全性検証手段が存在しない」としていた§5の当初の記述は撤回し、`osv_sync_state.baseline_source_generation`列(§5)を追加した。

### 9-1. 残る未検証事項(実装スパイクでの確認が必須)

4. PYSEC/GO/RUSTSEC/DRUPAL-CONTRIB/EEF-CVEそれぞれの`database_specific.severity`充足率(§5-1)。
5. baseline実行時、各エコシステムzip(§6-1、item5改訂後)のGHSA-*/MAL-*を除いた全件を個別パースする際の実処理時間・メモリ使用量(§6-1末尾)。
8. **【シニアレビュー項目3で新設】ディレクトリ名↔エコシステム別zip収録集合の一致検証**: 10エコシステムそれぞれについて、`{ecosystem}/all.zip`内の非GHSA/非MALな全IDが`modified_id.csv`上で同じ`{ecosystem}/`ディレクトリの行としても出現することを確認する(§6-2冒頭)。baselineスパイク時に両ファイル(`{ecosystem}/all.zip`と`modified_id.csv`)が手元にあるので追加コストはほぼゼロ。一致しなかった場合は§8-3(a)のフォールバックを適用する。

### 9-2. 【シニアレビュー項目11で新設】7. A/B検証ゲート(実装完了条件)

ミラー化はOSVサーバー側のエコシステム別バージョン解決を、`OsvVersionRange`(旧`GhsaVersionRange`)の数値限定fail-closed評価に置き換える変更である。シニアレビューの実測では、既存GHSAミラーの実データで範囲境界のパース可能率がmaven 81%・packagist 87%・pypi 93%・go 82%・crates.io 97%(境界だけでこの数字——アイテム側のバージョンが`^\d+(\.\d+)*$`でなければさらに全滅するケースもある)。この精度低下がOSVミラーでも同様に起こりうる。

**実装完了条件として、以下を必須とする**:

1. 完了済み実ジョブのアイテム(または`docs/spec/stage1-golden-benchmark.md`のセット)を対象に、ライブAPI版`find()`とミラー版`find()`を同一入力で両方実行し所見ID集合を突き合わせる、使い捨ての`@SpringBootTest`(`*Test`サフィックスを避ける慣習通り、他の`*JobCreator`等と同じ命名規則)を書くこと。
2. 「ミラー版にしか出ない所見」と「ライブ版にしか出ない所見」を件数付きで列挙すること。
3. **【実測後に訂正、V25ロールアウトのA/B再検証で確認】** 後者(ライブ版にしか出ない所見)は2つの想定内カテゴリのどちらかで説明できることを確認すること: (a) `GHSA-*`由来レコード(§0(d)の除外方針により、ミラーはそもそも`GHSA-*`を取り込まないため、ライブAPI側だけがGHSA由来の所見を出すのは想定内)、および(b) **ID表記の違い**——ライブAPIはOSVの native id(`RUSTSEC-*`/`GO-*`/`PYSEC-*`等)をそのまま返すのに対し、ミラー側は`COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)`によるCVE-ID優先(項目10、§5-2・§7-1・§10-0)で同一アドバイザリーを別ラベル(多くの場合CVE-ID)で発行するため、native idの方が「ライブ版にしか出ない所見」として現れる。これは`GHSA-*`除外とは別の、独立した想定内カテゴリであり、両者を混同しないこと——(a)はミラーが取り込まないこと自体が理由、(b)はミラーも同じアドバイザリーを取り込んでいるが発行idの優先順位が異なることが理由。(a)(b)いずれでも説明できない損失だけが、次項4の「説明できない損失」に該当する。
4. 説明できない損失(GHSA由来では説明のつかないミラー側の欠落)があれば、`known-limitations.md`に記録すること。
5. **この突き合わせ結果を見ずに`OsvVulnerabilitySource.find()`をライブAPI版からミラー版へ切り替えてはならない。**

---

## 10. 未決定事項・決定済み事項

### 10-0. 決定済み事項(本ドキュメントで確定)

- **10エコシステムへの絞り込み、かつGHSA-*/MAL-*の除外を行う**(§0(a)(b)(d)、§3・§4)。除外の正しい根拠は「`GhsaVulnerabilitySource`が既に同じアドバイザリー集合をカバーしているため」であり「内容が同一だから」ではない(§4-1)。
- **baselineは単一の`all.zip`ではなく、10エコシステムそれぞれの`{ecosystem}/all.zip`を個別取得する**(§6-1、シニアレビュー項目5)。
- **`raw_json`列は持たない**(§5、タスクの最重要方針、GHSAミラーとの唯一の構造的差異)。
- **finding発行のID優先順位は`COALESCE(o.cve_id, g.cve_id, o.ghsa_id, o.osv_id)`**(`ghsa_advisories`をLEFT JOINする、§5-2・§7-1、シニアレビュー項目10で修正)。
- **`queryPackage()`は当面ミラー化せず、ライブAPI実装のまま残す。`OsvVulnerabilitySource`(ミラー専用)と`OsvLiveQueryClient`(新規、ライブAPI専用)の2クラスに分割する**(§0(e)・§7-2、シニアレビュー項目14)。
- **`GhsaVersionRange`→`OsvVersionRange`、`GhsaPackageNameNormalizer`→`OsvPackageNameNormalizer`へのリネーム、および`OsvEcosystems`への対応表統合は完了済み**(§1-2・§5-3、シニアレビュー項目13)——旧版が未決定事項としていたリネーム要否の判断はもはや不要。
- **`OsvVulnerabilitySource.find()`をライブAPI版からミラー版へ切り替える前に、§9-2のA/B検証ゲート(所見ID集合の突き合わせ)を実装完了条件とする**(シニアレビュー項目11)。

### 10-1. 未決定事項(実装スパイクまたはシニアレビューでの判断を仰ぐ点)

1. §9-1に列挙した3件の未検証事項(`database_specific.severity`充足率、baseline処理時間・メモリ実測、ディレクトリ名↔エコシステム別zip収録集合の一致検証)——いずれも実装着手前のライブスパイクで確認すべき。
2. **マイグレーション番号の衝突**。本ドキュメント作成時点の最新は`V24__job_cost_ledger_item_index.sql`——実装着手時点で`ls backend/src/main/resources/db/migration/`を再確認し、他の並行作業と衝突していないか確認した上でV25以降を採番すること。
3. **`queryPackage()`の将来的なミラー化**(§7-2)——本ドキュメントは結論を出さない。
4. **delta用レート制限の具体的な間隔値**——§6-4は「軽い固定間隔ペーサーを新設することを推奨する」とだけ述べており、具体的な秒数は実装時に決めるべき事項として残す(レート制限自体の有無は§9-0で解決済み)。
5. **`/admin/osv`のような運用可視化画面の要否**——GHSAミラーが確立した`/admin/ghsa`(`AdminController.java:138-163`、`admin/ghsa.html`)と同型のGET表示+POST起動画面を追加するかどうかは、本ドキュメントでは「追加すべき」という方向性だけ示し、実装時のタスクとして残す。

### 10-2. 【シニアレビュー項目3で新設】後続バックログ: `GhsaSyncService`の供給元をOSV.dev側へ切り替える案

`GhsaSyncService`は現在GitHubのtarball+REST APIからGHSAアドバイザリーを取得しているが、この供給元をOSV.devのエコシステム別zip(`{ecosystem}/all.zip`)+`modified_id.csv`へ切り替える案を、将来のバックログ項目として記録する。**今回のスコープでは実施しない**。

理由: §4-1で確認した通り、OSV.dev版の`GHSA-*.json`はGitHub版より情報量が多く(`affected[].versions[]`の完全列挙、プレリリース版含む)、これが無料で手に入る。加えてGitHub API自体の60 req/hour制約(`GhsaSyncService`が現在抱える制約)がOSV.dev経由では発生しない。さらに、GHSAアドバイザリーの供給元をOSV.dev側に一本化できれば、「GitHub由来のGHSAミラー」と「OSV.dev由来の本OSVミラー」という2つの類似ミラーを別々に運用する二重化も解消できる。ただし`GhsaSyncService`は本番稼働中のコンポーネントであり、供給元の切り替えは`affected[].versions[]`パーサの新規実装・既存データとの整合性検証を要する規模の変更のため、本ドキュメントのスコープ外として切り離す。

---

## 11. この文書が参照する既存ドキュメント・コード

- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvVulnerabilitySource.java`(クラス全体、特に`:24`の`@Component`、`:32`の`ECOSYSTEM_MAP`(実装は`OsvEcosystems.INTERNAL_TO_OSV`)、`:37-46`の`find()`、`:62-133`の`queryPackage()`/`extractFixedVersion()`/`firstReferenceUrl()`) — 現行のper-item ライブ実装。`find()`はミラー照会に置き換え(§7-1)、`queryPackage()`系メソッドは新規`OsvLiveQueryClient`へ移設する対象(§7-2、シニアレビュー項目14)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvRateLimiter.java` — `find()`/`queryPackage()`両方が現在共有しているレートリミッタ。`find()`のミラー化後は前提(呼び出し元・呼び出し頻度)が変わるため、javadocの100ms導出根拠の書き直しが必要になる旨を明記(§7-2、シニアレビュー項目14)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvEcosystems.java` — 内部エコシステムキーとOSV自身のエコシステム文字列の対応表(`OSV_TO_INTERNAL`/`INTERNAL_TO_OSV`/`SUPPORTED_INTERNAL_KEYS`)。3箇所の重複を統合した新設クラス、直接再利用する(§1-2・§5-3・§6-1・§7-1、シニアレビュー項目13)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvVersionRange.java` — fail-closedなバージョン範囲評価、`GhsaVersionRange`から改名済み。GHSA固有ロジックを持たないため直接再利用する(§1-2・§5-3・§7-1)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvPackageNameNormalizer.java`(クラス全体、特に`:37-49`の`normalize`) — per-ecosystemパッケージ名正規化、`GhsaPackageNameNormalizer`から改名済み。直接再利用する(§1-2・§5-3)。
- `backend/src/main/java/com/vulncheck/app/service/BundledComponentResearchService.java:97,136-139,242` — `queryPackage()`を`find()`を経由せず直接呼ぶ既存コード(`MAX_COMPONENTS_PER_ITEM`定数含む)。`find()`のミラー化後は依存先を新規`OsvLiveQueryClient`へ差し替える対象(§0(e)・§7-2)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/VulnerabilitySource.java:19-24` — インターフェース契約(§1-3)。
- `backend/src/main/java/com/vulncheck/app/service/ghsa/GhsaSyncService.java`(クラス全体、特に`:100-227`のクラス構造、`:124`の`MAX_PAGES_PER_DELTA_RUN`、`:128`の`MAX_JSON_DOCUMENT_BYTES`、`:137`の`GHSA_ID_PATTERN`、`:231-356`の`doSyncBaseline`、`:383-476`の`doSyncDelta`(`:410,434`のフィルタ/前進が同一時計である不変条件)、`:602-626`の`recordFailureAndCheckDeadLetter`、`:849`の`readBounded`) — 実装済みGHSAミラーの同期サービス、本設計の直接のテンプレート(§6・§8)。
- `backend/src/main/java/com/vulncheck/app/service/ghsa/GhsaDocumentUpsertService.java`(クラス全体、特に`:67`の`OSV_ECOSYSTEM_TO_INTERNAL`(実装は`OsvEcosystems.OSV_TO_INTERNAL`)、`:80-134`の`upsertGhsaAdvisory`、`:148-173`の`parseAffectedEntries`、`:157`の`OsvPackageNameNormalizer.normalize`呼び出し、`:190-236`の`parseRangeEvents`) — 共有upsertの直接のテンプレート(§6-3)。
- `backend/src/main/java/com/vulncheck/app/service/vuln/GhsaVulnerabilitySource.java`(クラス全体、特に`:74`の`SUPPORTED_ECOSYSTEMS`(実装は`OsvEcosystems.SUPPORTED_INTERNAL_KEYS`)、`:79-139`の`find()`、`:85`の`OsvPackageNameNormalizer.normalize`呼び出し、`:109`の`OsvVersionRange.matches`呼び出し、`:173-177`のCVE-ID優先emission) — ミラー版`VulnerabilitySource`実装の直接のテンプレート(§7-1)。
- `backend/src/main/java/com/vulncheck/app/repository/GhsaVulnerabilityLookupRepository.java`(クラス全体) — N+1を避ける2クエリ構成の直接のテンプレート。`OsvVulnerabilityLookupRepository`はここに`LEFT JOIN ghsa_advisories`を追加した形になる(§5-2・§7-1、シニアレビュー項目10)。
- `backend/src/main/java/com/vulncheck/app/repository/GhsaAdvisoryRepository.java:64-74` — アプリ/DBの時計のずれによるトゥームストーン誤爆の教訓、`currentDatabaseTime()`(§6-1)。
- `backend/src/main/resources/db/migration/V19__ghsa_advisories.sql` — 6テーブル構成の直接のテンプレート(§5)。
- `backend/src/main/java/com/vulncheck/app/service/cveorg/CveOrgSyncService.java:29-40,58-97` — baseline個別JSON約38万件パースの前例、単一zipストリーミング取得の前例(§6-1)。
- `backend/src/main/java/com/vulncheck/app/service/ghsa/GhsaScheduledSync.java` — 日次delta同期のスケジューリング前例。**05:30 UTC**を推奨する(シニアレビュー項目15で04:30 UTCから修正——`Go/all.zip`の`last-modified`が実測04:19 UTCであり、04:30 UTCだとエクスポート生成中に走る可能性があるため。他の`@Scheduled`ジョブ(03:30/03:45/04:00/04:15 UTC)との衝突回避という当初の要件は05:30 UTCでも変わらず満たす)。
- `backend/src/main/java/com/vulncheck/app/controller/AdminController.java:138-163` — `/admin/ghsa`のGETフォーム+POST起動+永続状態表示の前例(§10-1項目5)。
- `backend/src/main/java/com/vulncheck/app/config/RestClientConfig.java:92-105` — `ghsaSyncRestClient`のようなsync専用RestClient beanの前例(baseline用ストリーミングは別途プレーンURLConnectionを使う設計)。
- `docs/spec/ghsa-mirror-plan.md` — 設計ドキュメントとしての一次テンプレート。ただし本ドキュメント冒頭で述べた通り、実装は既にこの設計を上回って進んでおり、実装済みコード自体を優先して引用している(§0冒頭)。
- `docs/spec/known-limitations.md`「GHSAミラー実装(2026-08-27)」各項目(特に`OsvVersionRange`のfail-closedルール・`cvss_score`常時NULL・`ghsa_affected_versions`ほぼ未使用・本改訂で追加する新項目)、「GHSA/OSVが『メタパッケージ』に対して大量の脆弱性を返すことがある」「CVE/GHSAエイリアス統合なし」「OSVの残り4エコシステム」 — 既知の制約、本設計が解消しない範囲の確認(§2・§4-2・§5-1・§7-1)。
- `docs/spec/bundled-package-detection-plan.md`§3-3・§4 — 同梱コンポーネント検知のトリアージという位置づけ、1アイテム約$0.02の専用予算ゲーティング(§7-2)。
- `docs/spec/name-variance-refactoring-plan.md:128,147` — OSV.dev全件ミラーを別バックログ項目として推奨順序2位に記載していた当初計画(本ドキュメントがその項目に対する具体設計にあたる)。
- `docs/spec/database-schema.md` — マイグレーション履歴一覧、GHSAミラー(V19)のテーブル一覧記載(§3の基準値の裏取り)。
- `docs/spec/stage1-golden-benchmark.md` — §9-2のA/B検証ゲートで使用しうるゴールデンセット候補(シニアレビュー項目11)。
- 実測データ: `/tmp/osv-all.zip`(1,518,436,782バイト、883,022件、`unzip -l`で実測)、`/tmp/modified_id.csv`(48,911,487バイト、948,110行、GCSから直接取得して実測)、`https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`(エコシステム名の正確な表記の一次情報源)、`https://osv-vulnerabilities.storage.googleapis.com/{npm,PyPI,Maven,Go,NuGet,RubyGems,crates.io,Packagist,Hex,Pub}/all.zip`(§6-1。**【シニアレビュー項目7で訂正】実際に実取得しサイズを実測したのはnpm/PyPI/Go/Mavenの4本のみ**——残り6本(NuGet/RubyGems/crates.io/Packagist/Hex/Pub)は「合計30MB以下見込み」という推定値であり実測していない、§6-1の記載と統一)——いずれも本ドキュメント作成時・改訂時に取得・確認した一次データ。
