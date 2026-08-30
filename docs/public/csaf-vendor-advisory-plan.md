# CSAFベンダーアドバイザリー対応 設計案（2026-08-27 設計のみ・未実装）

**実装状況の要約（2026-08-30追記、`known-limitations.md`と突き合わせ）**: タイトルの「設計のみ・未実装」は本ドキュメント執筆当時のものであり、その後フェーズ1（Siemens）・フェーズ2（Red Hat）は実装済みに進んでいる——`csaf_advisories`/`csaf_products`/`csaf_product_status`/`csaf_sync_state`の4テーブル（V17・V20）・`SiemensCsafSyncService`・`RedHatCsafSyncService`・`CsafVulnerabilitySource`が稼働中（`known-limitations.md`冒頭「CSAFベンダーアダプタ」項参照）。一方、Cisco分は未実装のまま（認証情報のストレージモデル承認待ちで§4-3/§10の通り明示的にスコープ外）、Red Hatの`csaf/v2/vex/`（実測約18.51GB相当）取り込みも§10の通りスコープ外。以下の本文（設計案そのもの）は当時の検討過程の記録として変更していない。

**本ドキュメントは設計のみ。実装コード・マイグレーション・設定変更は一切含まない。**

**改訂履歴**: 2026-08-27、シニアレビューのREVISE判定（16項目）を反映した全面改訂版。スキーマを2テーブルから4テーブルへ組み替え、検出結果の届け方（§8）を全面設計変更、レート制限・文書整合性・部分失敗対応・テスト戦略の各節を新設・具体化した。個々の変更点は末尾に一覧化していない——各節本文に「（2026-08-27改訂）」等の形で変更点そのものを埋め込む形式を取る。

対象は、`docs/spec/known-limitations.md`「未実装」節が既に記載している既知のギャップ——Red Hat・Cisco・Siemens等が個別に公開する**CSAF（Common Security Advisory Framework）形式の公式ベンダーセキュリティアドバイザリー**に、専用の`VulnerabilitySource`アダプタが存在しない件——である。同じギャップは`guide-integrations.html`「4. ベンダー公式アドバイザリー（CSAF等）」節にもユーザー向けに明記されている。`vendor_advisory_sources`テーブル（後述）は存在するが、行が投入されておらず、パース済みコンテンツを保持する仕組みも一切ない。

本ドキュメントは、事前に実施された`Explore`エージェントによる実現可能性調査（内部コード調査＋CSAF/ROLIE仕様・Red Hat/Cisco/Siemens3ベンダーのライブ確認）の結果を、設計として構造化したものである。調査結果そのものの再導出はしていない——引用は「実測・確認済み」「未検証」を区別して明記する。

---

## 0. 結論を先に（埋没させない）

**(a) 技術的には実現可能。** CSAF 2.0はOASIS Standard（2022-11）かつISO/IEC 20153（2025-05）であり、JSON形式の機械可読な仕様である。スクレイピング問題ではない。少なくともRed HatとSiemensは、無認証・スペック準拠の`provider-metadata.json`＋差分同期の手がかりを公開しており、これは本プロジェクトが既に実証済みの`CveOrgSyncService`（baseline+delta）パターンに近い形で取り込める。

**(b) しかし実際の作業量は「単一アグリゲータ」ではなく「ベンダーごとの個別対応」になる。** CSAF仕様はAggregator（集約ハブ）が全Publisherを網羅する義務を課していない。CISAが運用するアグリゲータは存在するが、Red Hat/Cisco/Siemensを実際にカバーしているかは**未確認**。今回確認した3ベンダーだけでも、発見方式（ROLIE feed vs. ディレクトリ+CSV差分 vs. 認証済みREST API）と認証要否がそれぞれ異なる、確認された断片化した世界である。

**(c) OSV.dev一括ミラー（過去に検討済みの別バックログ項目）との相対比較で、エンジニアリング工数は明確に高コスト。** OSVは「1ソース・1フォーマット・1差分機構」で、既存の`CveOrgSyncService`パターンをほぼコピーできた。CSAFは対象を3ベンダーに絞ってもなお「Nソース・N発見機構・N認証方式」であり、ストレージスキーマをゼロから設計する必要があり（§3）、さらにベンダーごとの照合ロジックが必要になる可能性が高い（§4, §8）。**ただしこれは「構築コスト」の軸であり、「稼働時コスト」の軸とは別である——後者は§0-1-3で述べる通りCSAFの方がむしろ有利。両者を混同しないこと。**

**(d) 【最も強調すべき価値提案の補足】NVD/CVE.org/OSVは、これら3ベンダーの製品に影響するCVEの"存在"自体は、既にかなりの部分を捕捉している可能性が高い。** CSAF/VEXが固有に追加する価値は「取りこぼしを埋める（カバレッジ）」ではなく、**製品コンポーネント単位の適用可否ステータス（fixed / known_affected / known_not_affected / under_investigation）という、より精密な情報**である。これはOSV一括ミラーの「カバレッジギャップを埋める」というストーリーとは性質が異なり、費用対効果の評価軸も異なるべきである——本ドキュメントはこの違いをそのまま各節に反映する。**（2026-08-27改訂）** この価値提案は§8の検出結果デリバリ設計に直接効く。当初案（CSAFを通常の競合`VulnFinding`として返す）はこの価値提案をまさに価値提案が効くはずの場面（NVD/OSV/CVE.orgが既に見つけている一般的なケース）で無効化してしまうバグを含んでいたため、§8で全面的に設計し直した——詳細は§8参照。

### 0-1. 本設計が踏襲する、このプロジェクトの既存の設計原則

以下は本ドキュメント独自の新発明ではなく、いずれも既にこのコードベースの別箇所に前例がある原則を、CSAF設計にそのまま適用したものである。「暗黙の前提」にせず、明示的な設計制約としてここに書き出す。

**1. 「見つからなかった」≠「安全と確認された」。** このプロジェクトは既にこの区別を`ResearchJobItem.researchIncompleteReason`（`INCOMPLETE_REASON_SOURCES_FAILED`＝ソース側の障害で実際には何も確認できていない、`INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK`＝識別が弱くAI検証を意図的にスキップした、`ResearchJobItem.java:70,79`）としてコード化しており、さらに直近では同梱パッケージ機能が同じ規律を「裁定不能」という形で明文化している（`bundled-package-detection-plan.md`§3-3「どちらにも当たらなければ『裁定不能』として記録し、脆弱性ありともなしとも判定しない…見つからない＝安全ではなく、単に確認できなかったという扱いにする」、`known-limitations.md`の該当エントリ「オプトインしたが変更履歴が見つからなかった項目は『異常なし』と見分けがつかない」）。

CSAFアダプタにもこの規律をそのまま適用する。**設計制約として明記する**: あるベンダーのフィードがまだ同期されていない場合、同期済みデータの中に該当製品が見つからない場合、あるいはベンダー自体が未対応（例: フェーズ1時点でのCisco、§10）の場合、これらのいずれも「このCSAFチェックの結果は"当該ベンダーのアドバイザリーは存在しない"」という意味で提示してはならない。既存の`VulnerabilitySource`契約（`VulnerabilitySource.java`のjavadoc）が既にこの区別を持っている——「本当に0件だった」と「このソースはこのアイテムに適用されない」の両方を`SourceResult.success(空リスト)`として扱い、`SourceResult.failure()`と区別する——ので、CSAFアダプタが単にこの既存契約に従う限り、構造的には自動的に満たされる。**（2026-08-27改訂）** §8で確立した`known_not_affected`のアノテーション表示ルール（該当CVEが他ソースで見つかっている場合にのみ、そのCVE個別への注記として表示——アイテム全体の安全宣言としては絶対に表示しない）も、この原則の直接の適用である。

**2. 一次情報源としての信頼（低信頼のLLM経路とは区別する）。** 本セッションの同梱パッケージ機能REVISEサイクルで確立されたルール（`BundledComponentResearchService.java:148-155`のコメント）は明快である: NVD/OSVのような一次情報源は`VulnerabilityRepository.upsertAndGetId`（`VulnerabilityRepository.java:26`、既存行を上書き更新できる）を使い、`insertIfAbsentAndGetId`（`:52`、「低信頼のLLM由来の発見が一次情報源の内容を上書きできないようにする」ためのもの、Stage4がこちらを使う、`Stage4WebSearchResearchService.java:73-76`）は低信頼な書き手専用に予約する。CSAF文書はベンダー自身が発行する一次情報（CVE.orgと同種の性質）であり、LLMの生成物ではない。**明記する**: CSAFアダプタは`CveOrgVulnerabilitySource`・`Stage2VulnerabilityResearchService`（`:71`）と同じ`upsertAndGetId`経路を使う一次情報源として扱う。`insertIfAbsentAndGetId`の低信頼経路は使わない。この原則は、まさにこの信頼レベルゆえに§6で新設する「文書の完全性・取得先の安全性」節の根拠にもなっている——一次情報源として無検証にDBへ書き込める経路だからこそ、書き込む前の文書自体の真正性検証（ハッシュ照合・SSRF対策）が重要になる。

**3. コスト面: 同期サービス+ローカルミラー方式は、per-item追加LLMコストがゼロ。** 既存のNVD/OSV/CVE.orgと同じ理由（`docs/spec/pipeline.md`のStage2行「無料 | 識別済みアイテムに常時」）で、CSAFアダプタも`VulnerabilitySource.find()`がローカルDBクエリのみで完結する設計である限り、稼働中の1アイテムあたりの追加コストはゼロである。これは`bundled-package-detection-plan.md`§4が明らかにした状況（LLM web_search呼び出しを伴うため1アイテムあたり約$0.02の追加コストが発生し、既存の$5/1,000件キャップを単独で突破するため専用の別枠予算が必要と結論づけた）とは**構造的に異なるコストの物語**である——CSAF対応は既存の$5/1,000件ブレンドコスト目標の枠内にそのまま収まり、`JobCostBudgetService`の予算ゲーティングという論点自体が発生しない。§0(c)で述べた「構築コストはOSVより高い」というのはエンジニアリング工数の軸であり、この稼働時per-itemコストの軸とは別問題である——優先順位を検討する際（§11）はこの両軸を混同しないこと。

**4. 具体先行・過剰な一般化の回避。** `name-variance-refactoring-plan.md:408-410`が示した前例（「一般化できない不規則ケースの表」を候補生成本体から物理的に分離した最後の手段として扱い、実際にはそのような表が最後まで不要だったこと）と同じ精神で、本設計は対象2ベンダー（Siemens/Red Hat）の段階では**製品照合ロジック**（ベンダーごとの製品分類の意味付け）の共有インターフェース層を先回りして作らない。詳細は§4・§8で述べる。**（2026-08-27改訂）** ただしこの原則は「ベンダー固有のロジックを共有しない」という話であって、「OASIS/ISO標準そのもののパース処理を共有しない」という話ではない——両者を混同しないことが§4の核心的な訂正点である。

以下、これら4原則を踏まえて詳細設計に入る。

---

## 1. 現状アーキテクチャの要約（コード引用）

### 1-1. `vendor_advisory_sources`テーブルは空の3列カタログで、パース済みコンテンツの置き場がない

`backend/src/main/resources/db/migration/V1__init.sql:96-102`:

```sql
CREATE TABLE vendor_advisory_sources (
    id            BIGSERIAL PRIMARY KEY,
    vendor_name   VARCHAR(255) NOT NULL UNIQUE,
    feed_type     VARCHAR(20) NOT NULL CHECK (feed_type IN ('csaf', 'rss', 'scrape')),
    url           TEXT NOT NULL
);
```

これはフィード自体のカタログであり、`cve_org_records`/`cve_org_affected_products`（V8）に相当する「パース済みアドバイザリー本体を保持するテーブル」が存在しない。§3で設計する4テーブルに相当する構造を新設しない限り、CSAFデータを保存する場所自体がない。

なお`vulnerabilities.source`（`V1__init.sql:63`、`VARCHAR(50)`）にはCHECK制約が無いため、`csaf_redhat`のような新しい`source`値を追加すること自体にマイグレーションは不要——`database-schema.md`が記す`nvd`/`osv`/`ghsa`/`cve_org`と同じ「運用上の規約」として扱える。

### 1-2. `VulnerabilitySource`はドロップイン——ただし新規ソース追加はStage2の逐次実行に直接コストを乗せる

`backend/src/main/java/com/vulncheck/app/service/vuln/VulnerabilitySource.java:23`:

```java
SourceResult find(ResearchJobItem item, IdentifiedProduct identifiedProduct, Long userId);
```

**（2026-08-27訂正）** 本節は当初、`Stage2VulnerabilityResearchService`が全`VulnerabilitySource`を**並行的に**問い合わせると記述していたが、これは事実誤認だった。同クラスのjavadoc（`Stage2VulnerabilityResearchService.java:18-26`）は明示的に次のように述べている:

> Sources are queried sequentially, one after another in a plain `for` loop (not in parallel) — each source's own findings still contribute regardless of order, since each has different coverage/lag and relying on just one risks missing known CVEs, but the calls themselves are not concurrent. Deliberately not parallelized: `ResearchJobProcessingService` already processes multiple items of a job concurrently, so parallelizing the source loop on top of that would only add more concurrent pressure on the already process-wide-shared NVD/GHSA rate limiters — no clear throughput win, just more contention.

つまりStage2の`research()`（`:58-82`）は`for (VulnerabilitySource source : vulnerabilitySources)`という単純な逐次ループ（`:62`）であり、各ソースへの`find()`呼び出しは1件のアイテム処理の中で直列に積み上がる。この誤記は`docs/spec/pipeline.md:37`からのコピーであり、**同ドキュメントの該当行自体も本改訂と同時に修正した**（本ドキュメントとは別ファイルだが、事実誤認の発生源であるため合わせて訂正——修正差分はこのドキュメントの管理範囲外）。

**この訂正が持つ設計上の意味**: N番目のソースを追加することはアーキテクチャ上ドロップイン（インターフェース変更は不要）だが、**逐次実行である以上、追加コストはアイテム単位の直接的なレイテンシとして積み上がる**——「並行だから追加は実質無料」という当初案の前提は誤りだった。1,000件/3時間のスループット目標（`project_three_pillar_targets`メモリ）がある以上、Stage2に第4のソースを素朴に足すことは看過できない。これが、§4で「Siemens用・Red Hat用の2つの`VulnerabilitySource`アダプタを別々に作る」という当初案を「単一の`CsafVulnerabilitySource`が`WHERE vendor IN (...)`で1回のクエリにまとめる」設計へ変更した直接の理由である——2ベンダー分の逐次クエリを1回に削減することで、この訂正が明らかにしたレイテンシコストを直接相殺する。

### 1-3. 最も近いテンプレートはNVD/OSVではなく`CveOrgVulnerabilitySource`

`CveOrgVulnerabilitySource.java`（クラスjavadoc、`:24-34`）は、CVE.orgの`affected[].vendor/product`フィールドが固定エコシステム分類を持たない自由文字列であることを理由に、`item.getVendor()`/`item.getProductName()`のCSV生テキストに対するローカルpg_trgmファジー検索を採用している。CSAFの`product_tree`も同様に、固定のエコシステム分類を持たないベンダー独自の製品分類である。したがってCSAFアダプタの直接のテンプレートはNVD/OSV（`ecosystem`/`packageName`キー）ではなく、この`CveOrgVulnerabilitySource`である。

具体的には、`matches()`（`:95-116`）がpg_trgm候補検索でヒットした各CVEの`affected[]`エントリを個別に再検証し、`isVersionAffected()`（`:131-160`）・`extractFixedVersion()`（`:162-177`）でバージョン範囲を評価する、という二段階（候補検索→エントリ単位の再検証）の設計が、CSAFの`product_status`ブロック単位の再検証にもそのまま応用できる形である。**（2026-08-27注）** ただし当初案のスキーマにはバージョンを保持する列が一切存在せず、「バージョン範囲を評価する」という本節の記述と矛盾していた——§3の新スキーマで`csaf_products.component_version`列を追加し、この矛盾を解消した。

### 1-4. `CveOrgSyncService`が再利用可能な同期サービステンプレート——ただし「per-document GET」ではなく「一括アーカイブ」が安全性の実体

`CveOrgSyncService.java`は`syncBaseline()`（フル同期、手動トリガー、`AdminController`経由、クラスjavadoc`:37-40`が明記する通り意図的に`@Scheduled`を付けていない）と`syncDelta()`（小さい日次差分、`CveOrgScheduledSync.java:21`が`cron`でスケジュール）の2メソッドが、いずれも同一の冪等な`upsertCveJson()`（`:148-190`）を経由する構成になっている。ストレージは`cve_org_records`（生JSON＋抽出済みフィールド）＋`cve_org_affected_products`（trgm検索用の非正規化行）。

**（2026-08-27追記）** `syncBaseline()`（`CveOrgSyncService.java:57-58`のjavadoc「Full baseline load — ~380k records, ~1.1GB download」）が安全に約38万件を同期できている実体は、380,000回の個別GETではなく、**GitHub Releaseアセットとして配布される単一のZIPアーカイブ2本（baseline用・delta用）を`download()`（`:272-278`）でストリーミング取得するだけ**という点にある。これはCSAF同期サービス設計にとって見過ごしてはならない前例であり、§5-6で詳述する——「per-documentのペースドGET」を素朴にbaseline同期の主経路として設計することそのものがレート制限リスクの発生源であり、ペーシングを足すだけでは解決しない構造の問題である。

これが、CSAF同期サービスが従うべき型である: プロバイダメタデータ取得→文書の発見（可能なら一括アーカイブ、なければper-document）→新設のローカルテーブルへupsert→`VulnerabilitySource`アダプタはミラーのみを照会し、アイテムごとのライブAPI呼び出しは行わない（`CveOrgVulnerabilitySource`クラスjavadoc`:19-22`と同じ契約）。

### 1-5. `IdentifiedProduct`はおそらく新規フィールド不要——ただしCSAFの`product_tree`はより階層的で、`relationships[]`は当初案が見落としていた構造

`IdentifiedProduct`（`ecosystem`/`packageName`/`cpe`/`purl`/`confidence`/`method`/`versionConfirmed`）は、`CveOrgVulnerabilitySource`の前例（`ResearchJobItem`の生の`vendor`/`productName`テキストで照合し、`ecosystem`/`packageName`は見ない）に倣えば、CSAFマッチングを可能にするためだけにStage1を拡張する必要はなさそうである。

ただし注意点として、CSAFの`product_tree`（branches、`full_product_names`、relationships、`product_status`ブロック）はCVE.orgの`affected[]`フラットリストより階層的・入れ子構造である。Red Hat（RHELバリアント/コンポーネント）、Cisco（IOS-XEトレイン/リリース）、Siemens（ハードウェア/ファームウェアファミリー）は、それぞれ独自の製品分類を`product_tree`にエンコードしている——共有可能なボイラープレートではなく、**ベンダーごとの個別マッチングロジックが必要になる見込み**（§8で詳述）。

**（2026-08-27追記・当初案の重大な見落とし）** 上記は「branches/full_product_namesの木を末端まで歩けば全製品が出てくる」という前提の記述だったが、これは正確ではない。CSAFの`product_tree.relationships[]`（`category: "default_component_of"`等）は、「あるコンポーネントが、別の製品（プラットフォーム）の一部として存在する」という組み合わせ製品（例: 「RHEL 9のコンポーネントとしてのopenssl-x.y.z」）を、branchesの木の末端とは**別の場所**（`relationships[].full_product_name.product_id`という、木の外側で生成される合成product_id）で表現する。当初案の「branchesを再帰的に歩いてfull_product_namesを非正規化して行に展開する」という素朴な木の走査だけでは、この合成product_idを参照する`product_status`エントリを一切解決できない——結果として、まさにRed Hatの典型的なユースケース（「RHELというプラットフォーム上のopenssl」）を取りこぼす設計になっていた。§3・§4の新設計（共有`CsafProductTreeWalker`）はこの見落としを解消することを主目的の一つとする。

---

## 2. CSAF/ROLIEという外形（標準・3ベンダーのライブ確認、未検証点を明記）

### 2-1. 標準としての位置づけ（確認済み）

CSAF 2.0はOASIS Standard（2022年11月）かつISO/IEC 20153（2025年5月）——JSON形式で安定した仕様。ROLIEはCSAFプロバイダが発見用に使うAtomベースの索引形式（各エントリがCSAF JSON文書へのリンク＋ハッシュ＋署名を持つ）。

**単一の必須集約フィードは存在しない。** CSAF仕様はAggregatorがPublisher全体を網羅する義務を課していない。CISAがアグリゲータを運用しているが、Red Hat/Cisco/Siemens個別のカバレッジは**未確認**。

### 2-2. 3ベンダーのライブ確認結果

| ベンダー | 発見方式 | 認証 | 確認状況 |
|---|---|---|---|
| **Siemens** | 仕様準拠`provider-metadata.json`（`https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json`）→ROLIEフィード（`ssa-feed-tlp-white.json`） | 不要 | ライブ確認済み。1回のfetchで70件以上のエントリを確認（**打ち切られた取得結果であり、総数の下限として扱うべきで、総数そのものではない**） |
| **Red Hat** | `provider-metadata.json`（`security.access.redhat.com`へリダイレクト）→フラットディレクトリ（`csaf/v2/advisories/`、`csaf/v2/vex/`）＋差分同期用`changes.csv`/`deletions.csv`（形式: `"path","ISO8601タイムスタンプ"`、更新順ソート） | 不要 | ライブ確認済み。打ち切られたfetchでCVE年2011〜2026にまたがる約1,800〜2,000件以上の行を確認（**これも総数ではない**） |
| **Cisco** | PSIRT openVulnAPI（`apix.cisco.com`/`api.cisco.com`）経由でアドバイザリーごとにCSAFを取得可能 | **JWTベアラートークン必須**（developer.cisco.comでのアプリ登録が前提） | Cisco DevNetドキュメントで確認——他2ベンダーと異なり匿名利用不可 |

### 2-3. 明示的に未検証の項目（事実として扱わない）

- Red Hat/Siemensの総文書数・更新頻度: CVE.orgの「約38万件・約1.1GB」のような公式な統計は見つかっていない。上表の件数は打ち切られたfetchの観測値にすぎない。**これは§5のレート制限計算にも直接影響する未確定値であり、そちらでも改めて触れる。**
- いずれかのCSAFアグリゲータが実際にこの3ベンダーを再配信しているかどうか。
- Ciscoの登録手続きの具体的な摩擦・レート制限（「JWT認証が必須」という事実の先は未確認）。
- Red Hatの`csaf/v2/advisories/`・`csaf/v2/vex/`ディレクトリ自体がROLIE形式かどうか（`changes.csv`による差分機構自体は、これとは独立に利用可能と確認済み）。
- **「専用ライブラリ不要、JsonNodeの手動走査で足りる」という結論——前例からの推論であり、本調査で実際のCSAF `product_tree`に対して検証されたわけではない。** OASISが提供するJavaツールはCVRF 1.2 XML専用でCSAF 2.0 JSONには非対応。Pythonツール（csaf-validator, csaf-check）はあるが本プロジェクト（Java）には使えない。本プロジェクト自身の前例（`CveOrgSyncService.upsertCveJson()`/`CveOrgVulnerabilitySource.matches()`が生成POJOではなくJacksonの`JsonNode`を手で歩く方式）は同じアプローチがCSAFにも通用することを示唆するが、**これは推論であり、実測ではない**。
- ~~**（2026-08-27追記）** Red Hatが「年次の`.tar.zst`一括アーカイブ＋`archive_latest.txt`」というCSAF仕様のディレクトリベースアーカイブ規約に沿った配布を実際に行っているか——これは実装スパイクで初めて確認すべき事実であり、本ドキュメントでは**未検証の推測として明記するに留める**（§5-6参照）。仮に存在すれば、baseline同期の主経路をper-document GETの束からこの一括アーカイブへ差し替える必要がある。~~ **（2026-08-27 go/no-goレビューで確認済みに更新）** ライブ確認済み——実在し、ダウンロード可能（§5-6参照）。baseline同期はこの一括アーカイブを主経路として実装した。
- Red Hatの`deletions.csv`は§2-2の表に既に記載されている実在のCSVであることは確認済みだが、当初案ではこのCSVを一切消費していなかった——§7で設計に組み込む。

---

## 3. 提案スキーマ: 新規4テーブル（`cve_org_*`ペアを踏襲しつつ、CSAF固有の階層に合わせて再設計）

**（2026-08-27全面改訂）** 当初案は「`csaf_advisories`＋`csaf_affected_products`」の2テーブルで、1アドバイザリー内の全CVEに対して単一の`status`列しか持たせていなかった。これは実際のCSAFの意味論と矛盾する——**CSAFは製品の適用可否ステータスを"(脆弱性, 製品)"の組ごとに持つのであって、"(アドバイザリー, 製品)"の組ごとに持つのではない**。1つのRHSAが20件以上のCVEを束ね、同じコンポーネントがあるCVEには`fixed`、別のCVEには`known_not_affected`という、CVEごとに異なるステータスを持つケースは珍しくない。旧スキーマの「1行1ステータス」という形状では、この最も基本的なCSAFの構造そのものを表現できない。またバージョン列が一切存在せず（§1-3で述べた「バージョンを再検証する」という本ドキュメント自身の記述と矛盾していた）、`product_tree.relationships[]`（`category: "default_component_of"`によるコンポーネント・イン・プラットフォーム表現、§1-5参照）を解決する手段も無かった。以下は、これら3点をすべて解消した4テーブル構成である。

```sql
-- csaf_advisories: 1アドバイザリー文書につき1行。生JSONはあくまで再導出・デバッグ用に保持し、
-- find()の実行時パスでは絶対にパースしない（CSAF文書はCVE.orgの1レコードよりはるかに大きく、
-- 構造化列に落とし込んだ csaf_products / csaf_product_status だけを実行時参照経路とする）。
CREATE TABLE csaf_advisories (
    vendor          VARCHAR(50) NOT NULL,    -- 'redhat' | 'siemens' | （将来）'cisco'
    tracking_id     VARCHAR(100) NOT NULL,   -- CSAFの tracking.id（例: RHSA-2026:1234, SSA-123456）
    tracking_status VARCHAR(20) NOT NULL,    -- 'draft' | 'interim' | 'final'（§7: draft/interimは所見として出さない）
    revision        VARCHAR(50),             -- tracking.version（改訂番号。ベンダーによりセマンティクスが異なる自由文字列として保持）
    title           TEXT,
    tlp_label       VARCHAR(20),             -- distribution.tlp.label（'WHITE'/'GREEN'/'AMBER'/'RED' 等）
    cvss_score      NUMERIC,
    cvss_severity   VARCHAR(20),
    date_published  TIMESTAMPTZ,
    date_updated    TIMESTAMPTZ,
    raw_json        TEXT NOT NULL,           -- 再導出・デバッグ専用。find()は絶対に直接パースしないこと。
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (vendor, tracking_id)        -- tracking.id はベンダー内では一意だがベンダー間の一意性は保証されない
);

-- csaf_products: 1アドバイザリー内の distinct な解決済み製品につき1行。
-- component_name/component_version は product_tree の product_version ブランチから、
-- platform_name は relationships[]（default_component_of 等）で解決した「関係先」製品の名称。
-- 単体製品（プラットフォーム関係を持たない）の場合 platform_name は NULL。
CREATE TABLE csaf_products (
    id                  BIGSERIAL PRIMARY KEY,
    vendor              VARCHAR(50) NOT NULL,
    advisory_id         VARCHAR(100) NOT NULL,     -- csaf_advisories.tracking_id
    csaf_product_id     TEXT NOT NULL,              -- CSAF自身の product_tree 上の product_id（アドバイザリー内で一意）
    component_name      TEXT,                       -- 実際にCSVのproduct_nameと照合する対象（trgm候補検索はこの列のみ）
    component_version   TEXT,
    platform_name       TEXT,                       -- 関係先プラットフォームの名称。関係を持たない製品ではNULL
    cpe                 TEXT,
    purl                TEXT,
    UNIQUE (vendor, advisory_id, csaf_product_id),
    FOREIGN KEY (vendor, advisory_id) REFERENCES csaf_advisories (vendor, tracking_id) ON DELETE CASCADE
);

CREATE INDEX idx_csaf_products_advisory ON csaf_products (vendor, advisory_id);
-- component_name のみにtrgmインデックスを張る。CSVのproduct_nameと実際に照合するのはこの列だけであり、
-- platform_name（"Red Hat Enterprise Linux 9" のような高反復文字列）にインデックスを張ると、
-- §3-1のボリューム試算のもとでは選択性がほぼゼロの巨大GINインデックスを作ることになるだけで、
-- どのクエリにも使われない。
CREATE INDEX idx_csaf_products_component_name_trgm ON csaf_products USING gin (component_name gin_trgm_ops);

-- csaf_product_status: (脆弱性 × 製品) の行列そのもの。旧スキーマのカンマ区切り cve_ids TEXT 列は
-- 完全に廃止し、代わりにインデックス可能な cve_id 列を持つこのテーブルに置き換える。
CREATE TABLE csaf_product_status (
    id                  BIGSERIAL PRIMARY KEY,
    vendor              VARCHAR(50) NOT NULL,
    advisory_id         VARCHAR(100) NOT NULL,
    cve_id              VARCHAR(50) NOT NULL,
    csaf_product_id     TEXT NOT NULL,
    status              VARCHAR(30) NOT NULL,  -- 'fixed' | 'known_affected' | 'known_not_affected' | 'under_investigation'
    fixed_version       TEXT,                  -- ベンダー独自の後継バージョン（多くはNEVRA形式。§8の注意点参照——
                                                 -- vulnerabilities.fixed_version には絶対に流用しないこと）
    remediation_url     TEXT,
    FOREIGN KEY (vendor, advisory_id) REFERENCES csaf_advisories (vendor, tracking_id) ON DELETE CASCADE,
    FOREIGN KEY (vendor, advisory_id, csaf_product_id)
        REFERENCES csaf_products (vendor, advisory_id, csaf_product_id) ON DELETE CASCADE
);

CREATE INDEX idx_csaf_product_status_cve ON csaf_product_status (vendor, cve_id);
CREATE INDEX idx_csaf_product_status_advisory_product ON csaf_product_status (vendor, advisory_id, csaf_product_id);

-- csaf_sync_state: 変更なし（ベンダーごとに同期状態を持つ）。
CREATE TABLE csaf_sync_state (
    vendor            VARCHAR(50) PRIMARY KEY,
    last_synced_at    TIMESTAMPTZ,
    last_cursor       TEXT   -- Red Hat: changes.csv/deletions.csvの最終処理タイムスタンプ / Siemens: ROLIEフィードの最終更新時刻
);
```

**設計判断（本ドキュメント作成時に決めた点）**:
- `status`と`fixed_version`を`csaf_advisories`ではなく`csaf_product_status`に持たせたのは、上述の通りCSAFのステータスが「(脆弱性, 製品)」単位だから。1アドバイザリーが束ねる複数CVEが、同じ製品に対して異なるステータスを持つケースをこの形状でのみ正しく表現できる。
- `csaf_products`と`csaf_product_status`を分けたのは、同じ製品が複数のCVEに対して異なるステータスを持ちうる（多対多）ため——製品の属性（名前・バージョン・プラットフォーム）を製品ごとに1回だけ持ち、ステータスだけをCVEごとに繰り返す方が、非正規化の重複を`fixed_version`/`remediation_url`という薄い列に限定できる。
- `csaf_advisories`は`cve_org_records`と異なり複合主キー（`vendor, tracking_id`）にした。CVE.orgは単一の権威的な採番元だが、CSAFはベンダーごとに独立した`tracking.id`空間を持つため、ベンダー間の衝突を主キーレベルで防ぐ必要がある。
- `csaf_sync_state`をベンダー単位の複数行テーブルにしたのは、§4の通り同期サービス自体がベンダーごとに独立するため——1ベンダーの同期失敗が他ベンダーの状態を巻き込まないようにする。
- アーキテクチャのみが異なるブランチ変体（x86_64/aarch64/s390x/ppc64le等）は、`csaf_products`に別々の行として展開しない——同一の(component_name, component_version, platform_name)に集約する1行として折りたたむ。これは§3-1のボリューム制御に直結する設計判断であり、ステータスがアーキテクチャ間で実際に異なる可能性がある（CSAF仕様上は許容されている）という仮定の妥当性そのものは、§3-1・§9のスパイクで検証すべき未確認事項として扱う。

**（2026-08-27追記・go/no-goレビューでの訂正: `raw_json`のサイズ見積もりを修正する）** 本フェーズ着手前の見積もりでは`raw_json`列（TEXT、圧縮なしJSON文書全文をアドバイザリー単位で保持）が実測で約98GBに達するという懸念が示され、これが今回の詳細調査のきっかけの一つになっていた——**この見積もりは誤りで、実測の約16倍過大だった**。実際にRed Hat advisories全27,930文書をダウンロード・展開して計測した結果、生JSON合計は**6.09GB**（`6,092,320,215`バイト、2026-08-27実測）であり、PostgreSQLのTOAST圧縮後の実ストレージ使用量は**約1.06GB**にとどまる。したがって`raw_json`列の設計は**Phase 1の設計のまま変更しない**——上記98GBという誤った見積もりが将来また同じ懸念を呼び起こさないよう、ここに正しい実測値を記録しておく。

### 3-1. 行数・選択性の見積もり——実装スパイクでの`EXPLAIN ANALYZE`を必須のマージ条件とする

`cve_org_affected_products`は約38万CVE×数行程度の規模である。これに対し、CSAFは1つのRHSAだけで数百〜数千件の(製品×バリアント×アーキテクチャ)組を列挙することが珍しくなく、Red Hat・Siemens合計で`csaf_products`/`csaf_product_status`が現実的に**1,000万〜2,000万行規模**に達する可能性がある。しかも値の反復度が極端に高い——"Red Hat Enterprise Linux 9"のような文字列が何百万行にもわたって繰り返される。

このボリューム特性は、trgmクエリの実際のプラン形状（GINインデックスが本当に使われるか、候補行数が現実的な範囲に収まるか）を「本番で問題が起きてから」ではなく**実装前に確認すべき**ことを強く示唆する。このプロジェクトには既にこの教訓の一次情報源がある——`backend/src/main/resources/db/migration/V9__trgm_query_performance.sql`のコメントが明記する通り、`cve_org_affected_products.package_name`に対する当初の`similarity(col, x) > threshold`というクエリ形状は、GIN trgmインデックスをそもそも一切使えないことが`EXPLAIN`で確認されるまで気づかれなかった（`%`演算子のみがインデックスを使える）。この失敗は既に一度この規模のプロジェクトで実際に起きている。

**マージ条件として明記する**: 実装スパイクは、`csaf_products`/`csaf_product_status`に現実的なボリューム（§3-1の見積もり相当、最低でも数百万行規模のダミーデータかRed Hatの実データ）を投入した状態で、候補検索クエリに対して`EXPLAIN ANALYZE`を実行し、想定通りGINインデックスが使われ、実行時間が許容範囲であることを確認してからでなければマージしてはならない。アーキテクチャ変体の折りたたみ（上記の設計判断）は、この行数を制御するための直接の手段であり、「実装したら重かったので後から折りたたむ」ではなく最初から設計に組み込む。

**追記（2026-08-27、シニアレビューREVISE項目9への対応）**: 上記のマージ条件は、Phase 1（Siemensのみ）の実装完了時点では未実施のまま据え置く——意図的な先送りであり、失念ではない。理由: Phase 1時点でSiemensの実測ボリュームは831アドバイザリー・`csaf_products`で数千行規模（V17マイグレーション適用直後の実測）であり、本節が問題視している「1,000万〜2,000万行規模」「値の反復度が極端に高い」というシナリオはRed Hatが参入して初めて成立する。Phase 1のボリュームでは`WHERE vendor IN (...) AND component_name % ?`が仮にプランナーにGINインデックスを使われず逐次スキャンへフォールバックしたとしても、実行時間への影響は無視できる規模に留まる。したがって、このマージ条件は**Phase 2（Red Hat同期サービスの実装）に持ち越す**——Red Hatの参入によって初めてこのクエリ形状が実際に負荷を支配する（load-bearing become）ため、Phase 2の着手前に必須のマージ条件として再度明記する。Phase 1のみをスコープとするレビュー・マージ判断において、本条件の未充足を理由にブロックしないこと。

---

## 4. 提案アーキテクチャ: ベンダーごとの個別同期サービス＋標準パース処理の共有

**なぜ発見機構（同期サービス）は単一の汎用クライアントにしないか**: §2-2の通り、Siemens（ROLIEフィード）とRed Hat（ディレクトリ一覧+`changes.csv`/`deletions.csv`差分）は発見機構そのものが異なる。「次に同期すべき文書の一覧をどう取得するか」という同期サービスの中核ロジックは共有できない。`CveOrgSyncService`が単一ベンダー（CVE.org）専用に書かれているのと同じ理由で、CSAFも**ベンダーごとに独立した`SiemensCsafSyncService`/`RedHatCsafSyncService`**とする——この判断自体は当初案から変更していない（ROLIE feedと`changes.csv`は本質的に異なる発見機構であり、この分割は正しい）。

**（2026-08-27訂正）しかし`product_tree`のパース処理そのものは、当初案が想定していたより明確に共有すべきである。** 当初案は「JSON構造のパース自体は仕様共通なので共有ヘルパーとして切り出す余地がある"かもしれない"」という留保付きの記述に留めていたが、これは§0-1原則4（過剰な一般化の回避）を誤って適用していた。原則4が避けているのは「**ベンダー固有のロジック**を2ベンダーの段階で先回りして抽象化すること」であり、`product_tree`/`product_status`のJSON構造そのものはOASIS/ISO標準として仕様化されている——これを2回別々にパースすることは「時期尚早な一般化を避ける」ことにはならず、単に**同じ仕様を2回冗長にパースする**だけである。したがってフェーズ1から次の2点を共有する:

1. **共有`CsafProductTreeWalker`**: `product_tree.branches[]`を再帰的に歩いて末端の`full_product_names`を`csaf_products`候補行へ展開し、**`relationships[]`（`category: "default_component_of"`等）を解決して`platform_name`を埋める**（§1-5で洗い出した、当初案が見落としていたギャップの直接の解消）。アーキテクチャのみが異なる兄弟ブランチを1行に折りたたむロジック（§3の設計判断）もここに集約する。
2. **共有`upsertCsafDocument(String vendor, JsonNode root)`**: メタデータ抽出→`csaf_advisories`へupsert→`CsafProductTreeWalker`で`csaf_products`へ展開→`vulnerabilities[].product_status`ブロックを歩いて`csaf_product_status`へ展開、という`CveOrgSyncService.upsertCveJson()`と同型の冪等upsert処理。`SiemensCsafSyncService`/`RedHatCsafSyncService`はいずれもこの共有メソッドを呼ぶだけで、文書パース自体を自前で持たない。

一方、「パースした結果をどう`ResearchJobItem`の生テキストと突き合わせるか」（§8のマッチングロジック）はベンダーごとの製品分類の意味付けに依存するため、依然として共有しない——ここは§0-1原則4がそのまま適用される部分であり、当初案のこの点自体は正しかった。

### 4-1. `SiemensCsafSyncService`（設計スケッチ）

```
1. GET provider-metadata.json → ROLIEフィードURL（ssa-feed-tlp-white.json）を取得
2. ROLIEフィードの各エントリ（<entry>ごとに、CSAF JSON文書へのリンク＋updated日時＋ハッシュ＋署名）を
   updated日時の昇順で走査（§7: 昇順処理・逐次チェックポイントの原則）
3. csaf_sync_state.last_cursor（前回同期時の最新updated日時）より新しいエントリのみ処理
   （syncBaseline: last_cursorがNULL/未設定の場合に全件、syncDelta: last_cursorより新しい分のみ）
4. 各エントリについて: §6のハッシュ検証→問題なければ§4の共有 upsertCsafDocument("siemens", json) を呼ぶ
   →成功したら csaf_sync_state.last_cursor をこのエントリのupdated日時まで進めてコミット（§7: 1件ごと
   またはごく小さいバッチごとにチェックポイント。失敗した場合はcursorを進めず次回再試行する）
```

### 4-2. `RedHatCsafSyncService`（設計スケッチ）

```
1. GET provider-metadata.json → security.access.redhat.com 配下のディレクトリURLを解決
2. baseline: §5-6でまず一括アーカイブ配布の有無を確認し、存在すればそれを主経路とする
   （存在しない場合のper-document GETは§5-6が定めるフォールバックとしてのみ許可）
3. delta: GET changes.csv（"path","ISO8601タイムスタンプ" の行、更新順ソートと確認済み）
   →csaf_sync_state.last_cursorより新しい行のみ、タイムスタンプ昇順で処理・逐次チェックポイント（§7）
4. GET deletions.csv（同形式）→前回処理以降の行について、pathからtracking_idを解決し、
   該当する csaf_advisories 行を削除（CASCADE で csaf_products/csaf_product_status も連動削除）。
   これを消費しない限り、撤回・失効したアドバイザリーがローカルミラーに永久に残り続ける（§7）。
5. 各文書について: §6のハッシュ検証（.sha256サイドカー）→問題なければ§4の共有
   upsertCsafDocument("redhat", json) を呼ぶ
```

### 4-3. Ciscoは明示的に後回し（クレデンシャル・ゲート、かつ本アプリ初のシステムレベル認証情報）

Ciscoだけが認証（JWTベアラートークン＋developer.cisco.comでのアプリ登録）を要する。これは`feedback_stop_for_credentials`メモリの方針（認証トークン系が必要な場合は必ずユーザーに確認してから進める）が直接適用される事項であり、**先に構築すべき対象ではない**。

**（2026-08-27追記・明記が必要な点）** これは単に「トークンを取得すればよい」という話ではない点を明示する。本アプリの既存の認証情報はすべて`user_secrets`テーブル（`V1__init.sql:16-23`、`(user_id, provider)`の複合ユニーク制約、`provider IN ('claude', 'nvd')`）に**ユーザー単位**で保持され、`SecretEncryptionService`/`UserApiKeyService`経由で個々のユーザーが自分のAPIキーを登録・管理する設計になっている。Cisco PSIRT JWTはこれとは性質が異なる——**同期サービス自身がバックグラウンドで使う、アプリ全体で1つのシステムレベル認証情報**であり、特定ユーザーに紐付かない。したがって、Ciscoフェーズ着手時にユーザーに確認すべきなのは「トークンを発行してよいか」だけでなく、**このアプリにとって初めてとなる「ユーザー単位ではないシステム認証情報」をどこにどう保存し、誰が所有し、どう失効・ローテーションするか**という、既存の`user_secrets`パターンでは対応できない新しいストレージ・所有権モデルそのものである。これはCiscoフェーズ着手前に、単発の「トークンください」以上の承認をユーザーから得るべき事項として明記する（§10で改めて述べる）。

Siemens/Red Hatの無認証パスを先に実装・検証し、Ciscoは「クレデンシャル発行の可否とストレージモデルをユーザーに確認してから」着手する、という順序を推奨する（§10）。同時に§0-1原則1のとおり、Ciscoが未対応である間、CSAFアダプタの結果は「Ciscoアドバイザリーは存在しない」ではなく単に「Cisco向けCSAFチェックは未実施」として構造的に沈黙する。

### 4-4. どちらを先に実装するか: Siemensを先にする（2026-08-27、本ドキュメントで決定）

**（2026-08-27改訂・当初は未決定事項として先送りしていたが、本改訂で決定する）** Siemensを先に実装する。理由:

1. 発見機構が単一のROLIEフィードのみで、Red Hatの「ディレクトリ一覧＋`changes.csv`＋`deletions.csv`＋（§5-6で検証すべき）一括アーカイブの有無」という複数機構の組み合わせより単純。
2. §2-2のライブ確認値（打ち切られたfetchの下限とはいえ）でSiemensが70件超、Red Hatが1,800〜2,000件超と、概算でおよそ2桁の差があるボリューム——§4で新設する共有`CsafProductTreeWalker`・§5のペーシングゲート・§8の照合ロジックを、より小さく制御しやすい対象で先に端から端まで検証できる。
3. Red Hatは§2-3・§5-6で未検証のまま残っているbaseline全量取得手段（一括アーカイブの有無）という、設計時点で解決していない論点を抱えている——これを検証・実装する前に、Siemensで一度パイプライン全体を動かしておく方がリスクが低い。

Red Hatの方がエンドユーザーとの関連性（Linuxサーバー製品がCSVコーポラに出現する見込み）が高いと考えられる点は、**Red Hatを2番目に優先すべき理由であって、1番目にすべき理由ではない**——技術的な複雑さと未検証事項をSiemensで先に消化してから、より価値の高いが複雑なRed Hatに進む、という順序が本ドキュメントの結論である。

---

## 5. レート制限（同期サービスごと、明示的に扱う——一次確認事項）

このプロジェクトには痛みを伴う実例が2つある。**新しい外部同期ループを書くたびに、実装後に問題が起きてからレート制限を足すのではなく、実装前に想定される同期ボリューム（baselineとdelta双方）に対して`呼び出し回数 × 待機間隔`の概算を必ず行う**、というのがそこから得られた教訓であり、本設計もこれをそのまま踏襲する。

- `ExternalRegistryRateLimiter`は、レジストリ照合の並列化（1アイテムにつき最大10レジストリ同時照会）後にクライアント側ペーシングが一切存在しないことが判明し、1,000件ジョブ実行中に実際に crates.io の公開ルール（1req/秒）と Maven Central のボット遮断をほぼ突破しかけた（`project_vuln_research_server`メモリ「External registry rate limiting」記載、稼働中のジョブを途中で止める事態になった）ことを受けて追加された。
- GHSAがStage2のper-item経路から外された（`docs/spec/pipeline.md:45`）のは、無認証60req/hourという実際の制限が実運用負荷下でほぼ即座に枯渇したため（`project_ai_cost_target`メモリ記載）——これも事前に`呼び出し回数 × 間隔`の算数をしていれば、もっと早く気づけたはずの問題だった。
- `NvdRateLimiter`は単一外部ソース専用の既存パターン（`NvdRateLimiter.java`、キー無し6.5秒間隔・キーあり700ms間隔、`:33-35`）。

### 5-0. これは「バックグラウンドジョブ」の問題であり、「ジョブ内per-item」の問題とは形が違う

`ExternalRegistryRateLimiter`/`NvdRateLimiter`が解いているのは、**ユーザーのジョブ処理中に、CSV1行ごとに発火するライブ照会**をペーシングする問題である（Stage1のレジストリ照会、Stage2のNVD照会）。CSAF同期サービスはこれと違い、`CveOrgSyncService`と同様に**ユーザーのジョブ実行とは独立したバックグラウンド処理**であり、「1回のフィード全体取得（baseline）をどれだけ速く終えられるか」「更新をどれだけの頻度でポーリングできるか（delta）」という、同期サービス自身の実行1回の中で完結する問題である。両者は形が違うことを明記した上で、下記5-4で機構の再利用可否を決定する。

### 5-1. Siemens（ROLIEフィード）

公開されたレート制限は本調査では見つかっていない（§2-3）——**未検証・未確認として扱う**。`ExternalRegistryRateLimiter`が公開値の無いエコシステムに対して行っている慣習（`ExternalRegistryRateLimiter.java:46-60`、既定フォールバック500ms、chocolateyのように新規追加ソースは「無制限と決めつけず、Maven Centralと同じ保守的な階層」を割り当てる）と同じ考え方で、**保守的な既定ペーシング（例: 500ms〜1,000ms/リクエスト）を、実測される限界が見つかるまでの暫定値として適用する**ことを推奨する。

概算（あくまで仮の下限値ベース、実装前に総数を再確認する前提）: baseline同期は`provider-metadata.json`取得1回＋ROLIEフィード取得1回＋確認済みの70件超（打ち切られたfetchの下限、真の総数は未確認）の個別文書取得。500msペーシングだけでも数分規模——この規模自体は問題にならない可能性が高いが、**真の総数が未確認である以上、この見積もりをそのまま実装の根拠にしてはならない**。実装直前に一度、フィードの総エントリ数を実際に数え上げてから、この概算を差し替えること（§5-5のマージゲート表を埋める作業そのもの）。

### 5-2. Red Hat（`changes.csv` + 文書ごとの個別取得、ただし§5-6でbaselineの主経路が変わりうる）

同じく公開されたレート制限は見つかっていない（§2-3）——保守的な既定ペーシングを推奨する。**ボリューム面での注意点を明記する**: §5-6の一括アーカイブが実在しない場合、baseline同期は確認済みの約1,800〜2,000件超（これも打ち切られたfetchの下限、真の総数は未確認）の個別CSAF文書それぞれに対して個別のペーシング済みGETが必要になる——仮に保守的な500ms〜1,000ms/リクエストで概算すると、文書2,000件だけで15〜35分規模になる——**この数字自体、真の総数が未確認のため過小評価の可能性が高く、実装前のライブスパイクで総数を確認してから再計算すべき、確定値ではなく「事前に概算する習慣そのものが必須」であることを示すための仮数値**として提示している。delta同期（`changes.csv`の前回同期以降の差分行のみ）はCVE.orgの日次差分（数十件規模）と同様に小さいと見込まれ、リスクは相対的に低い。

### 5-3. Cisco（後回し、フェーズ外）

PSIRT openVulnAPIは登録制・JWT認証付きの開発者APIであり、この種のAPIには通常、明文化されたレート制限が付随する（未確認だが一般的なパターン）。**これはCisco対応フェーズ（§4-3、§10）で実際に着手する時に確認すべき既知の未確認事項として明記するに留める**——Siemens/Red Hatフェーズ1の着手を妨げるものではない。

### 5-4. 機構: `ExternalRegistryRateLimiter`をベンダー別キーで再利用する（2026-08-27、本ドキュメントで決定）

**（2026-08-27改訂・当初は実装者の裁量として先送りしていたが、本改訂で決定する）** `ExternalRegistryRateLimiter`の既存マップに`siemens_csaf`/`redhat_csaf`のようなキーを追加し、同期サービスからも同じインスタンスの`awaitTurn(key)`を呼ぶ。

**決定理由**: §5-0で述べた通り呼び出しパターンの形（バックグラウンド同期 vs. ジョブ内per-item照会）は異なるが、根底の機構（「この外部サービスへの呼び出し間には最低Nミリ秒空ける、プロセス全体で1つのゲート」というper-key lock + next-allowed-atの記帳方式、`ExternalRegistryRateLimiter.java:88-123`）はそのまま転用できる。より重要な理由は次の点である: **スケジュールされたdelta同期が、まだ完了していない数時間規模のbaseline同期の途中で発火した場合**、もし両者が独立したペーシング機構を持っていたら、同じホストに対して意図した2倍のレートで同時に叩く独立した2つのループが生まれてしまう——プロセス全体で1つの鍵付きゲートに相乗りさせることで、この事態を構造的に不可能にできる。専用の軽量機構を新設する選択肢(b)は、この「同時実行時の合算レート」という論点に対して`ExternalRegistryRateLimiter`と同等以上の保証を独自に再実装する必要があり、既にテスト済みの機構を再利用する方が明らかに合理的。

**あわせて明記する**: ベンダーごとの「同期実行中」ガードを別途設ける——同一ベンダーに対する2つの同期実行（例: 手動トリガーのbaseline同期と、スケジュールされたdelta同期）が同時に走らないようにする排他制御（`csaf_sync_state`行への簡易ロック、または同等の仕組み）を同期サービス自体に持たせる。ペーシングゲートの共有だけでは「同時に2つの独立したループが動いている」という状態そのものは防げない（両方とも正しくペーシングされたうえで、それでも合算のリクエスト数が2倍になる）ため、この2つの対策は独立に必要。

### 5-5. マージゲート: 呼び出し回数×間隔の実測表（実装前に埋め、実装スパイクの成果としてPRレビューで確認する）

**（2026-08-27新設）** 「実装前に呼び出し回数×間隔を概算する」という本節冒頭の原則を、単なる心構えの記述に終わらせず、実際のマージ条件にする。以下の表は空のまま本ドキュメントに残す——**実装スパイクでこの表を埋め、埋まった状態でシニアレビューを経てから同期サービスをマージすること**。あわせて、埋まった数値は同期サービス自身のクラスjavadocにもそのままミラーすること（このプロジェクトの既存の慣習——`NvdRateLimiter.java:33-35`のインターバル値のインラインコメント、`ExternalRegistryRateLimiter.java`のクラスjavadocが実測の根拠をコード自体に埋め込んでいる形に倣う）。

**（2026-08-27追記・Phase 2完了時点で更新）** Red Hat行は`RedHatCsafSyncService`実装完了に伴い実測値で埋めた——同じ数値は`RedHatCsafSyncService`自身のクラスjavadocにもミラーしてある。

| ベンダー | 実測baseline文書数 | 採用したペーシング間隔 | 概算所要時間（wall-clock） | delta文書数/日 | cron周期 | 最悪ケースreq/hour |
|---|---|---|---|---|---|---|
| Siemens | 831件（ROLIEフィード全エントリ数、2026-08-27実測） | 500ms/リクエスト（`ExternalRegistryRateLimiter`、キー`siemens_csaf`——既存のフォールバック既定値と同値だが、§5-4の決定通り明示的なマップエントリとして追加） | 実測18.7分（831件を1リクエスト/件でペーシング取得——実装のsyncBaselineは文書取得+ハッシュサイドカー取得の2リクエスト/件のため、実運用は概ね30〜40分規模と見込む。この上振れ分は未実測の外挿であり、実測値とは明記して区別する） | 実測0〜2件/日（過去30日間のROLIEフィード`updated`日時を集計したところ19/831件——1日平均0.6件、2026-08-27実測） | 毎日03:45 UTC（`CveOrgScheduledSync`の03:30 UTCと重複しないようオフセット） | 7,200（500ms固定間隔の理論上限——実際のトラフィックはbaseline実行時以外はこれよりはるかに低い） |
| Red Hat | 27,930件（`csaf_advisories_2026-08-25.tar.zst`実測、2026-08-27。`changes.csv`自体は28,102行——現行アーカイブのスナップショットに存在しない過去分を含むため差分がある） | baseline: `archive_latest.txt`取得1回＋アーカイブ本体取得1回のみペーシング対象（キー`redhat_csaf`、500ms floor）——約103MBの本体ダウンロード自体は1回のダウンロードのためper-requestではペーシングしない。delta: `changes.csv`/`deletions.csv`の各文書取得2リクエスト（本文＋`.sha256`）ごとにペーシング | 実測2.49秒でアーカイブ本体（103,391,443バイト）をダウンロード（本環境のネットワーク条件によるもので移植可能な定数ではない）＋実測1.80秒で全27,930エントリをストリーム展開・走査（Pythonの`zstandard`ライブラリによる代理計測——本実装が実際に使うJava側`ZstdCompressorInputStream`/`TarArchiveInputStream`経路そのものの計測ではない点を明記する）＝I/O自体は数秒規模。実コーパス全件に対するバッチ挿入のDB書き込みスループットは本実装パスでは未計測（`GhsaSyncService`自身の表が同種の未計測ギャップに適用しているのと同じ規律） | 実測は変動が大きい：2026-08-25〜08-27の直近3日間は1日あたり2,012〜3,561件（高水準の期間）、2026-08-13〜08-18は1日あたり35〜254件（平穏な期間）——直近7日間平均は1,141.6件/日（いずれも2026-08-27、実際の`changes.csv`から実測）。`MAX_DOCUMENTS_PER_RUN`（2,000件、Siemensと同じ上限）により、バーストのある日は1回のdelta実行では処理しきれず、残りは次回実行に持ち越される（§7の設計） | 毎日04:15 UTC（`CveOrgScheduledSync`の03:30 UTC・`SiemensCsafScheduledSync`の03:45 UTC・`GhsaSyncService`の04:00 UTCといずれも重複しないようオフセット） | 7,200（`siemens_csaf`と同じ固定間隔の理論上限——実際のトラフィックはbaseline/delta実行時以外はこれよりはるかに低い） |

Siemens行は実装・実測済み。Red Hat行はフェーズ2で埋める。

**（2026-08-27追記・シニアレビューREVISE item 10）** baseline同期1回あたりのDB書き込み量を実測値で明記する: 実データ（27,930文書のアーカイブ）に対するbaseline同期で`csaf_products`行1,751,250件・`csaf_product_status`行4,245,640件（合計約600万INSERT）、`csaf_advisories.raw_json`への生JSON書き込みが約6.09GB。この数値は`RedHatCsafSyncService`自身のクラスjavadocにもミラーしてある。1,751,250件という`csaf_products`の行数は**REVISE item 3（未参照プロダクト行のフィルタリング）適用前**の実測値であり、item 3の実測では該当行の46.6%がどの`csaf_product_status`からも参照されていなかった——したがってitem 3適用後の実際の行数はこれより有意に少なくなる見込みだが、本改訂パスでは実アーカイブに対するbaseline再実行を行っておらず、再実測はしていない（見込みとして明記するに留め、実測値であるかのように書かない）。

### 5-6. バルクアーカイブ配布の確認を、per-document baseline同期の設計より先に行う

**（2026-08-27新設）** `CveOrgSyncService.syncBaseline()`が約38万件を安全に同期できている理由は、380,000回の個別GETではなく、**単一のZIPアーカイブ2本（archive、§1-4参照）をダウンロードするだけ**という点にある——これが実際の安全性の根拠であり、ペーシングはその上に乗る二次的な対策にすぎない。当初案のRed Hat向けbaseline設計（`changes.csv`だけでは全量を再現できない可能性があるためディレクトリ一覧を列挙し、確認済みの2,000件超それぞれに個別のペースドGETを行う）は、**そのN回の個別GETそのものがレート制限リスクの発生源**であり、ペーシングを足すだけでは解決しない構造的な問題を抱えている。

**要求事項として明記する**: 実装スパイクは、per-documentのbaseline GET設計に着手する前に、**各ベンダーが一括アーカイブ配布を行っているかどうかをまず確認する**こと。CSAF仕様自体がディレクトリベースのアーカイブ配布規約を定義している。Red Hatについては「年次の`.tar.zst`アーカイブ＋`archive_latest.txt`」を公開していると理解しているが、**これは本調査では未検証であり、事実として断定しない**（§2-3参照）——ライブスパイクでの確認が必須。一括アーカイブが存在する場合、baseline同期はそれを主経路としなければならない。per-document baseline GETは、一括アーカイブが存在しない場合の**文書化されたフォールバックとしてのみ**許可し、その場合は§5-5の表にフォールバック経路自身の呼び出し回数予算を明記すること。

**（2026-08-27追記・go/no-goレビューで確認済みに更新）** 上記の「未検証」は解消された——2026-08-27、`https://security.access.redhat.com/data/csaf/v2/advisories/archive_latest.txt`が実在し、そこが指す`csaf_advisories_2026-08-25.tar.zst`（圧縮約103,391,443バイト＝約103.4MB、27,930文書を格納）が実際にダウンロード可能であることをライブ確認した。`.sha256`サイドカーに加え、OpenPGP`.asc`署名も同じホストから配布されている（署名検証自体は§6の追記のとおりスコープ外——SHA-256検証は必須、OpenPGP検証は本フェーズでは見送る）。したがって`RedHatCsafSyncService`のbaseline同期はこの一括アーカイブをストリーム展開する経路を主経路として実装し、per-documentのbaseline GET（28,102文書×2リクエスト×500msペーシングで約7.75時間かかる見積もり）は採用しない——本節が要求していた「一括アーカイブが存在する場合はそれを主経路にする」という条件そのものを満たす形で実装済み。

### 5-7. 上限・バックオフ・User-Agent

**（2026-08-27新設）** 以下を同期サービスの必須要件として明記する:

- **1回の同期実行あたりの最大処理文書数の上限**を設ける（baseline・delta双方）。上限に達した場合は残りを次回実行に持ち越す（§7のチェックポイント設計と整合する）。
- **HTTP 429/403応答での中断・バックオフ**を実装する。以前のMaven Centralニアミス（§5冒頭）は単純なレート計算ミスではなく**ボット遮断**（能動的なブロッキング）だった——429/403は「もう少し待てば良い」ではなく「このアクセスパターンはブロック対象と判定された」というシグナルとして扱い、その同期実行を中断してバックオフする。
- **問い合わせ先を特定できるUser-Agentヘッダー**を設定する。既存の`externalApiRestClient`（`RestClientConfig.java:24`、`"vulncheck-server/0.1 (product identification)"`）や`CveOrgSyncService.download()`（`:276`、`"vulncheck-server/0.1 (cve.org sync)"`）は「ツール名/バージョン (用途)」という命名規約こそ踏襲しているが、**連絡先（メールアドレスやURL）を含んでいない**。CSAF同期サービスは既存経路より継続的・高頻度なバックグラウンドアクセスになる見込みが高く、ベンダー側が異常なアクセスパターンを検知した際に運営者へ連絡できる手段を持たせる価値がある——CSAF向けのUser-Agentはこの規約を踏襲しつつ連絡先を追加すべき、という拡張を推奨する。

---

## 6. 文書の完全性・取得先の安全性

**（2026-08-27新設）** 当初案はROLIEエントリがハッシュ・署名を持つことに触れながら、実際にはそれを一切検証していなかった。これは看過できない——§0-1原則2の通り、CSAFデータは`upsertAndGetId`を使う一次情報源経路として扱われ、既存の主要脆弱性データを上書きできる書き込み権限を持つ。この信頼レベルの高さゆえに、書き込む前の文書自体の真正性検証が重要になる。

**要求事項として明記する**:

- **ハッシュ検証**: ROLIEエントリが提供するSHA-256/512（および、Red Hatが個別文書に対して提供する`.sha256`サイドカーファイル）を、`upsertCsafDocument()`を呼ぶ前に必ず照合する。不一致の場合はその文書をupsertせず、スキップして同期失敗としてカウントする（§7のチェックポイント設計とも整合——失敗した文書のところでカーソルを進めない）。
- **SSRF形状のリスクへの対策**: 両同期サービスとも、リモート文書自身が持つURL（`provider-metadata.json`→フィード→エントリのリンク、Red Hatのメタデータがホストをまたいでリダイレクトする構成）を辿って次のfetch先を決定する構造になっている——これは実質的にSSRFの形をしたリスクである。以下を必須とする:
  - **HTTPSのみ**を許可する。
  - **ベンダーごとのホスト許可リスト**を設け、許可リスト外のホストへのfetchを拒否する。
  - **リダイレクト回数の上限**を設け、各ホップごとに再度ホスト許可リストと照合する（最初のリクエストだけ許可リストを通し、リダイレクト先を無条件に信用しない）。
  - **1文書あたりのレスポンスサイズ上限**を設ける。上限の無いボディをそのまま`raw_json`（TEXT列）に書き込むことは、OOMやディスク肥大化の攻撃面になる。

**（2026-08-27追記・go/no-goレビューでの決定: OpenPGP署名検証は本フェーズでは実装しない）** Red Hatはアーカイブ・個別文書ともに`.sha256`サイドカーに加えOpenPGP`.asc`署名も配布しており（`public_openpgp_keys`が`provider-metadata.json`自身に記載されている）、検討はした。**しかし本フェーズでは実装を見送る**——SHA-256検証は必須（上記の通り実装済み）だが、署名とアーカイブ本体は同一ホスト・同一TLSチャネルから配布されているため、署名検証が真に追加の防御価値を持つのは、Red Hatの公開鍵をこのチャネルとは別の経路（out-of-band）で取得し、コード側にピン留めした場合に限られる——それには鍵のローテーション方針（鍵が更新された場合にどう追従するか）という、それ自体が独立した設計判断を要する論点が伴う。したがってOpenPGP検証の要否・設計は本フェーズの範囲外とし、必要になった時点で改めて切り出して検討すべき、分離可能な将来の決定として扱う。

---

## 7. 同期の部分失敗・中断への対応

**（2026-08-27新設）** 当初案のスケッチは、同期実行の**最後に**（処理した全文書の中の最大タイムスタンプで）カーソルを1回だけ更新する形になっていた。この形状には2つの問題がある: (1) 実行途中の失敗で、それまでの進捗がすべて失われ、次回実行が全件を再取得し直す——これ自体がレート制限リスクの増幅要因になる。(2) baseline同期のように1回の実行が長時間かかる処理では、実行時間が失敗間隔より長い場合、この方式では**永遠に収束しない**可能性がある。

**要求事項として明記する**:

- **エントリはタイムスタンプ昇順で処理する**（§4-1・§4-2のスケッチに反映済み）。
- **カーソルは1件、または小さいバッチ単位で逐次コミットする**（実行の最後にまとめて1回更新するのではない）。
- **失敗した文書より先にカーソルを進めてはならない**——ある文書の処理（ハッシュ検証・パース・upsert）が失敗した場合、そこでカーソルの前進を止め、次回実行時に同じ文書から再試行する。
- **Red Hatの`deletions.csv`を同期設計に組み込む**（§4-2手順4）。これを消費しない限り、撤回・失効したアドバイザリーがローカルミラーに永久に残り、それらを根拠とした所見を返し続けるリスクがある。
- **`tracking_status`が`final`でない文書（`draft`/`interim`）は所見として一切表面化させない**——ローカルミラーへのupsert自体は許容する（将来`final`に更新された際の差分適用の土台として）が、§8の`find()`・アノテーション経路は`tracking_status = 'final'`の文書由来のデータのみを対象とする。

---

## 8. `VulnerabilitySource`実装の形状と検出結果の届け方

`CveOrgVulnerabilitySource`同様、CSAFアダプタも**ローカルミラーのみを照会し、アイテムごとのライブAPI呼び出しは行わない**——per-item追加コストがゼロという§0-1原則3の前提はこの設計に依存している。

### 8-1. 単一クラス（ベンダーIN句）にする（2026-08-27、当初案から変更）

**（2026-08-27改訂）** 当初案は「ベンダーごとの複数クラス（`SiemensCsafVulnerabilitySource`、`RedHatCsafVulnerabilitySource`）」を推奨していたが、これを撤回し、**単一の`CsafVulnerabilitySource`が`WHERE vendor IN (...)`で1回の候補クエリにまとめる**設計に変更する。理由:

1. §1-2で訂正した通り、Stage2は`VulnerabilitySource`を並行ではなく**逐次**に問い合わせる。ベンダーごとに別クラスを用意すると、Siemens用・Red Hat用の2回の逐次クエリがアイテムごとに積み上がる——3ベンダー目が加われば3回になる。単一クラスで`vendor IN ('siemens', 'redhat')`の1クエリにまとめれば、この逐次コストを1回に固定できる。
2. `product_tree`の**照合ロジック自体**（Red HatのRHELバリアント/コンポーネント名の扱い、Siemensのハードウェア/ファームウェアファミリーの扱い）がベンダーごとに異なりうるという当初案の懸念（§4末尾）自体は依然として正しい——ただしこれは「クラスを分けるか」ではなく「同じクラス内でベンダーごとの分岐（あるいは小さなヘルパー関数）を持つか」で吸収できる規模の違いであり、クラス自体を分けてまでレイテンシコストを2倍にするほどの理由にはならないと判断する。3ベンダー目（Cisco）が加わってなお1クラス内で吸収しきれない複雑さが実際に生まれた場合は、その時点でクラス分割を再検討すればよい——これも§0-1原則4（具体先行）の精神に合う判断である。

`find()`本体（`csaf_products`をvendor+trgm候補検索→`csaf_product_status`から該当CVE行を取得→バージョン・アーキテクチャの再検証）は`CveOrgVulnerabilitySource`とほぼ同型になる見込み。

### 8-2. 検出結果の届け方の全面設計変更——これが本節で最も重要な修正

**（2026-08-27全面改訂）** 当初案は、CSAFの結果を通常の競合`VulnFinding`として返し、Stage2の`byId.putIfAbsent(...)`（`Stage2VulnerabilityResearchService.java:66`、完全一致するID文字列でのみ重複排除、先着ソース勝ち）にそのまま乗せる設計だった。これは重大な欠陥を持っていた: **NVD/OSV/CVE.orgが既に同じCVEを見つけている一般的なケースでは、CSAFの発見（およびそのベンダー固有のfixedVersion/status）は`putIfAbsent`によって黙って捨てられる**。これはまさに§0(d)で本ドキュメント自身が強調した価値提案（適用可否ステータスの精密さであり、新規CVEカバレッジではない）が最も効くべき場面——つまり「そのCVE自体はもう見つかっている」場面——でその価値提案を無効化してしまう。当初案の§8末尾（旧番号）は「第一弾では`status`をStage2の共有コントラクトへ持ち出さない」という限定を書いていたが、この限定は問題の根を全く塞いでいなかった——競合`VulnFinding`として返す形状そのものが誤りだった。

**修正方針**: 同梱パッケージ機能の前例に**忠実に**倣う。`BundledComponentResearchService`（`:142-159`）は、そもそもStage2の`vulnerabilitySources`一覧に加わる`VulnerabilitySource`実装ではなく、**別建てのサービス**として、自身の`adjudicate()`結果を`vulnerabilityRepository.upsertAndGetId(...)`＋`jobItemVulnerabilityRepository.linkIfAbsentWithBundledComponent(...)`で直接永続化し、Stage2の`byId`競合には一切乗らない。その永続化経路は、`job_item_vulnerabilities`に**既存の`bundled_component_name`/`bundled_component_version`という2つのnullable列**（`V16__bundled_component_detection.sql:11-12`）を追加し、「どのCVE行に対する注記か」を保持する形を取っている（`bundledComponentName != null`が「同梱コンポーネント由来」を表すマーカー、`:4-10`のコメント参照）。

CSAFにも**同型**の列を追加する: `job_item_vulnerabilities`に`csaf_advisory_id`/`csaf_status`/`csaf_fixed_version`の3つのnullable列を追加し（マイグレーションはこのドキュメントの対象外——実装時に付番）、`JobItemVulnerabilityRepository`に`linkIfAbsentWithBundledComponent`（`JobItemVulnerabilityRepository.java:38-56`）と同型の新規オーバーロード（例: `linkIfAbsentWithCsafAnnotation`）を追加する。

**ただし、CSAFのケースにはbundled-componentの前例と異なる点が1つある**: bundled-component由来の発見は通常、製品自身とは別のCVE ID（別コンポーネントの脆弱性）なので、`job_item_vulnerabilities`行が既に存在しているケースをほぼ考えなくてよい。CSAFの場合はむしろ**逆**——「NVD/OSV/CVE.orgが既に同じCVE IDで行を作っている」が主要なケースである。したがって`linkIfAbsent`系（`INSERT ... ON CONFLICT (job_item_id, vulnerability_id) DO NOTHING`）をそのまま使うと、既存行がある限りCSAFの注記列は書き込まれない。設計として次の2経路を明確に分ける:

1. **既存行への注記（主要経路）**: そのCVE IDについて、CSAF以外のいずれかのソース（NVD/OSV/CVE.org、あるいはStage4）が既に`job_item_vulnerabilities`行を作っている場合——`CsafVulnerabilitySource`（あるいはStage2側の呼び出し元）は、Stage2の`byId`ループが完了し全ソースの発見が確定した**後**に、CSAFが持つ当該CVEのステータスをその既存行へ**UPDATE**する（`ON CONFLICT (job_item_id, vulnerability_id) DO UPDATE SET csaf_advisory_id = ..., csaf_status = ..., csaf_fixed_version = ...`という新規リポジトリメソッド）。挿入ではなく更新なので、「どのソースがdedupで勝ったか」に関係なく、CSAFのステータスを持つCVEには必ず注記が付く——これが本項目の核心的な修正点である。
2. **新規行としての作成（CSAF単独でしか見つからないCVE、稀なケース）**: どのソースもそのCVEを見つけていない場合、CSAFの発見自体が唯一の一次情報源になる。この場合は通常の`upsertAndGetId`＋新規オーバーロード（挿入時に`csaf_*`列も同時に埋める）で行を作る。**この経路は`status = fixed | known_affected`の場合にのみ許可する**——`known_not_affected`は次項(a)の制約により、既存行が無い限り一切表面化させない。

`Stage2VulnerabilityResearchService.research()`（`:58-82`）はこの2経路を扱うための小さいが実質的な変更を要する——CSAFソースの結果を他ソースと同じ`byId.putIfAbsent`扱いにせず、①非CSAFソースの発見を先に確定・永続化し、②その後CSAFの(cve_id, status, advisoryId, fixedVersion)群を②-a「`byId`に既にあるCVEへのUPDATE」と②-b「`byId`に無く、かつstatusがfixed/known_affectedのCVEのみ新規INSERT」に振り分ける、という2パス構成にする。具体的なデータの受け渡し方（`VulnFinding`を拡張するか、`SourceResult`とは別の戻り値をCSAF専用に設けるか）は実装時の判断でよい——アダプタ層の小さな実装判断であり、シニアレビューを要するフォークではない。

**2つの必須制約**:

**(a) `known_not_affected`はCVE個別の注記としてのみ表示し、アイテム全体の安全宣言として絶対に表示しない。かつ、該当アドバイザリーが実在しない場合は一切表示しない。** これは§0-1原則1の直接の適用である。UI表示文言は「このベンダーは自社製品が本CVEの影響を受けないと表明しています（アドバイザリーID）」のように、**その特定のCVEに紐づく**形にする。上記1の「既存行へのUPDATE」経路でのみこの状態が生まれ、既存行が無い場合（＝どのソースもそのCVEを見つけていない場合）は`known_not_affected`のデータを新規行として作らない（上記2の制約）——これにより「CSAFが何も言っていない」と「CSAFが明示的に無関係と言っている」が構造的に混同されない。

**(b) ベンダーが示すfixedVersionは典型的にNEVRA形式（例: `0:3.0.7-24.el9_2`）であり、上流のsemverではない。** これを`vulnerabilities.fixed_version`（`V7__fixed_version.sql:6`）や`JobController.highestFixedVersion`（`JobController.java:406-420`）の「推奨アップデート版」計算に混入させてはならない——これは同梱パッケージ機能のREVISEサイクルで既に一度修正された、同じ種類のバグである。`JobController.java:399-405`のコメントを引用する:

> REVISE item 3 (senior review 2026-08-26): a bundled-component finding (`bundledComponentName != null`) must never contribute here — its `fixedVersion` (if any) belongs to the bundled component itself (e.g. "7-Zip 26.03"), not to this row's own product, and rendering it as "推奨アップデート版" (the product's own recommended upgrade version) would tell the user to upgrade their actual product to a version of unrelated software.

CSAFの`csaf_fixed_version`列も同じ理由で`highestFixedVersion`から除外する——`vuln.bundledComponentName() != null`のガード（`JobController.java:409`）に並べて、`vuln.csafAdvisoryId() != null`のような同型のガードを追加する必要がある（新規行としてCSAF発見のみでCVE行を作る経路②-bの場合、その行の`VulnFinding.fixedVersion`自体もNEVRAで汚染しないよう、CSAF由来の新規行は`vulnerabilities.fixed_version`に常にNULLを書き込み、NEVRA値は`job_item_vulnerabilities.csaf_fixed_version`にのみ保持する）。

### 8-3. UI表示

`jobs/detail.html`の既存の同梱コンポーネント注記（`:110-111`、`th:if="${vuln.bundledComponentName != null}"`）の近くに、同型のCSAF注記ブロックを追加する。§8-2(a)の文言規則に従い、`csafStatus`の値に応じて表示文言を出し分ける（`fixed`/`known_affected`はアドバイザリーへのリンクとベンダー側fixedVersionの参考表示、`known_not_affected`は上記(a)の専用文言）。

### 8-4. 「見つからなかった」の扱い（§0-1原則1の適用、変更なし）

`find()`が空リストを返す状況——(a)当該ベンダーのフィードがまだ同期されていない、(b)同期済みだが該当製品が見つからない、(c)ベンダー自体が未対応（Ciscoフェーズ1時点）——は、いずれも既存の`SourceResult.success(空リスト)`契約にそのまま乗る。Stage2の集約は複数ソースの和集合であり、CSAFアダプタが空を返してもNVD/OSV/CVE.orgの発見を抑制しない。

---

## 9. テスト戦略

**（2026-08-27新設）** `CsafProductTreeWalker`・各`XxxCsafSyncService`・`CsafVulnerabilitySource`は、`MockRestServiceServer`で、**実際にキャプチャした本物のCSAF文書**（手で簡略化したものではない）をフィクスチャとして構築したテストで検証する。これは本プロジェクト自身が既に持つ規約であり、`CveOrgVulnerabilitySourceTest`のクラスjavadoc（`backend/src/test/java/com/vulncheck/app/service/vuln/CveOrgVulnerabilitySourceTest.java:23-27`）が明記している:

> Uses the real CVE-2025-7195 (operator-sdk) JSON shape captured live from cvelistV5 during 2026-08-23 testing — a genuine `lessThan`-ranged `affected[]` entry, not a hand-simplified fixture, so the version-range parsing is exercised against real-world shape.

同じ規律は`docs/spec/test-design-policy.md`のP1原則（「実在する製品・実際にリリースされたバージョンを使う。もっともらしく手で捏造した値は使わない」）とも一致する——CSVテストデータ向けの原則だが、根底の考え方（実データでしか見えないクセを、手で簡略化したデータは再現しない）はCSAFフィクスチャにもそのまま当てはまる。

**最低限必須とするフィクスチャ**（いずれも実際にキャプチャした文書から作る）:

1. **複数CVEを束ねるRed Hatアドバイザリー1件** — §3で再設計したCVEごとのステータス行列（同じ製品が異なるCVEに対して異なるステータスを持つケース）を演習する。
2. **`product_tree.relationships[]`でコンポーネント・イン・プラットフォームを表現する文書1件**（例: RHEL上のopenssl） — §4の共有`CsafProductTreeWalker`が`relationships[]`を正しく解決することを演習する。
3. **`known_not_affected`エントリを含む文書1件** — §8-2(a)のアノテーション表示制約（既存行がある場合にのみUPDATEで注記が付き、無い場合は新規行を作らない）を演習する。
4. **同期途中で失敗するケースのテスト1件** — §7の要求事項（失敗した文書より先にカーソルが進んでいないことをアサートする）を演習する。

---

## 10. フェーズ分けと明示的スコープ外

**フェーズ1（無認証・Siemensを先行、§4-4で決定）**: `csaf_advisories`/`csaf_products`/`csaf_product_status`/`csaf_sync_state`の4テーブルを新設。`SiemensCsafSyncService`＋共有`CsafProductTreeWalker`/`upsertCsafDocument`＋`CsafVulnerabilitySource`を実装・検証する。§9の4フィクスチャのうち、Siemens側で検証可能なものから着手する。

**（2026-08-27追記・フェーズ1の成果を一言で比較可能にする）** 本プロジェクトの他のバックログ項目（§11参照）と比較する際、フェーズ1が実際に何を届けるかを一言で言えば: **「既に見つかっているCVEに対して、2ベンダー分のベンダー表明適用可否ステータスを注記として表示する」**——新規CVEカバレッジの拡大ではない（§0(d)）。これを他の未実装バックログ項目自身の一言サマリと並べて比較できるよう、§11-1で改めて整理する。

**フェーズ2**: Red Hatを追加（§4-4の理由により2番目）。この時点で、共有`CsafProductTreeWalker`/`upsertCsafDocument`が実際に2ベンダー分で機能しているかを検証できる——2ベンダー目を迎えて初めて「本当に共有できる部分」の妥当性を再確認する、という§0-1原則4の運用そのものでもある。

**（2026-08-27追記・go/no-goレビューでの決定: `csaf/v2/vex/`はフェーズ2のスコープから明示的に除外する）** Red Hatは`csaf/v2/advisories/`（本フェーズが対象、27,930〜28,102件・圧縮約103.4MB）と`csaf/v2/vex/`の2ディレクトリを公開しているが、後者は実測で65,440文書・生JSON換算で約18.51GB、`csaf_products`への外挿見積もりで約2,460万行に達する——`advisories`単体の実装だけでもDB容量・行数が大きく増える中、`vex`はそれとは別に**このアプリのDBフットプリントをさらに約3倍近くに押し上げる規模**であり、`advisories`の実測ボリューム（本節・§5-5参照）とは一桁違う投資判断を要する。したがって`csaf/v2/vex/`はフェーズ2に含めず、**別途ユーザーの明示的な承認を得てから**着手する将来の独立したフェーズとして扱う——§4-3のCisco同様、「実装すれば動く」ことと「今のスコープに含めてよい」ことは別の判断であるという、本ドキュメントの既存の規律をそのまま適用したものである。

**Ciscoは明示的にスコープ外（本ドキュメントでは設計しない）**: §4-3の通りクレデンシャル・ゲートされた項目であり、着手にはユーザーの明示的な承認が要る。**§4-3で明記した通り、これは単なるトークン発行の可否確認ではなく、本アプリ初のシステムレベル認証情報のストレージ・所有権・ローテーションモデルそのものについての承認を要する**——着手する場合も「フェーズ1・2の実装パターンが検証できてから」が自然な順序。§5-3の通りCiscoのレート制限も未確認のまま。

**「N個目のベンダーに対応するための製品照合ロジックの汎用抽象化」は明示的にスコープ外**: §8-1で述べた通り、2ベンダーの段階で照合ロジックの共有インターフェースを先回りして設計しない（クラス自体は単一`CsafVulnerabilitySource`にまとめるが、これは§1-2のレイテンシ上の理由によるものであり、照合ロジックの抽象化とは別の判断である——両者を混同しないこと）。これは本プロジェクトの既存の流儀（`name-variance-refactoring-plan.md`）に合わせた、意図的な過剰一般化の回避である（§0-1原則4）。

---

## 11. 未決定事項（優先度順、シニアレビューでの判断を仰ぎたい点）

**（2026-08-27改訂）** 前版の未決定事項のうち、次の項目は本改訂で決定済みとなったため本節から除外した: どのベンダーを先に実装するか（§4-4でSiemens先行と決定）、レート制限機構の再利用可否（§5-4でExternalRegistryRateLimiter再利用と決定）、`VulnFinding`/`status`の扱い（§8-2で全面設計変更として決定）。以下が残る未決定事項である。

1. **相対優先順位: CSAF対応が他のバックログ項目と比べて着手に見合うか。** 本プロジェクトには`docs/spec/bundled-package-detection-plan.md`（同梱コンポーネント検知）・`docs/spec/batch-api-integration-plan.md`（コスト半減）という競合するバックログ項目が既に存在する。§0-1原則3の通り、CSAF対応は稼働時per-itemコストがゼロで既存の$5/1,000件キャップにそのまま収まる（同梱パッケージ機能が必要とした専用予算ゲーティングの論点がそもそも発生しない）という点で有利だが、**構築（エンジニアリング）コストは§0(c)の通りOSVミラーより高い**——この2つの評価軸をどう重み付けして他バックログと比較するかは、本ドキュメントでは判断せずシニアレビューに委ねる。**（2026-08-27追記）** 比較のため、各バックログ項目の届け出る成果を一言で並べる（優先順位そのものはここでは判断しない——比較可能にするだけ）:
   - 本ドキュメント（CSAFフェーズ1）: 既に見つかっているCVEに対して、2ベンダー分のベンダー表明適用可否ステータスを注記として表示する（§10参照）。
   - `bundled-package-detection-plan.md`: 製品自身のリリースノート/チェンジログにしか記載されない同梱コンポーネント（パッケージマネージャの依存関係としては見えないもの）の脆弱性を、LLMが抽出した(component, version)ペアをOSVで検証する形で検出する。1アイテムあたり約$0.02の追加コストを要し、専用予算ゲーティングが必要。
   - `batch-api-integration-plan.md`: Stage1 Tier2/Tier3・Stage4のClaude API呼び出しをAnthropic Batch APIに載せ替え、トークン単価を50%削減する。ただし最大24時間のレイテンシ床が生じ、現行の「1回のブロッキング呼び出しで完結する」実行モデルと構造的に相容れない。
2. **§2-3・§5に列挙した未検証事項は、実装着手前に短いライブスパイクで確認すべき。** 具体的には: (a) Red Hat/Siemensの総文書数・更新頻度の実測（§5-5のマージゲート表そのもの）、(b) Red Hatの一括アーカイブ配布の有無（§5-6）、(c) `product_tree`/`relationships[]`をJsonNode手動走査で実際にパースできるかの実機検証（§9のフィクスチャ作成そのもの）、(d) SiemensのROLIEフィード・Red Hatの文書取得エンドポイントそれぞれの実際のレート制限有無。これらはいずれも数時間規模のスパイクで確認可能な見込みだが、本ドキュメント自体はスパイクを実施していない。
3. **マイグレーション番号の衝突。** 本ドキュメント作成時点での最新マイグレーションは`V16__bundled_component_detection.sql`であり、次番は`V17`のはずである。しかし同日付の`docs/spec/infra-rollout-plan.md`（§2項目5）が、これも未実装の設計として`V17`をコスト実績永続化のために予約している。両ドキュメントとも「設計のみ・未実装」のため実害はないが、**実装着手時点でどちらが先行するかにより実際の番号が変わる**——本ドキュメントでは仮に上記スキーマ（§3、4テーブル）を次番（実装時点でのマイグレーション履歴を`ls backend/src/main/resources/db/migration/`で再確認した上での採番）として設計するに留める。`job_item_vulnerabilities`への3列追加（§8-2）も同様に別マイグレーションとして採番する。

---

## 12. この文書が参照する既存ドキュメント・コード

- `docs/spec/known-limitations.md`「未実装」節 — CSAFギャップが現在文書化されている箇所。本設計の直接の出発点。同ドキュメントの同梱パッケージ機能に関する新規エントリ（「オプトインしたが変更履歴が見つからなかった項目は『異常なし』と見分けがつかない」）は§0-1原則1の直接の先例。
- `backend/src/main/resources/templates/guide-integrations.html:62-67` — ユーザー向けに同じギャップを説明している箇所。フェーズ1実装後は更新が必要になる。
- `docs/spec/pipeline.md`「Stage2: 脆弱性調査」節 — `VulnerabilitySource`のfan-out・重複排除の現行仕様（本改訂で「並行」表記を「逐次」へ訂正済み）、およびGHSAがper-item経路から外された経緯（§5で引用）。
- `backend/src/main/java/com/vulncheck/app/service/Stage2VulnerabilityResearchService.java:18-26,58-82` — Stage2が全ソースを逐次問い合わせる設計であることの一次情報源（§1-2、本改訂での事実訂正の根拠）。
- `backend/src/main/resources/db/migration/V1__init.sql:16-23,96-102` — `user_secrets`（§4-3、システムレベル認証情報との対比）、`vendor_advisory_sources`の現行定義。
- `backend/src/main/resources/db/migration/V7__fixed_version.sql:6` — `vulnerabilities.fixed_version`列（§8-2(b)、CSAFのNEVRA値を混入させてはならない対象）。
- `backend/src/main/resources/db/migration/V8__cve_org.sql` — 本設計が踏襲するスキーマの直接のテンプレート。
- `backend/src/main/resources/db/migration/V9__trgm_query_performance.sql` — trgmクエリ形状を実装前に確認すべきという§3-1の教訓の直接の一次情報源。
- `backend/src/main/resources/db/migration/V16__bundled_component_detection.sql:1-17` — §8-2のアノテーション設計（`bundled_component_name`/`bundled_component_version`列）の直接のテンプレート。
- `backend/src/main/java/com/vulncheck/app/service/cveorg/CveOrgSyncService.java:29-40,57-58,272-278` — 同期サービスの実装テンプレート（baseline/delta、冪等upsert）、および§1-4・§5-6で引用したbaseline同期が一括アーカイブ2本のダウンロードで完結している実体。
- `backend/src/main/java/com/vulncheck/app/service/vuln/CveOrgVulnerabilitySource.java` — `VulnerabilitySource`実装の直接のテンプレート（自由文字列マッチング、候補検索→エントリ単位の再検証）。
- `backend/src/main/java/com/vulncheck/app/service/vuln/VulnerabilitySource.java`／`SourceResult.java`／`VulnFinding.java:13-19` — Stage2側の共有コントラクト。
- `backend/src/main/java/com/vulncheck/app/entity/ResearchJobItem.java:70,79` — `INCOMPLETE_REASON_SOURCES_FAILED`/`INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK`、§0-1原則1の直接の先例。
- `backend/src/main/java/com/vulncheck/app/repository/VulnerabilityRepository.java:26,52` — `upsertAndGetId`（一次情報源用）/`insertIfAbsentAndGetId`（低信頼LLM用）、§0-1原則2の直接の先例。
- `backend/src/main/java/com/vulncheck/app/repository/JobItemVulnerabilityRepository.java:32-56` — `linkIfAbsentWithBundledComponent`、§8-2で新設するCSAF版オーバーロードの直接のテンプレート。
- `backend/src/main/java/com/vulncheck/app/service/BundledComponentResearchService.java:142-159` — 同梱パッケージ機能が、Stage2の競合`VulnFinding`経路を使わず別建ての永続化経路を取っている実例。§8-2の設計変更の直接の先例。
- `backend/src/main/java/com/vulncheck/app/controller/JobController.java:399-420` — `highestFixedVersion`とそのbundled-component除外ガード（REVISE item 3, 2026-08-26）。§8-2(b)で引用した、同じ種類のバグの直接の先例。
- `backend/src/main/resources/templates/jobs/detail.html:110-111` — 同梱コンポーネント注記の表示テンプレート。§8-3のCSAF注記追加位置。
- `backend/src/main/java/com/vulncheck/app/service/registry/ExternalRegistryRateLimiter.java:11-60,88-123` — §5-4で再利用を決定したレート制限機構、および§5-1のフォールバック既定値の慣習の直接の先例。
- `backend/src/main/java/com/vulncheck/app/service/nvd/NvdRateLimiter.java:31-35` — §5-5でジャベドックへのミラーを要求した、実測値をコードに埋め込む慣習の直接の先例。
- `backend/src/main/java/com/vulncheck/app/config/RestClientConfig.java:16-26` — §5-7で引用した既存のUser-Agent命名規約（連絡先を含まない現状）。
- `backend/src/test/java/com/vulncheck/app/service/vuln/CveOrgVulnerabilitySourceTest.java:23-27` — §9で引用した「実際にキャプチャした本物のフィクスチャを使う」規約の直接の先例。
- `docs/spec/test-design-policy.md`「P1」原則 — §9で引用した、実データを使うべきという規律の別文脈での同型の先例。
- `docs/spec/name-variance-refactoring-plan.md:408-410` — 「一般化できない不規則ケースの表は最後の手段」という、本ドキュメント§0-1原則4・§8・§10の過剰一般化回避判断の先例。
- `docs/spec/bundled-package-detection-plan.md`（特に§3-3, §3-4, §4）／`docs/spec/batch-api-integration-plan.md` — §11-1で触れた、コスト構造の対比および優先順位判断の対象となる競合バックログ項目。
- `docs/spec/infra-rollout-plan.md`§2項目5 — §11-3で触れたマイグレーション番号（V17）の衝突元。
- `feedback_stop_for_credentials`メモリ — §4-3（Ciscoのクレデンシャル・ゲート、およびシステムレベル認証情報のストレージモデル承認）の直接の根拠。
- `project_vuln_research_server`メモリ「External registry rate limiting」／`project_ai_cost_target`メモリ（GHSA枯渇の経緯） — §5冒頭の教訓の一次情報源。
