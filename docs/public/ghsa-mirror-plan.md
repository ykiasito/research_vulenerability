# GHSAミラー構築 設計案（2026-08-27 設計のみ・未実装、シニアレビューREVISE反映版）

**実装状況の要約（2026-08-30追記、`known-limitations.md`と突き合わせ）**: タイトルの「設計のみ・未実装」は執筆当時のものであり、その後実装が進んでいる——`known-limitations.md`は2026-08-27時点で「GHSAミラー実装」として`GhsaVersionRange`のfail-closedルール等、実装済みの挙動を具体的に記述している。以下の本文（設計案そのもの）は当時の検討過程の記録として変更していない。

**本ドキュメントは設計のみ。実装コード・マイグレーション・設定変更は一切含まない。**

対象は、`GhsaVulnerabilitySource.java`が2026-08-25に意図的に`@Component`を外され（同クラスjavadoc`:28-38`）、Stage2のper-item経路から脱落したままになっているGHSA（GitHub Security Advisories）データを、`CveOrgSyncService`と同じ「バックグラウンド同期＋ローカルミラー＋ミラー専用照会の`VulnerabilitySource`」パターンで復帰させるかどうかの設計である。事前に実施された`Explore`エージェントによる実現可能性調査（GHSA/OSV.devのカバレッジ・鮮度・`github/advisory-database`の配布形態のライブ確認）の結果を土台とし、それに加えて本ドキュメント作成過程で判明した新たな設計上の論点（§1-2・§3-1）を組み込んでいる。調査結果そのものの再導出はしていない——引用は「実測・確認済み」「未検証」を区別して明記する。

**本改訂について**: シニアレビューがREVISE判定（23項目）を返し、(A) baseline/deltaは2アダプタではなく単一パーサに収束させる設計、(B) `OsvRateLimiter`が本設計より先に単独で出荷され、本GHSAミラー設計は`csaf-vendor-advisory-plan.md`・`batch-api-integration-plan.md`の後ろに優先順位づけされる、という2つの決定を下した。本改訂はこの2決定をそのまま反映し（再審議しない）、バージョン範囲評価・レート制限のスレッド安全性・完全性検証・削除/撤回の扱い等の実際の正確性上の欠陥を修正する。決定事項は§10-0に列挙する。

---

## 0. 結論を先に（埋没させない）

GHSAミラー構築を後押しする論拠は2つあり、**性質が異なる**。両方を並べて明示する。

**(a) カバレッジ論（既存の"OSVが代替している"という前提）は、狭く、第三者情報源に基づき、かつこのアプリの実情に照らすと当初より弱い。** 唯一見つかった定量情報は一件の第三者分析（dev.to、2026-04-10、再現可能なコード付き）であり、公式統計ではない（§2-1）。その分析自体は「OSV.devがGHSA-reviewedの内容をほぼ100%（99.95%）カバーしている」という強い数字を示すが、これは**外部のOSV.devサービス**についての数字であり、**このアプリ自身はOSV.devのローカルミラーを一切持っていない**（§1-2で確認済みの事実）。「OSVが既にカバーしているから重複を避ける」という論拠は、重複する対象（ローカルOSVミラー）がこのアプリに実在しない以上、当初想定より弱い。

**(b) 鮮度論（新規、調査で新たに判明）は、カバレッジ論とは独立に成立する。** `google/osv.dev`のGitHub Issueスレッド（`#4359`、`#4799`）は、GHSAエントリがOSV.dev側に24時間以上反映されない事例、メンテナ自身が「更新の反映に5日以上かかることがある」と認めているスレッドを報告している——OSV.devの取り込みインポーターは公称約15分周期にもかかわらず、である。これは§(a)のカバレッジ論（"最終的にはほぼ全部入っている"）とは別の軸の問題であり、**GHSA直接ミラーは「新規カバレッジの追加」ではなく「OSV.devの取り込み遅延を埋める鮮度ヘッジ」として位置づけるのが正確**である。

**(c) この2論拠は、当初計画（`docs/spec/name-variance-refactoring-plan.md:129,150`「GHSA（`github/advisory-database`をgit clone）……未着手・OSV後に再評価」「推奨順序……5. GHSA（2の後に要否再判定）」）が前提としていた「まずOSV.dev全件ミラーを構築し、それを踏まえてGHSAの要否を再判定する」というシーケンシングが、実際には一度も満たされなかった状態で評価している。** 同ドキュメントの推奨順序では「2. OSV.dev全件」がGHSAより先に来ていたが、この作業は着手されておらず（§1-2で確認済み、`osv_*`という名前のテーブル・マイグレーションはリポジトリ中に一件も存在しない）、OSVは今も§1-2の通りper-itemライブ呼び出しのままである。したがって「OSV後に再評価」という前提条件自体が成立しておらず、本ドキュメントは条件未成立のまま(a)(b)の論拠だけで判断せざるを得ない状態にある——これは判断を避けるための言い訳ではなく、正直に明記すべき前提の欠落である。

**(d) 対象はGHSAの`advisories/github-reviewed/`（人間レビュー済み、約28,529件）のみに絞る。** `advisories/unreviewed/`（約297,078件）はGitHub自身のREADMEによれば「NVDをそのまま転記したフィルタ済みパススルー」であり、このアプリの既存NVD/CVE.orgソースとほぼ完全に重複する。人間キュレーションという付加価値がある`github-reviewed`だけを対象にすることで、構築コストとストレージ量を抑えつつ、上記(a)(b)の論拠が実際に効く部分集合だけを取り込む。

**(e) 【シニアレビューで前面化】このドキュメント作成中に、OSV呼び出しにクライアント側のレート制限が一切無いという別の欠陥が発見され、本設計とは独立に、既に修正・出荷済みである。** 詳細は§1-2。`OsvRateLimiter.java`（2026-08-27追加、マージ済み）が`OsvVulnerabilitySource.queryPackage()`（`OsvVulnerabilitySource.java:72-73`）にペーシングを追加した——GHSA自身の60/hour枯渇（`GhsaRateLimiter.java`が既に対処済み）、crates.io/Maven Centralのニアミス（`ExternalRegistryRateLimiter.java`）に続く、このプロジェクト3件目の「クライアント側ペーシング欠如」インシデントの芽を、実際に事故化する前に摘んだ形になる。この単独の修正は、本GHSAミラー設計の主な価値提案（鮮度ヘッジ）の重要性そのものを相対的に下げる——OSV.devというデータの主経路が既にペーシング面で堅牢化された以上、GHSAミラーが埋める「取り込み遅延」という穴は残るが、その穴を埋める投資の優先度は下がる。この理由づけを§10-0の優先順位決定にそのまま反映する。

### 0-1. 本設計が踏襲する、このプロジェクトの既存の設計原則

以下はいずれも既にこのコードベース・関連設計ドキュメントの別箇所に前例がある原則を、GHSAミラー設計にそのまま適用したものである。

**1. 「見つからなかった」≠「安全と確認された」。** 既存の`ResearchJobItem.researchIncompleteReason`（`INCOMPLETE_REASON_SOURCES_FAILED`＝ソース側の障害で実際には何も確認できていない、`INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK`＝識別が弱くAI検証を意図的にスキップした、`ResearchJobItem.java:70,79`）、そして`docs/spec/csaf-vendor-advisory-plan.md`§0-1原則1・`docs/spec/bundled-package-detection-plan.md`§3-3が同じ規律をそれぞれの文脈で明文化している。**設計制約として明記する**: GHSAミラーがまだ同期されていない場合、同期済みデータの中に該当パッケージが見つからない場合、あるいは`ghsa_advisories.updated_at`が古く直近の更新を反映できていない場合、いずれも「このGHSAチェックの結果はGHSAアドバイザリーが存在しない」という意味で提示してはならない。既存の`VulnerabilitySource`契約（`VulnerabilitySource.java`のjavadoc、「本当に0件だった」と「このソースは適用されない」の両方を`SourceResult.success(空リスト)`として扱い`SourceResult.failure()`と区別する）に単に従う限り、構造的には自動的に満たされる——ただし同期が完全に失敗している状態（`ghsa_sync_state.baseline_loaded = false`）でGHSAソースが常に無言で空を返し続けることは、他ソースの発見を抑制しないという意味では安全だが、運用上のダッシュボード等でこの状態を可視化する価値はある（§9-0）。**この原則1は、§3-1のバージョン範囲評価アルゴリズムのfail-closedルールにもそのまま適用される**——評価不能なバージョンを「安全」側へフォールバックさせてはならない。

**2. 一次情報源としての信頼（低信頼のLLM経路とは区別する）。** GHSA-reviewedはGitHub自身がキュレーションする一次情報（CVE.org/NVDと同種の性質）であり、LLMの生成物ではない。**明記する**: GHSAアダプタは`CveOrgVulnerabilitySource`・`Stage2VulnerabilityResearchService`（`:71`）と同じ`VulnerabilityRepository.upsertAndGetId`（`VulnerabilityRepository.java:26`、既存行を上書き更新できる）経路を使う一次情報源として扱う。`insertIfAbsentAndGetId`（`:52`、低信頼LLM由来の発見専用、Stage4がこちらを使う`Stage4WebSearchResearchService.java:73-76`）は使わない。これは現行の`GhsaVulnerabilitySource.find()`（有効化されていた頃も含め）が既に`upsertAndGetId`経路のsourceの一つとして`Stage2VulnerabilityResearchService.research()`（`:71-74`）の共通upsertループに乗る設計だったこととも整合しており、ミラー化してもこの扱いを変える理由はない。

**3. コスト面: 同期サービス＋ローカルミラー方式は、per-item追加LLMコストがゼロ。** 既存のNVD/CVE.orgと同じ理由（`docs/spec/pipeline.md`のStage2記述）で、`GhsaVulnerabilitySource.find()`がローカルDBクエリのみで完結する設計である限り、稼働中の1アイテムあたりの追加コストはゼロである。`docs/spec/bundled-package-detection-plan.md`§4が明らかにした「1アイテムあたり約$0.02の追加コストで専用予算ゲーティングが必要」という状況とは構造的に異なるコストの物語であり、`docs/spec/csaf-vendor-advisory-plan.md`§0-1原則3が確立したのと同じ「既存の$5/1,000件ブレンドコスト目標の枠内にそのまま収まり、`JobCostBudgetService`の予算ゲーティングという論点自体が発生しない」という位置づけになる。

**4. 具体先行・過剰な一般化の回避。** `name-variance-refactoring-plan.md:408-410`の前例（「一般化できない不規則ケースの表」を最後の手段として扱い、実際には最後まで不要だったこと）、および`csaf-vendor-advisory-plan.md`§0-1原則4・§4の同様の判断を踏まえ、本設計は**CSAF対応（`csaf-vendor-advisory-plan.md`）と共有インフラを持たない**ことを明示的に決める。GHSAとCSAFは発行元（GitHub単一 vs. ベンダー複数）・データ形式（GitHub独自REST/OSVスキーマ準拠 vs. OASIS CSAF標準）・発見機構（GitHub REST API vs. ROLIE/ディレクトリ差分）のいずれも異なり、「アドバイザリーミラー」という抽象的な共通レイヤーを作れるだけの共通の形が実際には無い——CSAFドキュメントが自身のケースで確立した「OASIS/ISO標準そのもののパース処理は共有すべき、ベンダー固有ロジックは共有しない」という原則（同ドキュメント§0-1原則4改訂）とは異なり、GHSAとCSAFの間には共有すべき"標準のパース処理"に相当するものすら存在しない（GHSAはGitHub固有のREST/OSVスキーマ、CSAFはOASIS標準）。したがって両者を統合する汎用抽象化は検討した上で明示的に見送る。

以下、これら4原則を踏まえて詳細設計に入る。

---

## 1. 現状アーキテクチャの要約（コード引用）

### 1-1. `GhsaVulnerabilitySource`は登録解除済みで、Stage2の逐次ループから完全に外れている

`GhsaVulnerabilitySource.java:28-38`のクラスjavadocが理由を明記している——`GhsaRateLimiter`の65秒固定間隔がプロセス全体・呼び出しごとの制約であるため、Stage2のper-item fan-out（アイテム1件につき1呼び出し）に組み込むと1,000件ジョブで約65,000秒（約18時間）の純粋なスリープだけで「1,000件/3時間」のスループット目標を単独で突破する、という2026-08-25の実測に基づく判断。`docs/spec/pipeline.md:45`にも同じ経緯が記録されている。クラス自体と`GhsaRateLimiter`は削除されておらず、`GhsaVulnerabilitySourceTest.java`・`GhsaRateLimiterTest.java`で単体テストされ続けている——javadocは将来の**リポジトリ単位**（アイテム単位ではない）利用を想定して残していると明記する。本ドキュメントが提案する同期サービスは、この「リポジトリ単位」の想定そのものではないが、同じ「per-itemではない呼び出しパターンなら65秒間隔と両立する」という性質を、後述§5でバックグラウンド同期に転用する。

### 1-2. `OsvVulnerabilitySource`は現在もper-itemのライブ呼び出しである——ただしレート制限の欠如は本ドキュメント作成中に発見され、本設計とは独立に既に修正済み

`OsvVulnerabilitySource.java:21`は`@Component`が付いており、`Stage2VulnerabilityResearchService`にコンストラクタインジェクションされる`List<VulnerabilitySource> vulnerabilitySources`（`Stage2VulnerabilityResearchService.java:38`）に自動的に含まれる。`find()`（`:48-56`）→`queryPackage()`（`:72-`）は`api.osv.dev/v1/query`への**POSTを毎回、Stage2の逐次ループの中で同期的に実行する**——ローカルミラーは無く、`osv_*`という名前のテーブル・マイグレーションはリポジトリ中に一件も存在しない（`grep`で確認済み）。この事実自体は変わっていない——OSVは「ローカルに存在するデータ」ではなく「毎回叩きに行く外部サービス」のままであり、§0(a)で述べた「OSVが既にカバーしているから重複を避ける」論拠の弱さの技術的な根拠でもある。

**（2026-08-27、本ドキュメント作成中に発見・その後別途修正済み）** 当初の投資調査時点では`GhsaRateLimiter`/`NvdRateLimiter`/`ExternalRegistryRateLimiter`に相当するクラスがOSV呼び出し経路に存在せず、クライアント側ペーシングが一切無い状態だった。この欠陥は本ドキュメントのスコープ外の別課題として先に単独で修正され、**`OsvRateLimiter`（`OsvRateLimiter.java`、2026-08-27追加・マージ済み）としてこのコードベースに実在する**——`NvdRateLimiter`/`GhsaRateLimiter`と同じfixed-gap・no-burst設計で、`OsvVulnerabilitySource.queryPackage()`（`OsvVulnerabilitySource.java:72-73`、`osvRateLimiter.awaitTurn()`）に組み込まれている。`find()`（`:48-56`）は`queryPackage()`へ委譲するだけの薄いラッパーなので、ペーシング呼び出しをこの1メソッドだけに置けば`find()`経由の呼び出しも`BundledComponentResearchService`からの直接呼び出しも両方カバーされる（同ファイル`:68-70`のjavadocが明記）。§0(e)・§10-0の通り、これは本設計にとって「今後対応すべき未解決のギャップ」ではなく、「本設計の外で先に完了した、参照すべき実例」として扱う。

### 1-3. 直接のテンプレートは`CveOrgSyncService`（同期サービス構造）だが、**照合ロジックの直接のテンプレートはむしろNVD/OSVに近い**

`CveOrgSyncService.java`の`syncBaseline()`/`syncDelta()`二分構成、冪等な単一upsertパス、`@Scheduled`を`syncBaseline()`に付けない設計（クラスjavadoc`:29-40`）は、GHSA同期サービスがそのまま踏襲すべき型である——詳細は§4。

しかし**照合ロジック**（「あるアイテムがこのアドバイザリーの対象か」の判定）については、`CveOrgVulnerabilitySource`（自由文字列のpg_trgmファジー照合、CVE.orgが固定エコシステム分類を持たないことへの対応）を直接のテンプレートにすべきではない。GHSAは`GhsaVulnerabilitySource.java:47-57`の`ECOSYSTEM_MAP`が示す通り、**最初から固定のエコシステム taxonomy（npm/pypi/maven/go/nuget/rubygems/crates.io/packagist/hex/pub）を持つ**——これは`OsvVulnerabilitySource.java:29-39`の`ECOSYSTEM_MAP`と同じ構造的な性質であり、GHSAミラーの候補検索はCVE.orgのようなpg_trgmファジー一致ではなく、**(ecosystem, package_name正規化済み)の完全一致インデックス検索**で済む（§3-1【正規化】）——`NvdVulnerabilitySource`/`OsvVulnerabilitySource`の構造化キー照会に近い。§3のスキーマはこの点を反映する。

### 1-4. 【本ドキュメント作成過程で判明した新たな論点】ローカルミラー化は、これまでGitHub側に委ねていたバージョン範囲評価を、初めて自前で実装する必要を生む

`GhsaVulnerabilitySource.java:16-19`のクラスjavadocが明記する通り、現行実装は`affects=package@version`というクエリパラメータでGitHub側にバージョン範囲の該当判定そのものを委ねている（「GitHub resolves whether that exact version falls in the advisory's vulnerable range server-side」）。`extractPatchedVersion()`（`:120-132`）は表示用の参考情報（`patched_versions`文字列をそのまま見せる）を拾っているだけで、**該当判定ロジックそのものは`GhsaVulnerabilitySource`のコード上どこにも実装されていない**。

ローカルミラーに対する照会はGitHubのサーバーを経由しないため、この前提が丸ごと崩れる——**GHSAミラーは、`CveOrgVulnerabilitySource.isVersionAffected()`（`CveOrgVulnerabilitySource.java:131-160`）や`OsvVulnerabilitySource.extractFixedVersion()`（`OsvVulnerabilitySource.java:109-127`）に相当する、バージョン範囲評価ロジックを新規に実装する必要がある**、という点は投資判断上見過ごせない追加コストであり、調査時点では明示的に洗い出されていなかった論点として本節で明記する。

**【シニアレビューで指摘・訂正】「`VersionUtils.compare`で評価すればよい、軽微な作業」という当初の位置づけは不正確だった。** この既存の一次情報源自体が、単純な「fixed_versionが1本あればよい」という表現では不十分であることを既に示している——`CveOrgVulnerabilitySource.isVersionAffected()`（`CveOrgVulnerabilitySource.java:131-160`）は`lessThan`（`<`、排他的上限、`:137,152-153`）と`lessThanOrEqual`（`<=`、包括的上限、`:138,155-157`）を明示的に別のフィールドとして扱っている。もし本設計が`ghsa_affected_ranges`に上限を1列（例えば`fixed_version`のみ）でしか持たせず、OSVの`last_affected`イベント（`<=`相当）をその1列にそのまま押し込めば、**バージョンXちょうどが実際には脆弱であるにもかかわらず「安全」と誤判定される**——CveOrgVulnerabilitySourceが2列に分けている理由そのものであり、GHSAミラーがこの区別を欠けば、既存の社内実装が既に達成している精度をわざわざ下回ることになる。加えて`VersionUtils.compare`自体にも実務上無視できない既知の弱点がある（詳細は§3-1）。したがって本改訂では、範囲評価を「§3-1の正規化さえ済めば軽微」という位置づけから、**専用の評価コンポーネント（`GhsaVersionRange`）とfail-closedルールを持つ、明示的に設計すべき論点**へ格上げする。

---

## 2. GHSA/OSV.devのカバレッジ・鮮度をめぐる調査結果（未検証点を明記）

### 2-1. カバレッジ論（第三者調査、公式統計ではない）

唯一見つかった定量的なオーバーラップ情報は、方法論が公開されている第三者分析（dev.to、2026-04-10、再現可能なエンティティ解決コード付き）であり、**GitHub/OSV.dev公式の統計ではない**。GHSA（350,164件総数＝reviewed 28,618件＋unreviewed 297,078件）とOSV.dev（519,760件）の和集合のうちOSV.dev単独が312,098/312,250件（**99.95%**）をカバーしていたと報告している。差分152件は、GHSA-unreviewed専用でエコシステムタグも対象パッケージも持たないエントリ（Heartbleed/CVE-2014-0160、Shellshock/CVE-2014-6271、ProxyShellなど、パッケージ形状を持たないシステムレベルCVE）であり、パッケージ形状を持つGHSAコンテンツのOSV取り込み漏れではないと分析している。**この数字は一件の第三者研究に基づくものであり、公式・権威的な数字として扱わない**。

### 2-2. 鮮度論（新規、GHSAダイレクトミラーを支持する独立した論拠）

`google/osv.dev`のGitHub Issue（`#4359`、`#4799`）が、GHSAエントリがOSV.dev側に24時間以上未反映のまま残る事例、メンテナ自身の「一部の更新は反映に5日以上かかることがある」という発言スレッドを報告している——OSV.devの取り込みインポーターの公称サイクルは約15分だが、実際の反映はそれよりはるかに遅いケースがあると確認されている。§2-1のカバレッジ論とは独立に成立する論拠であり、GHSAダイレクトミラーの主な価値提案は「新規カバレッジ」ではなく「OSVの取り込み遅延を埋める鮮度ヘッジ」である。

### 2-3. `github/advisory-database`の確認事実

- `github`組織自身が所有・保守し、`github.com/advisories`を直接支えるリポジトリである。ただし「一括アクセス用にcloneせよ」という明示的な公式声明は見つかっていない（CVE.orgのリリースアセット文書のような明文化はない）。
- GitHub API `size`フィールドで3.46GBと確認済み——ただしこれは2022-02から継続的にコミットされてきたフルgit履歴を反映している可能性が高く、`--depth 1`浅いクローンのサイズを実際に測定したものではない。**浅いクローン時のサイズは未測定であり、実装スパイクでの実測が必要**。
- 更新はバッチではなくほぼリアルタイム——ライブのコミットログでアドバイザリー公開後数分以内に個別コミットが着地することを確認済み。
- GitHubのREST API（`GET /advisories`）は`published`/`updated`/`modified`の日付範囲フィルタとカーソルページネーション（`before`/`after`、最大100件/頁）を既にサポートしている——`GhsaVulnerabilitySource`が既に呼んでいるのと**同一のエンドポイント**であり、これがgitに依存しない「更新差分」機構として使える（§4）。**§7で改訂した設計（決定A）では、この一覧応答は変更検知シグナルとしてのみ使い、`ghsa_id`/`published_at`/`updated_at`だけを取り出す——応答本体の`vulnerabilities[].vulnerable_version_range`は解釈しない（理由は§3-1）。**
- `advisories/github-reviewed/`は約28,529ファイル——GitHubのGit Trees APIによる直接カウント、GitHub自身のブログ記載値・§2-1のdev.to調査値（28,618/28,419）と三者独立にほぼ一致。`advisories/unreviewed/`（約297,078ファイル）はGitHub自身のREADMEにより「フィルタ済みNVDパススルー」と明記されており、既存NVD/CVE.orgソースとの重複が大きいためスコープ外とする（§0(d)）。

### 2-4. 明示的に未検証の項目（本節、事実として扱わない・実装スパイクでの確認事項一覧）

- OSV.dev/GHSAの公式オーバーラップ率は存在しない（§2-1の一件のみ）。
- §2-3の浅いクローンサイズ実測。
- GHSAの`main`ブランチtarball/zipballの具体的な取得手段（`GET /repos/github/advisory-database/tarball/main`のようなAPIエンドポイントか、`codeload.github.com`直リンクか）は未検証——実装スパイクで確認する（§5-2）。
- **【シニアレビューで追加】`raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/<YYYY>/<MM>/<GHSA-ID>/<GHSA-ID>.json`というパス規約が、`published_at`から導出した年月と実際に一致し続けるか（アドバイザリー内容が後日更新されてもパスの年月は初回公開時点で固定されたままか）どうかは未検証——決定A（§3-1・§7）はこの規約が決定的であることに依存する。実装スパイクでの確認が必須、失敗した場合は§3-1に記載のフォールバック（2アダプタ構成）へ切り替える。**
- **【シニアレビューで追加】`raw.githubusercontent.com`が`api.github.com`とは別のレート制限バケットから配分されるかどうかは未検証——決定Aの成立条件の一つ（§3-1）。実装スパイクでの確認が必須。**
- **【シニアレビューで追加】baselineのtarball/zipball取得が実際に`api.github.com`配下のエンドポイント（例: `GET /repos/github/advisory-database/tarball/main`）を使う場合、これが本当に`/advisories`呼び出しと同じ60/hourバケットを共有するかどうかを、取得リクエストの前後で`x-ratelimit-remaining`レスポンスヘッダーを読んで確認する（§5-2・§6）。実装の結果`codeload.github.com`のような別ホストへ直接落ちることが判明した場合に限り「別バケットである」と明記してよい——確認前提で断定しない。**
- **【シニアレビューで追加】`GET /repos/github/advisory-database/commits/main`のレスポンスの`verification.verified`フィールドが実際に信頼できる値を返し続けるか（コミット署名の慣行が本当に成立しているか）は未検証——§6の完全性検証の前提。実装スパイクでの確認が必須。**
- **【シニアレビューで追加】REST API `/advisories`一覧応答が、撤回済み（withdrawn）アドバイザリーをそもそも表示するのか（withdrawnフラグ/タイムスタンプ付きで）、それとも撤回は将来の一覧から単に消えるだけで表現されないのかは未検証——§6-3のトゥームストーン設計に直接影響する。実装スパイクでの確認が必須。**
- REST API一覧応答の`modified`パラメータが受け付ける正確な演算子構文（例: `>=2026-01-01T00:00:00Z`のような前置演算子付き文字列か、範囲区切り構文か）は、本ドキュメント作成中に独立して再確認していない——`GhsaVulnerabilitySourceTest.java`のフィクスチャにもこの形式は含まれていない。§4-2で暫定的に`>=`前置の想定を書くが、**未検証としてそのまま扱い**、実装スパイクでの実測が必須。

---

## 3. 提案スキーマ: 新規6テーブル（`cve_org_*`パターンを踏襲しつつ、GHSAの構造化エコシステムとバージョン範囲の正確な意味論に合わせる）

**【シニアレビューで全面改訂】** 当初案は4テーブルで、バージョン範囲を`(introduced_version, fixed_version)`の2列だけで表現していた。これは(1)包括的上限（`<=`）と排他的上限（`<`）を区別できない、(2)OSVの`type`（SEMVER/ECOSYSTEM/GIT）を持たずGITレンジ（コミットSHA）を数値比較にかけてしまう、(3)`affected[].versions[]`による個別バージョン列挙（レンジとは独立な一致条件）を表現できない、(4)パッケージ名の表記ゆれを吸収できない、という4つの正確性上の欠陥を持っていた。以下のスキーマはこれらを修正する。

```sql
-- ghsa_advisories: 1 GHSA-reviewed アドバイザリーにつき1行。raw_jsonは再導出・デバッグ専用であり、
-- find()の実行時パスでは直接パースしない。§3-1(決定A)の通り、baseline/deltaいずれの経路で取得した
-- JSONも同一のOSVスキーマ形状(単一パーサ)であるため、raw_jsonの由来による形状の違いを気にする必要がない。
CREATE TABLE ghsa_advisories (
    ghsa_id         VARCHAR(20) PRIMARY KEY,   -- 例: GHSA-35jh-r3h4-6jhm
    cve_id          VARCHAR(30),               -- エイリアス。GHSA-reviewedでもCVE番号を持たない例がある
    summary         TEXT,
    details         TEXT,
    severity        VARCHAR(20),
    cvss_score      NUMERIC,
    withdrawn_at    TIMESTAMPTZ,               -- NOT NULL = 撤回済み。§6でfind()対象から除外する
    published_at    TIMESTAMPTZ,               -- deltaのraw.githubusercontent.comパス導出にも使う(§3-1)
    updated_at      TIMESTAMPTZ NOT NULL,      -- delta同期のカーソル source（GHSA自身の modified/updated_at）
    html_url        TEXT,
    raw_json        TEXT NOT NULL,             -- 再導出・デバッグ専用
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_ghsa_advisories_updated_at ON ghsa_advisories (updated_at);

-- ghsa_affected_packages: 1 (アドバイザリー, エコシステム, パッケージ) 組につき1行。
-- package_name_normalized: §3-1【正規化】の通り、per-ecosystemの正規化規則(PyPIはPEP 503
-- 正規化、NuGet/Mavenは大文字小文字を畳む、npmは小文字化)をingest時・照会時の両方に同じ
-- 共有関数で適用した値。生のpackage_nameは表示・デバッグ用にそのまま残す。
CREATE TABLE ghsa_affected_packages (
    id                       BIGSERIAL PRIMARY KEY,
    ghsa_id                  VARCHAR(20) NOT NULL REFERENCES ghsa_advisories(ghsa_id) ON DELETE CASCADE,
    ecosystem                VARCHAR(30) NOT NULL,   -- このアプリの内部エコシステムキー(npm/pypi/maven/...)
    package_name             TEXT NOT NULL,          -- 生の表記(表示用)
    package_name_normalized  TEXT NOT NULL,          -- 正規化済み(照会・重複排除用)
    UNIQUE (ghsa_id, ecosystem, package_name_normalized)
);
CREATE INDEX idx_ghsa_affected_packages_lookup ON ghsa_affected_packages (ecosystem, package_name_normalized);
CREATE INDEX idx_ghsa_affected_packages_advisory ON ghsa_affected_packages (ghsa_id);

-- ghsa_affected_versions: OSVの affected[].versions[]（レンジとは独立な、個別の脆弱バージョン列挙）。
-- find()はこのテーブルでの完全一致を、ghsa_affected_rangesのレンジ評価とは独立にチェックしなければ
-- ならない——レンジが評価不能(GIT型やパース不能なバージョン文字列でfail-closed、§3-1)でも、
-- この完全一致は成立しうる。
CREATE TABLE ghsa_affected_versions (
    affected_package_id  BIGINT NOT NULL REFERENCES ghsa_affected_packages(id) ON DELETE CASCADE,
    version               TEXT NOT NULL,
    PRIMARY KEY (affected_package_id, version)
);
CREATE INDEX idx_ghsa_affected_versions_package ON ghsa_affected_versions (affected_package_id);

-- ghsa_affected_ranges: 1つのaffected packageが持つ、互いに独立した脆弱バージョン範囲1本につき1行
-- (同じパッケージが「2.xで修正→再発→3.xで再修正」のような複数の非連続範囲を持つケースに対応)。
-- range_type: OSVスキーマのranges[].typeそのもの('SEMVER'|'ECOSYSTEM'|'GIT')。find()は'GIT'を
-- 評価対象から明示的に除外する(§3-1) — コミットSHAをVersionUtils.compareに渡しても意味のない
-- 辞書式比較になるだけのため。
-- introduced_version: NULLは「最初から脆弱」。OSVの introduced:"0" はNULLへ正規化する(§3-1)。
-- fixed_version: '<'相当(排他的上限、OSVのfixedイベント)。
-- last_affected_version: '<='相当(包括的上限、OSVのlast_affectedイベント)。
-- CveOrgVulnerabilitySource.isVersionAffected()(CveOrgVulnerabilitySource.java:131-160)が
-- lessThan/lessThanOrEqualを2列に分けているのと同じ区別を維持するため、両方同時にNULLでない
-- 状態は許容しない(CHECK)。1列だけに両方を押し込むと'<= X'を'fixed_version = X'として扱って
-- しまい、バージョンXちょうどが誤って「安全」と判定される(§1-4)。
CREATE TABLE ghsa_affected_ranges (
    id                     BIGSERIAL PRIMARY KEY,
    affected_package_id    BIGINT NOT NULL REFERENCES ghsa_affected_packages(id) ON DELETE CASCADE,
    range_type             VARCHAR(16) NOT NULL,
    introduced_version     TEXT,
    fixed_version          TEXT,
    last_affected_version  TEXT,
    CHECK (fixed_version IS NULL OR last_affected_version IS NULL)
);
CREATE INDEX idx_ghsa_affected_ranges_package ON ghsa_affected_ranges (affected_package_id);

-- ghsa_sync_state: cve_org_sync_state(V8)と同じ単一行パターン。
-- sync_in_progress: §6-2の排他制御(baseline/delta同時実行防止)用フラグ。
-- baseline_commit_sha: §6の完全性検証の通り、tarball取得時に解決したコミットSHA
-- (GET /repos/github/advisory-database/commits/main と突き合わせる)。
-- last_sync_error: §9-0の運用可視化で表示する直近の失敗理由(NULLなら直近実行は成功)。
CREATE TABLE ghsa_sync_state (
    id                    SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_loaded       BOOLEAN NOT NULL DEFAULT false,
    baseline_commit_sha   TEXT,
    sync_in_progress      BOOLEAN NOT NULL DEFAULT false,
    last_cursor           TIMESTAMPTZ,   -- 処理済みghsa_advisories.updated_atの最大値(deltaの`modified`フィルタの下限)
    last_synced_at        TIMESTAMPTZ,
    last_sync_error       TEXT,
    CHECK (id = 1)
);
INSERT INTO ghsa_sync_state (id) VALUES (1);

-- ghsa_sync_failures: §6-1「毒薬」エスケープハッチ用のdead-letter台帳。ghsa_advisoriesへの
-- FK制約は持たない——JSONパース自体が失敗した場合、ghsa_advisories側にまだ一度も行が
-- 作られていないことがあるため。
CREATE TABLE ghsa_sync_failures (
    ghsa_id               VARCHAR(20) PRIMARY KEY,
    consecutive_failures  INT NOT NULL DEFAULT 0,
    last_error            TEXT,
    last_attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dead_lettered_at      TIMESTAMPTZ
);
```

### 3-1. 【設計判断】単一パーサへの収束（決定A・シニアレビューにより確定）、バージョン範囲評価、イベント対応規則、パッケージ名正規化

#### (A) baseline/deltaを単一パーサへ収束させる — 2アダプタ構成は不採用（決定・確定済み）

当初案は「baseline用・delta用それぞれに薄いフォーマットアダプタ（`ingestFromRepoJson`/`ingestFromApiJson`）を用意する」という2アダプタ構成を提案していたが、**この案は不採用とし、単一パーサへ収束させる設計を決定として確定する**（未決定事項からこの改訂で決定済みへ移動、§10-0）。

理由（非対称性）: baseline（git tarball由来）は`advisories/github-reviewed/**/*.json`としてOSVスキーマそのもの（`affected[].ranges[].events[]`）を配布している。一方REST API `/advisories`（delta）は`vulnerabilities[].vulnerable_version_range`という、カンマ区切りの`>=`/`<`等の条件式を持つ単一文字列を返す——これをパースするには、**Group Aで整備するバージョン範囲評価ロジック（イベント対応規則、`range_type`判定等）とは別の、独立したもう一つのパーサ実装が必要になる**。これは単なるスタイルの好みではなく、実際に二重実装コストが発生し、かつbaselineパーサとdeltaパーサの間でロジックが将来ドリフトする実質的なリスクを生む。

**採用する設計**: GitHubのREST `/advisories`一覧応答は**変更検知シグナルとしてのみ**使う——`ghsa_id`＋`published_at`＋`updated_at`だけを取り出し、`vulnerabilities[]`の中身（バージョン範囲文字列を含む）は一切解釈しない。変更が検知された各アドバイザリーについて、その正規のOSVスキーマJSONを

```
https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/<YYYY>/<MM>/<GHSA-ID>/<GHSA-ID>.json
```

から個別に取得する（`<YYYY>`/`<MM>`は当該アドバイザリーの`published_at`から導出）。これをbaselineと**同一のパーサ**（`ingestOsvSchemaJson(JsonNode)`、単一実装）に通し、共有`upsertGhsaAdvisory(...)`（§4-3）へ渡す。結果として、範囲評価ロジックはこのアプリ全体で1箇所にしか存在せず、baseline/delta間のドリフトが構造的に起きない。

**この決定はライブスパイクでの2点の確認をゲートとする**（§2-4に列挙済み）——(i) `raw.githubusercontent.com`のパス規約（`<YYYY>/<MM>`が`published_at`から決定的に導出できること）、(ii) `raw.githubusercontent.com`が`api.github.com`とは別のレート制限バケットから配分されること。**このいずれかが実装スパイクで確認できなかった場合に限り**、REST APIの`vulnerable_version_range`文字列を直接解釈する2アダプタ構成へフォールバックする——ただしその場合、上記の「独立したもう一つのパーサ実装」という非対称コストがそのまま発生することを実装判断時に踏まえること。

#### (B) バージョン範囲評価: `GhsaVersionRange`とfail-closedルール

`VersionUtils`（`VersionUtils.java`）は自身のjavadoc（`:3-13`）で明確に「a general semver/rpm-version implementation」ではないと宣言している——「X.Y.Z」型の共通ケースに限定した、非数値セグメントは文字列比較にフォールバックする素朴な実装である。これには実務上無視できない2つの既知の弱点がある:

1. **`1.0.0-rc1`が`1.0.0`より大きいと判定される。** `compare()`（`VersionUtils.java:20-36`）はセグメントを`[._+\-]`で分割するため、`1.0.0-rc1`は`["1","0","0","rc1"]`、`1.0.0`は`["1","0","0"]`になる。4番目のセグメント比較で`"rc1"`（非数値、`isNumeric()`が全桁数値のみを数値扱いする、`:45-47`）と欠落側のデフォルト`"0"`が文字列比較（`compareSegment()`、`:38-43`）にかけられ、ASCII上`'r' > '0'`のため`1.0.0-rc1 > 1.0.0`という、意味論的に誤った結果になる。
2. **どちらかの引数が`null`だと`compare()`は`0`（等しい）を返す**（`VersionUtils.java:21-23`）。アイテムのバージョンが何らかの理由で`null`のまま範囲評価に渡ると、あらゆる`<=`判定を無条件で通過してしまう——これは「不明」ではなく「誤って一致」という、fail-openな挙動である。

**設計要求**: これらの弱点をfind()の実行時パスに素通しせず、専用の評価コンポーネント`GhsaVersionRange`を新設する。このコンポーネントは以下のfail-closedルールを持つ:

> アイテムのバージョン、または範囲の上限・下限のいずれかが「プレーンなドット区切り数値」（正規表現でいえば概ね`^\d+(\.\d+)*$`）としてパースできない場合、**何も所見を出さない（No finding）**。これを「対象外＝安全」として扱ってはならない——本ドキュメント自身の§0-1原則1「見つからなかった≠安全と確認された」がそのまま適用される。同様の理由で`range_type = 'GIT'`のレンジも評価対象から除外する（コミットSHAへの数値比較は無意味）。

**テスト要求**: `GhsaVersionRange`は表駆動（table-driven）の単体テストで、少なくとも上記2つの既知の弱点のケース（`1.0.0-rc1`を含む範囲、`null`アイテムバージョン）と、GITレンジのスキップ、正常系の`<`/`<=`/両端境界を含む形でカバーすること（§8）。

**既知の限界としての記録**: `VersionUtils`のプレリリース順序の弱点は、実装完了後に`docs/spec/known-limitations.md`へ実装担当者が追記すること（本ドキュメントではその追記自体は行わない——設計のみのスコープ）。

#### (C) OSVイベント列（`ranges[].events[]`）の解釈規則

OSVスキーマの`affected[].ranges[].events[]`は**順序付きリスト**であり、1レンジの中に複数の`introduced`/`fixed`（または`last_affected`）ペアと`limit`イベントが混在しうる。パーサは以下の規則に従う:

- `introduced`イベントで新しい範囲を開き、その次に現れる`fixed`または`last_affected`イベントで閉じる（1レンジ＝1つの連続した脆弱区間、これが`ghsa_affected_ranges`の1行に対応）。
- `limit`イベントは無視する（本設計の`GhsaVersionRange`評価には使わない情報）。
- `introduced: "0"`は「最初から脆弱」を意味するOSVの慣習であり、`ghsa_affected_ranges.introduced_version`は`NULL`へ正規化する。

#### (D) パッケージ名の正規化

**このミラー化自体が新たに生む照合上の失敗モード**を明記する: 現行のper-item実装はGitHub側の`affects=`パラメータでサーバーサイド解決しており、パッケージ名の表記ゆれ吸収もGitHubのインフラに委ねられていた。ローカルミラー化により、`(ecosystem, package_name)`の完全一致は**このアプリ自身の責務**になる。表記ゆれ（大文字小文字、PyPIのハイフン/アンダースコア/ドット揺れ等）を吸収しないと、正規化前は一致するはずのアイテムが一致しなくなる。

**要求事項**: per-ecosystemの共有正規化関数を、ingest時（`upsertGhsaAdvisory`が`ghsa_affected_packages.package_name_normalized`へ書き込む時）と照会時（`find()`が`identifiedProduct.getPackageName()`を正規化してからWHERE句に使う時）の**両方**で同じ実装に通す。規則: PyPIはPEP 503のパッケージ名正規化（英数字以外の連続を`-`へ畳んで小文字化）、NuGet/Mavenは大文字小文字の畳み込み、npmは小文字化。索引は`package_name_normalized`列に張る（§3のスキーマ）。`UNIQUE (ghsa_id, ecosystem, package_name_normalized)`により、同一アドバイザリー内で正規化後に衝突する重複行を防ぐ。

`vulnerabilities.source`（`V1__init.sql`、`VARCHAR(50)`、CHECK制約なし）に新しい値（例: `ghsa`——既存の`GhsaVulnerabilitySource.SOURCE`定数`ghsa`をそのまま流用可能、`database-schema.md:42`が既に運用上の値として記載済み）を追加すること自体にマイグレーションは不要。

---

## 4. 提案アーキテクチャ: `GhsaSyncService`

### 4-1. baseline: `main`ブランチのtarball/zipballを取得し、`advisories/github-reviewed/**/*.json`だけを歩く

```
1. GitHubのリポジトリtarball取得エンドポイント(具体的なURL形状は§2-3・§5-2の通り未検証、実装スパイクで確認)
   から github/advisory-database の main ブランチを1回のストリーミングダウンロードで取得
   (CveOrgSyncService.download()、:272-278 と同型 — 通常のexternalApiRestClientではなく、
   長時間ダウンロードに耐える別RestClient/URLConnectionを使う)。このリクエストが api.github.com
   を経由する場合は GhsaRateLimiter を通す(§5-2: 60/hourバジェットを/advisoriesと共有するため)。
   §6-2の通り、開始前に sync_in_progress を立てて排他制御する。
2. GET /repos/github/advisory-database/commits/main で解決したコミットSHAを記録候補として保持する
   (§6: 完全性検証、baseline_commit_shaへ書き込むのはコミット完了時)。
3. tar(またはzip)ストリームを順に読み、パスが advisories/github-reviewed/**/*.json に一致する
   エントリだけを処理する。advisories/unreviewed/** は §0(d) の理由で完全にスキップする。
4. 各エントリのJSON(OSVスキーマ)を ingestOsvSchemaJson() でパース → 共有 upsertGhsaAdvisory() を呼ぶ
   (§3-1の単一パーサ、失敗した個別文書は§6-1の毒薬エスケープハッチに従い記録してスキップする)。
5. 【完全性ゲート、シニアレビューで追加】取り込んだ件数が期待件数(§2-3実測: 約28,529件)の90%未満
   だった場合、ghsa_sync_state.baseline_loaded を true にせず、実行を失敗として扱い
   last_sync_error にその旨を記録して終了する(§6参照、§0-1原則1の直接の適用——
   打ち切られた/部分的なダウンロードが無条件に「読み込み完了」と自己申告し、find()が
   永久に「見つからない」を返し続けるという、この設計自身が警戒している失敗形を防ぐ)。
6. 90%以上取り込めていた場合のみ、ghsa_sync_state.baseline_loaded = true,
   baseline_commit_sha = 2.で保持したSHA, last_cursor = このバッチ内の最大updated_at,
   sync_in_progress = false をコミットする。
7. 【トゥームストーン、シニアレビューで追加】5.の完全性ゲートを満たした場合に限り、
   last_synced_at がこのbaseline実行の開始時刻より前のままの既存行を削除する(§6-3)——
   このbaseline実行で一度も触れられなかった行は、もはやgithub-reviewedに存在しないとみなす。
```

### 4-2. delta: REST API `/advisories`を変更検知シグナルとして使い、変更分だけを個別取得する（決定Aの直接の帰結、§3-1）

```
1. 開始前に sync_in_progress を確認・設定する(§6-2: baselineとの同時実行を防ぐ)。
2. GET https://api.github.com/advisories?type=reviewed&modified=>={ghsa_sync_state.last_cursor}
   &per_page=100&sort=updated&direction=asc
   — modified の演算子構文は未検証(§2-4)。カーソル比較は厳密な '>' ではなく '>=' を使う
   (理由: 秒粒度のタイムスタンプにstrict '>' を使うと、前回カーソルと同一秒に更新された
   アドバイザリーがページ/バッチ境界で silently 欠落しうる。再処理は upsertGhsaAdvisory() が
   冪等であるため無害——'>='による重複再処理の方が、'>'による静かな更新欠落より安全側)。
   — GhsaRateLimiter.awaitTurn() を1呼び出しごとに通す(§5)。
   — 【シニアレビューで追加】awaitTurn() 呼び出し直後に Thread.currentThread().isInterrupted()
     を確認する。GhsaRateLimiter.awaitTurn()(GhsaRateLimiter.java:54-64)はInterruptedExceptionを
     捕捉してThread.currentThread().interrupt()を呼ぶだけで、待機を完遂せずに戻る(:58-62)——
     この確認を怠ると、シャットダウン/割り込みが実行途中で発生した場合に残りのループが
     ペーシング無しで連続発火し、レートリミッタの意味が失われる。割り込みを検知したら
     last_cursorを進めずに実行を中断する。
3. 各アドバイザリーについて、published_at から <YYYY>/<MM> を導出し、
   https://raw.githubusercontent.com/.../github-reviewed/<YYYY>/<MM>/<GHSA-ID>/<GHSA-ID>.json
   から正規のOSVスキーマJSONを個別取得する(§3-1決定A)。
4. 各文書を updated_at 昇順で: baselineと同一の ingestOsvSchemaJson() でパース
   → 共有 upsertGhsaAdvisory() を呼ぶ(失敗時は§6-1の毒薬エスケープハッチ)。
5. 1件(または小さいバッチ)ごとに ghsa_sync_state.last_cursor をそのアドバイザリーのupdated_atまで
   前進させてコミット(§6: 失敗した文書より先にカーソルを進めない、ただし§6-1のN回連続失敗
   dead-letter後は例外的に前進する)。
6. 次ページが無くなるか、§5-4の1回あたり上限(5ページ)に達したら終了し、sync_in_progress を false へ戻す。
```

**この設計のポイント**: `/advisories`一覧応答自体が返す`vulnerabilities[]`（バージョン範囲文字列を含む完全な本文）は、決定A以降**意図的に使わない**——変更検知にのみ利用し、コンテンツは常にraw.githubusercontent.com経由の正規OSVスキーマJSONから取得する。これによりbaseline/delta間でパーサが1つに保たれる（§3-1）。

### 4-3. 共有`upsertGhsaAdvisory(...)`

`CveOrgSyncService.upsertCveJson()`と同型の冪等upsert: `ghsa_advisories`へupsert → 既存の`ghsa_affected_packages`/`ghsa_affected_versions`/`ghsa_affected_ranges`行を`ghsa_id`で削除してから作り直す（`CveOrgSyncService.upsertCveJson()`が`cveOrgAffectedProductRepository.deleteByCveId()`→再insertする方式、`:180-189`、と同型——アドバイザリーが更新されるたびに影響パッケージ集合自体が変わりうるため、部分更新ではなく作り直しの方が単純かつ安全）。成功したら`ghsa_sync_failures`の該当行（あれば）を削除する（§6-1: 過去に連続失敗していても、一度成功すればカウンタをリセットする）。

### 4-4. 【設計判断・決定】baselineはgit一括アーカイブ、deltaはREST変更検知＋raw.githubusercontent.com個別取得——この非対称な機構の理由

- **baselineに一括アーカイブを使う理由**: 28,529件個別のGETよりも、単一の一括アーカイブダウンロードの方が明らかに安全（§5-2、CVE.org/CSAFドキュメントが確立した「一括アーカイブ over per-documentフェッチ」原則そのもの）。REST APIにも一覧取得はあるが、28,529件を1日で全量取得しようとするとページネーション（100件/頁で約286頁）だけで相応の呼び出し回数になり、初回投入という一度きりの大量処理にはgit一括アーカイブの方が適する。
- **deltaにREST APIの変更検知＋個別取得を使う理由**: 1日あたり数十件規模のボリューム（§5-1）では、変更検知1〜2呼び出し＋数十件のraw.githubusercontent.com個別取得のどちらも、既存の`GhsaRateLimiter`（REST側）にそのまま乗る規模で完結する。§3-1(A)で述べた通り、この構成の核心的な利点は「gitへの依存を増やさない」ことよりもむしろ**「単一パーサに収束させられる」**ことにある——REST応答本体の`vulnerable_version_range`文字列パーサという、Group Aの範囲評価ロジックとは独立したもう一つの実装を避けられる。

---

## 5. レート制限（明示的に扱う——ユーザーからの強い要望に基づく必須節）

このプロジェクトには痛みを伴う実例が2つある——crates.io/Maven Centralのニアミス（`ExternalRegistryRateLimiter.java:19-30`）と、まさに本ドキュメントの対象であるGHSA自身の60req/hour枯渇（`GhsaVulnerabilitySource.java:28-38`、`GhsaRateLimiter.java:15-20`）。**新しい同期ループを書く前に、実装後ではなく実装前に想定される呼び出しボリューム（baseline・delta双方）に対して`呼び出し回数×間隔`の概算を必ず行う**という教訓を、そのまま本設計に適用する。

### 5-1. delta: 呼び出し回数×間隔の概算（具体的な数値で）

投資調査の実測: GHSA-reviewedの新規登録は平均で1日あたり約14〜20件、GitHub自身の「記録的な月」の投稿でも最大約50件/日。

- REST API `/advisories`の`per_page`上限は100件——**平均日は1ページ、バースト日でも1ページで収まる**（50 < 100）。この変更検知呼び出しに加え、決定A（§3-1）により変更のあった各アドバイザリーごとに`raw.githubusercontent.com`への個別取得が1回追加される——1日あたり14〜50件なので、`raw.githubusercontent.com`呼び出しも同程度の回数になる。
- 1日1回の`@Scheduled`実行、1回の同期で1〜2ページ（次ページが無ければ即終了）と仮定すると、**1日あたりの`/advisories`呼び出し回数は1〜2回**——`GhsaRateLimiter`の対象はこの`/advisories`呼び出しであり、`raw.githubusercontent.com`個別取得は別ホストのため別途扱う（§2-4: 別バケットかどうかは未検証、スパイクで確認）。
- `GhsaRateLimiter`の65秒固定間隔（`GhsaRateLimiter.java:26`）を1〜2回/日に適用しても、実際の待機時間はほぼゼロ（次の許可時刻が既に過去）——**65秒間隔という制約は、この呼び出しパターンに対して実質的に無視できるほど余裕がある**。1時間あたりで換算しても1〜2回/日は60req/hourの上限に対して桁違いに小さい。
- 仮に何らかの理由でdelta同期が1日に複数回（例えば手動リトライで）発火しても、1回あたり1〜2ページ・数回のREST呼び出しである限り、60req/hour上限に到達するには1時間に30回以上の実行が必要——通常運用ではまず起こり得ない。

**結論**: delta同期は`呼び出し回数×間隔`の概算上、明確に安全側に収まる。ただし§2-4の通り総アドバイザリー数の実測は未検証であり、この概算は「1日あたり14〜50件」という調査時点の観測値に基づく仮の数値である——実装直前に一度、直近1ヶ月程度の実際の増分件数を数え直してから確定させること。

### 5-2. baseline: 一括アーカイブ1〜2リクエスト vs. 個別文書28,529回GETの対比、および`api.github.com`バジェット共有の訂正

`CveOrgSyncService.syncBaseline()`が約38万件を安全に同期できている実体は、380,000回の個別GETではなく、**単一のZIPアーカイブのストリーミング取得だけ**という点にある（`CveOrgSyncService.java:29-40`）。GHSAのbaselineも同じ原則に従うべきで、`advisories/github-reviewed/`の約28,529件を個別文書GETの束（1リクエストあたり保守的に500ms〜1,000msのペーシングを仮定しても、28,529件だけで**4〜8時間規模**になる——これは本ドキュメントが想定するbaselineの安全性の根拠から明確に外れる）で取得するのではなく、**`main`ブランチのtarball/zipball1本のダウンロードで完結させる**。

**【シニアレビューで訂正】この一括ダウンロードが`api.github.com`配下のエンドポイント（例: `GET /repos/github/advisory-database/tarball/main`）を使う場合、それは`GhsaRateLimiter`の対象外の「別エンドポイント・別の制限体系」ではない。** GitHubの無認証プライマリレート制限（60req/hour）は**`api.github.com`全体に対してIP単位で適用される単一のバジェット**であり、`/advisories`呼び出しとは別のバジェットではない。したがって`api.github.com`からのtarball/アーカイブ取得は`/advisories`呼び出しと**同じ60/hourバケットを共有する**——本ドキュメントはこれを要求事項として明記する: **tarball/アーカイブ取得も`GhsaRateLimiter`を通す**。baselineは一度きり（または本番デプロイごとに一度）の操作であり、最大でも約65秒の待機が1回発生するだけなので、コストは無視できる。

**実装スパイクでの確認事項として追加**（§2-4）: tarball取得の直前・直後に`x-ratelimit-remaining`レスポンスヘッダーを読み、実際に`/advisories`呼び出しと同じバジェットを共有しているかどうかを確認すること。もし実装の結果`codeload.github.com`のような別ホストへ直接落ちることが判明した場合は、それは確認済みの別ホスト・別バジェットとして扱ってよい——ただし確認前提であり、断定しない。

### 5-3. 機構: 既存の`GhsaRateLimiter`を再利用する——ただし同期サービス専用の別インスタンスとして（【シニアレビューで訂正】単一bean共有は不採用）

CSAFドキュメント（`csaf-vendor-advisory-plan.md`§5-4）はSiemens/Red Hat向けに`ExternalRegistryRateLimiter`をベンダー別キーで再利用する設計を選んだが、これは「専用のレートリミッタが存在しなかった」ケースへの対応だった。GHSAには既に**このAPI専用に較正された**`GhsaRateLimiter`クラス（60req/hour、65秒固定間隔、`GhsaRateLimiter.java`）が存在し、`disabledForTesting()`ファクトリも含めて既に単体テスト済みである。同クラスのjavadoc（`:34-38`）は「将来の*リポジトリ単位*利用」を想定して残していると明記しているが、本設計の同期サービス呼び出しパターン（1日1〜2回のREST呼び出し、§5-1）は、その想定よりもさらに65秒間隔と相性が良い呼び出しパターンである。

**【シニアレビューで指摘・訂正】当初案は「既存の`GhsaRateLimiter`（Springの単一bean）をそのまま`@Autowired`で共有する」としていたが、これは計装（instrumentation）上の実害を持つ。** `ResearchJobProcessingService`は各`<source>RateLimiter.cumulativeWaitMillis()`をジョブ実行前後で差分し、その差分をそのジョブの待機時間としてログ出力する設計を既に採用している——`osvWaitBaselineMs`/`rateLimiterWaitDeltaMs`という命名でOSV向けに実装済みのこの実パターンを、そのまま新しいクラスに引用する（`ResearchJobProcessingService.java:126-127`のフィールド注入、`:162-164`のジョブ開始時ベースライン取得、`:205-206`の呼び出し、`:263-278`の`logJobTimings`が`rateLimiterWaitDeltaMs=[nvd={} ghsa={} osv={} registry={}]`という形でこの差分をログに出す）。`GhsaSyncService`は`@Scheduled`のバックグラウンドジョブであり、per-itemジョブ実行ではない——もし同じ`GhsaRateLimiter`インスタンスを`ResearchJobProcessingService`が読む対象と共有すると、バックグラウンド同期のスリープ時間が、たまたま同時に走っているユーザージョブの待機時間として誤って計上されうる。

**決定**: `GhsaSyncService`は`GhsaRateLimiter`と**同じ形状の、しかし別インスタンス**（同クラスの別bean、または同期サービス専用の新しいコンストラクタ引数付きインスタンス）を使う——`GhsaVulnerabilitySource`が将来リポジトリ単位で再有効化された場合に読まれる既存のSpring管理beanとは共有しない。この分離により、バックグラウンド同期のペーシングがper-itemジョブのログ計装（`ResearchJobProcessingService`のジョブ単位wait計測）と混線しないことを保証する。

### 5-4. 上限・バックオフ・User-Agent

**【シニアレビューで訂正】1回の同期実行あたりの最大処理ページ数上限を、当初案の20ページから5ページへ引き下げる。**

理由: `GhsaRateLimiter`は65秒固定間隔・バースト猶予なしのペーサーである。20ページ上限のままだと、delta同期が上限まで走った場合スケジューリングスレッドを約21.7分（20×65秒）ブロックする。`application.yml`は現時点で`spring.task.scheduling.pool.size`を一切設定しておらず（確認済み——grep該当なし）、Spring Bootのデフォルトプールサイズ1が`CveOrgScheduledSync.syncDailyDelta()`（`CveOrgScheduledSync.java`、`@Scheduled(cron = "0 30 3 * * *", zone = "UTC")`）と共有される。したがって長時間のGHSA同期がこのプールを占有すると、CVE.orgの日次スケジュール同期が実行されずに飢餓状態になる。

この問題への対処として2つの選択肢がある: (i) 1回あたりページ上限を大きく引き下げる、(ii) `spring.task.scheduling.pool.size`を明示的に増やす設定変更を本機能実装のスコープに含める。**本ドキュメントは(i)を選ぶ**——理由: §5-1の通り観測されているボリューム（1日14〜50件のGHSA-reviewed新規登録）は1ページ、バースト日でも1ページに収まる。**5ページ上限（5×65秒 ≈ 5.4分）でも観測ボリュームを十分カバーしながら**、共有インフラの設定変更（他の`@Scheduled`ジョブ全体に影響するプールサイズ）を伴わずに済む、より単純な変更で足りる。(ii)を選ぶ具体的な理由（例えば将来的に他の同期サービスも同時にページ上限へ張り付く見込みがある等）が実装時に判明しない限り、(i)を優先する。

- **1回の同期実行あたりの最大処理ページ数上限を5ページ（≈500件）とする。** §5-1の通り通常は1ページで完了する見込みだが、安全網として明記する。上限に達した場合は`last_cursor`をそこまで進めた上で残りを次回実行に持ち越す。
- **HTTP 429/403応答での中断・バックオフ**を実装する——GHSA自身の60/hour枯渇はまさにこのアプリが既に一度経験した失敗であり（§冒頭）、403を「もう少し待てば良い」ではなく「レート制限に達した」シグナルとして扱い、その同期実行を中断してバックオフする。
- **User-Agent**: `CveOrgSyncService.download()`（`:276`）が使う`"vulncheck-server/0.1 (cve.org sync)"`と同じ命名規約（ツール名/バージョン (用途)）を踏襲し、`"vulncheck-server/0.1 (ghsa sync)"`とする。CSAFドキュメント（§5-7）は「継続的・高頻度なバックグラウンドアクセス」を理由に連絡先アドレスの追加を推奨したが、GHSA deltaは1日1〜2回程度（§5-1）とCVE.orgの日次差分と同程度の頻度であり、CveOrgSyncServiceが連絡先無しの命名規約のまま問題なく運用できている前例に倣い、本ドキュメントでは連絡先追加を必須としない（CSAFのような近リアルタイム・高頻度アクセスとは呼び出しパターンが異なるため、同じ結論を機械的に流用しない）。

### 5-5. マージゲート: 呼び出し回数×間隔の実測表（【シニアレビューで追加】、実装前に埋め、実装スパイクの成果としてPRレビューで確認する）

`csaf-vendor-advisory-plan.md`§5-5が確立した、まさに同じ形の空表マージゲートをそのまま踏襲する。以下の表は空のまま本ドキュメントに残す——**実装スパイクでこの表を埋め、埋まった状態でシニアレビューを経てから同期サービスをマージすること**。この表が空のままである限り、GHSA同期サービスは実装完了とみなさない。あわせて、埋まった数値は同期サービス自身のクラスjavadocにもそのままミラーすること——このプロジェクトの既存の慣習（`NvdRateLimiter.java:33-35`のインターバル値のインラインコメント、`ExternalRegistryRateLimiter.java`のクラスjavadoc、そして特に`OsvRateLimiter.java`のクラスjavadoc「Throughput reasoning behind the 100ms figure」節、`:33-40`が実測に基づくスループット計算をそのままコードに埋め込んでいる、直近でマージされた実例）に倣う。

| 対象 | 実測baseline文書数 | 採用したペーシング間隔 | 概算所要時間（wall-clock） | delta文書数/日 | cron周期 | 最悪ケースreq/hour |
|---|---|---|---|---|---|---|
| GHSA (github-reviewed) | 34,768件（実測、2026-08-27、tarball全量ダウンロード＋走査。§2-3調査時点の約28,529件から実装時点までに増加——同一コーパスの異なる時点での実測値） | `GhsaRateLimiter`の65秒固定間隔は1回のbaseline実行あたり`api.github.com`呼び出し2回のみに適用（tarballリダイレクト解決＋`commits/main`）。tar.gz本体自体は`codeload.github.com`からペーシング無しでストリーミング取得（実測: 別ホスト・レート制限バケット無し） | 実測: 圧縮tarball 123.1MB、ダウンロード16.7秒＋gzip解凍＋走査12.7秒（無認証、本実装環境のネットワーク——ダウンロード時間は環境依存であり移植可能な定数ではない）＝DB書き込み前のI/Oだけで約30秒。34,768件全件に対するper-document upsertスループット（1アドバイザリーあたり4テーブルへの複数INSERT）は本実装パスでは実測していない（本番相当DBに対する実運用が必要）——`SiemensCsafSyncService`の§5-5表が自身の未実測外挿値に適用しているのと同じ規律で、外挿ギャップとして明記し偽の精度に丸めない | 実測: 直近24時間で36件変更（2026-08-27）——調査時点の§5-1見積もり（14〜50件/日）と整合、100件/頁のREST応答1頁に余裕で収まる | 毎日04:00 UTC（`CveOrgScheduledSync`の03:30 UTC、`SiemensCsafScheduledSync`の03:45 UTCとずらす） | 60（このアプリの`api.github.com`向け全呼び出しが共有する固定間隔の上限——baseline実行時を除く実トラフィックは1日1〜7回: 一覧頁1回＋raw.githubusercontent.com個別取得最大5回、後者はこのバジェットを消費しない） |

---

## 6. 部分失敗・完全性への対応

`CveOrgSyncService`の前例、および`csaf-vendor-advisory-plan.md`§6-7が確立した規律をそのまま適用する。

- **エントリは`updated_at`昇順で処理する**（§4-2のスケッチに反映済み）。
- **カーソルは1件、または小さいバッチ単位で逐次コミットする**（同期実行の最後に1回だけまとめて更新しない）。実行途中の失敗で、それまでの進捗が失われるのを防ぐ。
- **失敗した文書より先にカーソルを進めてはならない**——あるアドバイザリーの処理（パース・upsert）が失敗した場合、そこでカーソルの前進を止め、次回実行時に同じ文書から再試行する。**ただし§6-1のdead-letter条件（同一`ghsa_id`でN回連続失敗）を満たした場合は例外的にカーソルを前進させる**——この例外が無いと、1件の壊れた文書が同期全体を永久にブロックしうる。
- **カーソル比較は`>`ではなく`>=`を使う**（§4-2に反映済み）——秒粒度タイムスタンプでのstrict `>`は、ページ/バッチ境界で同一秒更新のアドバイザリーを静かに欠落させうる。冪等upsertにより再処理は無害であるため、`>=`による無害な重複再処理の方が安全側。
- **`withdrawn_at`が非NULLのアドバイザリー（撤回済み）は`ghsa_advisories`へのupsert自体は許容するが、`GhsaVulnerabilitySource`の`find()`・照合経路は対象から除外する**——CSAFの`tracking_status <> 'final'`除外（`csaf-vendor-advisory-plan.md`§7）と同じ精神で、撤回済みアドバイザリーを根拠に所見を返し続けないようにする。ただし§6-3の通り、REST API一覧応答が撤回フラグをそもそも表現するかどうかは未検証であり、このロジックだけでは撤回検出として不十分な可能性がある。
- **文書の完全性検証について【シニアレビューで訂正】**: 当初案は「検証機構が一切存在しない」と述べていたが不正確だった。正確には: **コミット単位の署名検証（commit signing verification）は、gitクローン経路を使う場合には（そのコミット履歴自体に）存在する**——しかしtarball/アーカイブダウンロードを選ぶと、この検証可能なコミット署名チェーンは構造的に失われる（tarballは特定コミットのスナップショットであり、署名済みコミットオブジェクトそのものではない）。本設計はtarball経路を選ぶため（§4-4）、この経路上の署名検証は放棄している——「無い」のではなく「（gitクローンなら使えたはずのものを）選択によって手放している」というのが正確な記述である。この不足を部分的に補うため、`ghsa_sync_state.baseline_commit_sha`（§3）へtarballが解決したコミットSHAを記録し、`GET /repos/github/advisory-database/commits/main`のレスポンスと突き合わせる——実装スパイクでは、同レスポンスの`verification.verified`フィールドが実際に信頼できる値を返し続けるか（署名慣行が本当に成立しているか）も確認すること（§2-4）。**CSAFのROLIEハッシュのような、個別文書ごとの暗号学的署名検証を要求する機構は、GHSA側にそもそも存在しないため、本ドキュメントはこれを要求事項に含めない**——存在しない要件を作り出さない、という原則をここでも維持する。
- **SSRF形状のリスク**: baseline/deltaいずれも取得先ホストは`api.github.com`／`raw.githubusercontent.com`／tarball配布ドメインに固定でき、CSAFのようにリモート文書自身が持つリンクを辿って次のfetch先を決定する構造ではない（CSAFの`provider-metadata.json`→フィード→エントリという間接参照の連鎖が無い）。したがってCSAFほど強いホスト許可リスト・リダイレクト制御は必須ではないが、念のため**GitHubのドメイン（`api.github.com`、`raw.githubusercontent.com`、tarball配布に使う実際のホスト、§2-4で確定後に明記）へのHTTPSのみ**を許可し、**1文書あたり・1アーカイブあたりのレスポンスサイズ上限**は設ける（`raw_json`列への無制限書き込みを防ぐ、tarball展開時のディスク肥大化を防ぐ）。

### 6-1. 「毒薬」エスケープハッチ: N回連続失敗でdead-letterへ

「失敗した文書より先にカーソルを進めない」という上記の既定動作は健全だが、それ自体に固有の失敗モードがある——1件のパース不能なアドバイザリーが永久にdelta同期をwedge（膠着）させうる。この間、`find()`はそのアドバイザリー以降のいかなる更新も反映できないまま、単に「成功（空リストまたは古いデータ）」を返し続ける。`CveOrgSyncService.upsertEntryIfCveJson()`（`CveOrgSyncService.java:127-145`）はこの理由から意図的に逆の方針を取っている——パース失敗（`:132-136`、`log.debug`して`false`を返す）もupsert失敗（`:141-145`、`log.warn`して`false`を返す）も、例外を外へ伝播させずログして次のエントリへスキップする。

**要求事項**: 同一`ghsa_id`で連続N回（N=3を推奨）処理に失敗した場合、そのアドバイザリーを`ghsa_sync_failures`（§3）へdead-letter登録する（`consecutive_failures`をインクリメント、`dead_lettered_at`をN回目到達時に設定）、WARNログを出す、§9-0の運用可視化経路で表示する、そしてカーソルをそのアドバイザリーの分だけ前進させて次回以降ブロックしないようにする。一度成功すれば（§4-3）`ghsa_sync_failures`の該当行を削除し、カウンタをリセットする。

### 6-2. 同時実行の防止: baseline/deltaの排他制御

baselineは手動トリガー（想定、`CveOrgSyncService`と同型）、deltaは`@Scheduled`であり、両者が同時に走る可能性は仮説ではなく現実的なシナリオである（例: 手動baseline実行中に日次deltaのcronが発火する）。両者が同時に`ghsa_affected_packages`/`ghsa_affected_ranges`へ削除→再作成を行うと、競合状態でデータが破損しうる。

**要求事項**: Postgresのアドバイザリーロック（`pg_advisory_lock`）、または`ghsa_sync_state.sync_in_progress`（§3）のような明示的な進行中フラグのいずれかで、baseline/delta双方の開始前にチェックし、既に他方が進行中であれば新しい実行を早期リターンさせる。

### 6-3. 削除・撤回のトゥームストーン

現行設計はどの経路でも行を削除しない。したがって、あるアドバイザリーが「reviewed」集合から外れた場合（unreviewedへ差し戻し、または撤回）、ローカルミラーは古い所見を永久に返し続けることになる。

**要求事項**: baseline実行は、`last_synced_at`が**今回のbaseline実行開始時刻より前のまま**残っている行（＝今回のbaselineパスで一度も触れられなかった行＝もはやsource側に存在しない）を刈り込む（§4-1ステップ7）。

**未検証事項として明記**（§2-4）: REST API `/advisories`一覧応答が撤回済みアドバイザリーをそもそも表現するのか（withdrawnフラグ/タイムスタンプ付きで一覧に表示され続けるのか）、それとも撤回は将来の一覧から単に消えるだけなのかは未検証。もし後者であれば、既存の「`withdrawn_at`のあるアドバイザリーをfind()から除外する」ロジック（§6本文）は、**ミラー化後に撤回されたアドバイザリー**に対しては一度も発火しない——`withdrawn_at`列自体がそのアドバイザリーについて更新される機会がREST一覧応答から到達しないため。この場合、上記のbaselineトゥームストーンだけが実質的な撤回検出手段になる（baseline実行の頻度でしか撤回が反映されない、という限界を伴う）。この限界は実装スパイクでの確認結果を踏まえて是正すべき事項として残す。

---

## 7. `VulnerabilitySource`実装の形状

`CveOrgVulnerabilitySource`同様、GHSAアダプタも**ローカルミラーのみを照会し、アイテムごとのライブAPI呼び出しは行わない**——per-item追加コストがゼロという§0-1原則3の前提はこの設計に依存する。

- クラス名は既存の`GhsaVulnerabilitySource`をそのまま再利用してよい（現行のper-item・ライブAPI実装を、ミラー照会実装に置き換える）——`SOURCE`定数（`ghsa`）・`ECOSYSTEM_MAP`（内部エコシステムキーへの正規化）はそのまま流用できる。**`GhsaRateLimiter`はfind()側からは削除する**（ミラー照会にレート制限は不要——`GhsaSyncService`側だけが対象、かつ§5-3の通り互いに別インスタンスを使う）。
- **候補検索クエリはJOINを1本にする**（【シニアレビューで追加】）: `ghsa_affected_packages`（(ecosystem, package_name_normalized)完全一致）→`ghsa_affected_ranges`／`ghsa_affected_versions`→`ghsa_advisories`を、候補ごとにN+1で逐次クエリするのではなく、単一のJOINクエリで取得する。`docs/spec/known-limitations.md`の「GHSA/OSVが『メタパッケージ』に対して大量の脆弱性を返すことがある」の記載通り、`symfony/symfony`のようなメタパッケージは1パッケージに対して大量のアドバイザリー行を持ちうる——**実装スパイクは`symfony/symfony`を最悪ケースの検証行として使い、このJOINクエリに対して`EXPLAIN ANALYZE`を実行し、想定通りのインデックス利用・許容範囲の実行時間であることを確認してからでなければマージしてはならない**。これは`csaf-vendor-advisory-plan.md`§3-1が自身のtrigramクエリに対して既に確立した「実装前に検証する」convention と同じものをGHSA側にも適用する。
- `find()`本体: `identifiedProduct.getEcosystem()`/`getPackageName()`（正規化後、§3-1【正規化】）を候補検索 → 各候補の`ghsa_affected_ranges`を`GhsaVersionRange`（§3-1【B】、fail-closed、`range_type = 'GIT'`は評価対象外）で評価、**それとは独立に`ghsa_affected_versions`での完全一致もチェックする**（§3）→ `ghsa_advisories`から本文（severity/summary/html_url等）を取得して`VulnFinding`を組み立てる。`withdrawn_at IS NOT NULL`の行は候補検索の時点でWHERE句により除外する（§6）。
- **識別子の選択: CVE-ID優先、GHSA-IDはフォールバックのみ【シニアレビューで追加】**: あるアドバイザリーが`cve_id`を持つ場合は必ずそれを`VulnFinding`のIDとして emit し、`cve_id`が無い場合にのみ`ghsa_id`を使う——これは現行の（無効化前の）`GhsaVulnerabilitySource.find()`が既に実装している挙動（`String id = cveId != null ? cveId : ghsaId;`、`GhsaVulnerabilitySource.java`の該当ロジック）をそのまま維持するものである。**理由**: `Stage2VulnerabilityResearchService.research()`はソース横断で発見結果を`byId.putIfAbsent(finding.cveOrGhsaId(), finding)`（`Stage2VulnerabilityResearchService.java:66`）という**ID文字列の完全一致**で重複排除している。もしGHSAミラーがCVE-IDを持つアドバイザリーに対してGHSA-IDをemitしてしまうと、NVD/OSV/CVE.orgが同じ脆弱性をCVE-IDでemitしている場合に重複排除されず、見かけ上の重複所見として表示される——`docs/spec/known-limitations.md`の「CVE/GHSAエイリアス統合なし」が既に記録している通り、このアプリには下流でこの重複を解消する仕組みが無い。**テスト要求**: CVE-ID優先のemissionをアサートする単体テストを追加する（§8）。
- 永続化経路は既存のStage2共通フロー（`VulnerabilityRepository.upsertAndGetId` → `JobItemVulnerabilityRepository.linkIfAbsent`、`Stage2VulnerabilityResearchService.java:71-74`）をそのまま使う——bundled-package/CSAFのような別建ての注記経路（`job_item_vulnerabilities`への追加列）は不要である。GHSAは単純に「このCVE/GHSA-IDが見つかったかどうか」の二値判定であり、CSAFの`known_not_affected`のような「ベンダーが明示的に無関係と表明する」第三の状態を持たない——`SourceResult.success(空リスト)`と`SourceResult.failure()`の既存の二分法で表現しきれる。
- **見つからなかった場合の扱い**（§0-1原則1）: `find()`が空リストを返す状況——(a)ミラーがまだ同期されていない、(b)同期済みだが該当パッケージが見つからない、(c)`identifiedProduct`にecosystem/packageNameが無い（CPEのみで識別されたアイテム）、(d)候補は見つかったがレンジ評価がfail-closedで棄権した（§3-1【B】）——は、いずれも既存の`SourceResult.success(空リスト)`契約にそのまま乗る。Stage2の集約は複数ソースの和集合であり、GHSAアダプタが空を返してもNVD/OSV/CVE.orgの発見を抑制しない。

---

## 8. テスト戦略

`GhsaSyncService`・(再実装後の)`GhsaVulnerabilitySource`は、`MockRestServiceServer`で、**実際にキャプチャした本物のGHSAアドバイザリーJSON**をフィクスチャとして構築したテストで検証する——`GhsaVulnerabilitySourceTest.java:20`が既に持つ規約（「Response shapes below mirror GitHub's real advisories API」）、および`CveOrgVulnerabilitySourceTest.java:23-27`・`docs/spec/test-design-policy.md`のP1原則（「実在する製品・実際にリリースされたバージョンを使う」）と同じ規律をそのまま踏襲する。

**最低限必須とするフィクスチャ**（いずれも実際にキャプチャした文書から作る。§3-1決定Aにより、baseline/delta双方とも同一のOSVスキーマパーサ`ingestOsvSchemaJson()`を通る点に注意——2つの異なるJSON形状ではなく、2つの異なる取得経路×同一パーサの組み合わせを検証する）:

1. **git baseline由来（OSVスキーマ）のアドバイザリー1件** — `ingestOsvSchemaJson()`が`affected[].ranges[].events[]`を正しく`ghsa_affected_ranges`（§3-1【C】のイベント対応規則、`introduced: "0"`→NULL正規化を含む）と`ghsa_affected_versions`（個別バージョン列挙）へ正規化することを演習する。
2. **REST変更検知→raw.githubusercontent.com個別取得由来のアドバイザリー1件** — 変更検知応答からghsa_id/published_at/updated_atのみを取り出し、`published_at`から`<YYYY>/<MM>`を導出してraw.githubusercontent.comのURLを組み立てられることを演習する（§2-4で未検証としたパス規約の実データ確認を兼ねる）。同一の`ingestOsvSchemaJson()`を通ることも合わせて確認する。
3. **同一アドバイザリーが両経路で二重に同期された場合の冪等性テスト1件** — baseline後にdeltaで同じ`ghsa_id`が再度流れてきても`ghsa_affected_packages`/`ghsa_affected_versions`/`ghsa_affected_ranges`が重複しないことをアサートする（§4-3の「削除してから作り直す」方式の検証）。
4. **`withdrawn_at`が設定されたアドバイザリーを含む文書1件** — §6の除外規則（find()側では出てこないが、ミラーへのupsert自体は行われる）を演習する。
5. **同期途中で失敗するケースのテスト1件** — §6の要求事項（失敗した文書より先にカーソルが進んでいないこと）に加え、§6-1のdead-letter要求事項（N回連続失敗後にカーソルが前進し、`ghsa_sync_failures`へ記録されること）をアサートする。
6. **`GhsaVersionRange`の表駆動単体テスト1件（§3-1【B】、新規）** — HTTPモック不要の純粋なロジックテスト。少なくとも: (i) `1.0.0-rc1`を含む範囲でのfail-closed動作、(ii) アイテムバージョンが`null`の場合のfail-closed動作、(iii) `range_type = 'GIT'`のレンジがスキップされること、(iv) `<`と`<=`それぞれの正常系境界値、(v) `ghsa_affected_versions`の完全一致がレンジ評価と独立に成立すること、をカバーする。
7. **CVE-ID優先emissionのテスト1件（§7、新規）** — `cve_id`を持つアドバイザリーが`ghsa_id`ではなく`cve_id`をemitすること、`cve_id`が無い場合にのみ`ghsa_id`にフォールバックすることをアサートする。
8. **既存の`GhsaVulnerabilitySourceTest.java`の4テスト**（CVE ID優先、GHSA IDフォールバック、未対応エコシステムでの早期リターン、パッケージ名欠如での早期リターン、HTTP失敗時の`SourceResult.failure()`）は、ミラー照会実装への置き換え後、対応するミラー版のテストケース（例: ローカルDBに候補が無い場合の早期リターン、DB例外時の`SourceResult.failure()`）に作り直す——なお「CVE ID優先」はそのまま項目7と統合してよい。

---

## 9. 観測性、フェーズ分けと明示的スコープ外

### 9-0. 運用可視化（【シニアレビューで追加】、§0-1原則1・§6-1から参照される）

`AdminController.java`は現時点でCVE.org/CPEディクショナリ向けに、**GETフォームで手動同期画面を表示し、POSTで同期を起動してその場の結果（件数）だけをflashメッセージとして表示する**という形の運用画面パターンを持つ（`AdminController.java:46-63`の`cveOrgForm()`/`cveOrgSyncDelta()`/`cveOrgSyncBaseline()`、対応する`admin/cve-org.html`テンプレート）。**ただしこのパターンは、同期状態（`baseline_loaded`や`last_synced_at`のような永続化された状態）をGET時に表示するものではない**——正確に言えば、既存の画面はPOSTの結果を都度表示するだけで、`cve_org_sync_state`のような永続状態そのものを画面に描画する既存の前例はまだ無い。したがって本ドキュメントの要求は「既存の前例をそのまま流用する」ではなく、**「既存のGETフォーム＋POST起動という画面構造を、GET時に永続状態を描画する形へ拡張する」**という位置づけで明記する。

**要求事項**: `/admin/ghsa`（同型の新規画面）のGETハンドラで、`ghsa_sync_state`の`baseline_loaded`/`last_synced_at`/`sync_in_progress`/`last_sync_error`と、`ghsa_sync_failures`の件数・一覧（§6-1のdead-letter状態）を表示する。§0-1原則1が既に指摘している通り、同期が未完了/失敗状態のままGHSAソースが無言で空を返し続けることは安全だが可視化の価値がある——本節はその可視化を具体化する。

### 9-1. フェーズ分け

**フェーズ1**: `ghsa_advisories`/`ghsa_affected_packages`/`ghsa_affected_versions`/`ghsa_affected_ranges`/`ghsa_sync_state`/`ghsa_sync_failures`の6テーブルを新設。`GhsaSyncService`（baseline + delta、§4）、単一パーサ`ingestOsvSchemaJson`＋共有`upsertGhsaAdvisory`、`GhsaVersionRange`評価コンポーネント（§3-1【B】）、（再実装後の）`GhsaVulnerabilitySource`をミラー照会専用に置き換える。§8の8フィクスチャを実装完了の条件とする。§5-5のマージゲート表、§7のJOINクエリ`EXPLAIN ANALYZE`確認も実装完了の必須条件に含む。

**フェーズ1が実際に届ける成果を一言で言えば**: 「GHSA-reviewed（約28,529件）をローカルミラー化し、Stage2にper-itemライブコストゼロで復帰させる——新規カバレッジの追加ではなく、主にOSV.devの取り込み遅延（24時間〜5日超、§2-2）を埋める鮮度ヘッジ（ただし§0(e)・§10-0の通り、OSV.dev自体は`OsvRateLimiter`によって既にペーシング面で堅牢化された後の状態での鮮度ヘッジであり、価値の相対的な大きさは当初より小さい）」。これは§10-0で他の未実装バックログ項目と比較する際の一言サマリとして使う。

**明示的にスコープ外**:
- CSAFミラー（`csaf-vendor-advisory-plan.md`）との共有インフラ化——§0-1原則4の通り、検討した上で見送る。
- 現行`GhsaVulnerabilitySource`が想定していた「リポジトリ単位」の将来利用（`GhsaVulnerabilitySource.java:35`）——本設計とは別の呼び出しパターンであり、本ドキュメントでは扱わない。
- CVE/GHSAエイリアス統合（`docs/spec/known-limitations.md`「CVE/GHSAエイリアス統合なし」に既に記載済みの既知の簡略化）——GHSAミラー導入後も、同じ実脆弱性を指すCVE-IDとGHSA-IDが両方見つかった場合は別々の行として残り続ける。本設計はこの簡略化を解消しない（§7のCVE-ID優先emissionは、この簡略化の影響範囲を最小化する緩和策であって、根本解消ではない）。
- OSV.dev自体のローカルミラー化（`name-variance-refactoring-plan.md:128,147`が既に推奨順序2位として記載している別バックログ項目）——本ドキュメントの対象外。§10-0で優先順位についての決定を記録する。

---

## 10. 未決定事項・決定済み事項

### 10-0. 決定済み事項（シニアレビューにより確定、2026-08-27）

**決定A: baseline/deltaは単一パーサへ収束させる（2アダプタ構成は不採用）。** §3-1(A)・§4-2・§4-4に詳細を反映済み。ライブスパイクで`raw.githubusercontent.com`のパス規約の決定性・レート制限バケットの分離のいずれかが確認できなかった場合に限り、2アダプタ構成へフォールバックする。

**決定B: 本GHSAミラー設計は`csaf-vendor-advisory-plan.md`・`batch-api-integration-plan.md`の両方より優先順位で劣後する。** 理由: 本設計の価値提案は「OSV.devの取り込み遅延を埋める鮮度ヘッジ」（§0(b)）だが、その主経路であるOSV.dev呼び出しは、本ドキュメント作成中に発見されたレート制限欠如という別の欠陥が既に単独で修正され（`OsvRateLimiter.java`、§0(e)・§1-2）、ペーシング面で堅牢化された状態にある。これは他の2バックログ項目それぞれの価値提案と比べて限界的な改善幅が小さい——`csaf-vendor-advisory-plan.md`は既知のCVEに対するベンダー適用可否ステータスという新しい情報次元を追加し、`batch-api-integration-plan.md`はStage1/Stage4のトークン単価を50%削減する。比較のため、各バックログ項目の届け出る成果を一言で並べる:

- 本ドキュメント（GHSAミラー フェーズ1）: GHSA-reviewed（約28,529件）をローカルミラー化し、Stage2にper-itemライブコストゼロで復帰させる——新規カバレッジではなく主にOSVの取り込み遅延を埋める鮮度ヘッジ。その主経路（OSV.dev）は既にOsvRateLimiterでペーシング面が堅牢化済み。
- `csaf-vendor-advisory-plan.md`: 既に見つかっているCVEに対して、ベンダー（Siemens/Red Hat）表明の適用可否ステータスを注記として表示する。
- `bundled-package-detection-plan.md`: 同梱コンポーネント（パッケージマネージャの依存関係としては見えないもの）の脆弱性を、LLM抽出(component, version)＋OSV/CPE照合で検出する。1アイテムあたり約$0.02の追加コストを要し、専用予算ゲーティングが必要。
- `batch-api-integration-plan.md`: Stage1 Tier2/Tier3・Stage4のClaude API呼び出しをAnthropic Batch APIに載せ替え、トークン単価を50%削減する。ただし最大24時間のレイテンシ床が生じる。
- （参考、未着手の別バックログ）OSV.dev全件ミラー: `name-variance-refactoring-plan.md`が推奨順序2位として既に記載しているが未着手。決定Bはこの項目とGHSAミラーとの厳密な着手順序（当初§0(c)が指摘した、満たされなかった前提条件）そのものには直接答えないが、GHSAミラーがcsaf/batch-apiの後ろに位置づけられたことで、この順序問題の実務上の重要性は下がっている。

### 10-1. 未決定事項（優先度順、実装スパイクまたはシニアレビューでの判断を仰ぐ点）

1. **§2-4に列挙した未検証事項は、実装着手前に短いライブスパイクで確認すべき。** 具体的には: (a)浅いクローン時の実サイズ、(b) `main`ブランチtarball/zipballの正確な取得エンドポイント形状、(c) `raw.githubusercontent.com`のパス規約の決定性（決定Aの成立条件）、(d) `raw.githubusercontent.com`が`api.github.com`と別のレート制限バケットかどうか（決定Aの成立条件）、(e) tarball取得が`/advisories`と同一バジェットを共有するかを`x-ratelimit-remaining`ヘッダーで確認（§5-2）、(f) `commits/main`応答の`verification.verified`フィールドの信頼性（§6）、(g) `/advisories`一覧応答が撤回済みアドバイザリーを表現するか（§6-3）、(h) `modified`パラメータの正確な演算子構文、(i) 直近1ヶ月の実際のGHSA-reviewed増分件数（§5-1の概算の裏取り）。
2. **OSV.dev全件ミラーとの厳密な着手順序。** §10-0決定Bにより優先度そのものは決着したが、「GHSAミラーとOSV.dev全件ミラーのどちらを先に着手すべきか」という当初§0(c)の狭い問いには本ドキュメントは直接答えない——両方ともcsaf/batch-apiより後回しになった以上、この2項目間の相対順序は当面の実務上の緊急性を持たない。着手時期が近づいた時点で改めて判断する。
3. **マイグレーション番号の衝突。** 本ドキュメント作成時点での最新マイグレーションは`V16__bundled_component_detection.sql`であり、`csaf-vendor-advisory-plan.md`§11項目3・`infra-rollout-plan.md`§2項目5がいずれも次番`V17`を（別々の用途で）予約済みである。本ドキュメントが提案する6テーブルも、実装着手時点でのマイグレーション履歴を`ls backend/src/main/resources/db/migration/`で再確認した上で採番する——3つの設計ドキュメントが同じ番号を仮予約している状態であり、実装順序が確定した時点でどれが実際に`V17`を取るかが決まる。§10-0決定Bにより本ドキュメントの実装順序はcsaf/batch-apiより後になる見込みが高く、実務上は`V17`を取るのはこのドキュメントではない可能性が高い。
4. **`GhsaVulnerabilitySource`の`find()`実装をこのドキュメントで置き換えることの影響範囲。** 現行の`GhsaVulnerabilitySourceTest.java`の4テストケースはper-itemライブAPI呼び出しを前提にしている（§8項目8）——これらを置き換えるか、ミラー実装と共存させる（ライブAPI版を別名クラスとして残すか）かは実装時の判断でよいが、既存テストの扱いを事前に明確にしておくべき事項として記す。

---

## 11. この文書が参照する既存ドキュメント・コード

- `backend/src/main/java/com/vulncheck/app/service/vuln/GhsaVulnerabilitySource.java:16-38,44-57,63-115,120-132` — 現行のper-itemライブ実装、`@Component`非登録の理由と将来のリポジトリ単位利用の想定、`ECOSYSTEM_MAP`、バージョン範囲評価をGitHubサーバー側に委ねている実装の事実、CVE-ID優先emissionの既存ロジック（§1-1・§1-4・§3-1・§7の直接の一次情報源）。
- `backend/src/main/java/com/vulncheck/app/service/vuln/GhsaRateLimiter.java:1-83` — 60req/hour・65秒固定間隔のレートリミッタ、`awaitTurn()`（`:54-64`）がInterruptedExceptionを捕捉するだけで待機を完遂せずに戻る挙動（`:58-62`、§4-2の割り込みチェック要求の根拠）、§5-3で別インスタンスとして再利用を決定した既存機構。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvVulnerabilitySource.java:21,44-56,58-73` — OSVが今もper-itemライブ呼び出しであること、`queryPackage()`（`:72-73`）に`OsvRateLimiter.awaitTurn()`が既に組み込まれていること（§1-2、§0(a)(e)の根拠）。
- `backend/src/main/java/com/vulncheck/app/service/vuln/OsvRateLimiter.java` — GHSAより先に単独出荷された、本ドキュメントが引用する具体的な前例。fixed-gap・no-burst設計、クラスjavadocにスループット実測根拠をインラインで埋め込む慣習（「Throughput reasoning behind the 100ms figure」節）、`disabledForTesting()`ファクトリ（§0(e)・§1-2・§5-5・§10-0の一次情報源）。
- `backend/src/main/java/com/vulncheck/app/service/vuln/VersionUtils.java:1-48` — `compare()`の実装（`:20-36`）、非semver・非rpm実装であるという自己申告（クラスjavadoc`:3-13`）、null引数で`0`を返す挙動（`:21-23`）、非数値セグメントの文字列比較フォールバック（`compareSegment()`、`:38-43`）——§3-1【B】の`GhsaVersionRange`fail-closedルールの直接の根拠。
- `backend/src/main/java/com/vulncheck/app/service/Stage2VulnerabilityResearchService.java:18-26,38,58-82` — Stage2の逐次実行・共通upsertループの一次情報源。特に`:66`の`byId.putIfAbsent(finding.cveOrGhsaId(), finding)`によるID完全一致重複排除——§7のCVE-ID優先emission要求の直接の根拠。
- `backend/src/main/java/com/vulncheck/app/service/ResearchJobProcessingService.java:126-127,162-164,205-206,263-278` — `osvWaitBaselineMs`/`rateLimiterWaitDeltaMs`という、ジョブ実行前後で`cumulativeWaitMillis()`を差分してログ出力する既存の計装パターン——§5-3で「同期サービスは別インスタンスの限定を使うべき」と判断した根拠。
- `backend/src/main/java/com/vulncheck/app/service/cveorg/CveOrgSyncService.java:29-40,57-58,99,127-145,148-190,272-278` — 同期サービスの実装テンプレート（baseline/delta、冪等upsert、bulk archive over per-document）。特に`upsertEntryIfCveJson()`（`:127-145`）の「失敗をログしてスキップする」方針——§6-1の毒薬エスケープハッチ要求の直接の根拠。
- `backend/src/main/java/com/vulncheck/app/service/cveorg/CveOrgScheduledSync.java` — 日次`@Scheduled`デルタ同期の前例（`cron = "0 30 3 * * *"`）。GHSAのdelta同期も同型で追加できる——§5-4のスケジューリングプール共有懸念の直接の根拠。
- `backend/src/main/resources/application.yml` — `spring.task.scheduling.pool.size`が設定されていないこと（確認済み、grep該当なし）——§5-4のデフォルトプールサイズ1・CveOrgScheduledSyncとの飢餓懸念の直接の根拠。
- `backend/src/main/java/com/vulncheck/app/service/vuln/CveOrgVulnerabilitySource.java:17-34,95-160` — 自由文字列ファジー照合の前例（§1-3で「GHSAの直接テンプレートではない」と判断した根拠）。特に`isVersionAffected()`（`:131-160`）の`lessThan`/`lessThanOrEqual`の2列分離（`:137-138,152-158`）——§1-4・§3の`fixed_version`/`last_affected_version`分離の直接の根拠。
- `backend/src/main/resources/db/migration/V8__cve_org.sql` — 本設計が踏襲するスキーマパターンの直接のテンプレート。
- `backend/src/main/resources/db/migration/V16__bundled_component_detection.sql` — マイグレーション番号衝突の起点（§10-1項目3）。
- `backend/src/main/java/com/vulncheck/app/repository/VulnerabilityRepository.java:26,52` — `upsertAndGetId`（一次情報源用）/`insertIfAbsentAndGetId`（低信頼LLM用）、§0-1原則2の直接の先例。
- `backend/src/main/java/com/vulncheck/app/repository/JobItemVulnerabilityRepository.java:15-30` — GHSAが使う既存の`linkIfAbsent`経路（bundled-package/CSAFのような追加注記列は不要と判断した根拠、§7）。
- `backend/src/main/java/com/vulncheck/app/entity/ResearchJobItem.java:70,79` — `INCOMPLETE_REASON_SOURCES_FAILED`/`INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK`、§0-1原則1の直接の先例。
- `backend/src/main/java/com/vulncheck/app/service/registry/ExternalRegistryRateLimiter.java:19-30,46-60` — レート制限の教訓の一次情報源、CSAFドキュメントとの比較対象（§5-3）。
- `backend/src/main/java/com/vulncheck/app/config/RestClientConfig.java:16-26` — User-Agent命名規約の既存前例（§5-4）。
- `backend/src/main/java/com/vulncheck/app/controller/AdminController.java:1-64` — CVE.org向け手動トリガー画面の前例（GETフォーム＋POST起動＋結果flash、`:46-63`）。§9-0の通り、永続状態表示の前例としてはまだ無いことを含めて正確に引用する。GHSAのbaseline/delta手動トリガー・状態表示も同型で追加できる。
- `backend/src/main/resources/templates/admin/cve-org.html` — 上記`AdminController`が使う既存画面テンプレート、§9-0の拡張対象の直接の一次情報源。
- `backend/src/test/java/com/vulncheck/app/service/vuln/GhsaVulnerabilitySourceTest.java` — 既存のGHSAテスト規約・フィクスチャ（§8）。
- `backend/src/test/java/com/vulncheck/app/service/vuln/CveOrgVulnerabilitySourceTest.java:23-27` — 「実際にキャプチャした本物のフィクスチャを使う」規約の直接の先例。
- `docs/spec/test-design-policy.md`「P1」原則 — §8で引用した実データ使用の規律。
- `docs/spec/pipeline.md:37,45,49` — Stage2の逐次実行仕様、GHSA無効化の経緯、CVE/GHSAエイリアス非統合の既知の簡略化。
- `docs/spec/known-limitations.md`「CVE/GHSAエイリアス統合なし」「GHSA/OSVが『メタパッケージ』に対して大量の脆弱性を返すことがある」「OSVの残り4エコシステム」 — 既存の既知の制約、本設計が解消しない範囲の確認。特にsymfony/symfonyメタパッケージの記載——§7のJOINクエリ`EXPLAIN ANALYZE`要求の最悪ケース選定の根拠。プレリリースバージョン順序の限界（§3-1【B】）は本ドキュメントでは追記せず、実装担当者が追記すべき事項として残す。
- `docs/spec/database-schema.md:42` — `vulnerabilities.source`の運用上の値（`ghsa`を含む）。
- `docs/spec/name-variance-refactoring-plan.md:120-150,408-410` — 「OSV.dev全件ミラーを先に、GHSAはその後に再評価」という当初計画の一次情報源（§0(c)の根拠）、および過剰な一般化回避の原則（§0-1原則4）。
- `docs/spec/csaf-vendor-advisory-plan.md`（§0-1、§3-1、§5、§5-5、§6-7、§9、§11） — 同時期に設計された類似バックログ項目。原則の適用パターン・レート制限節の形状・§5-5の空表マージゲート・EXPLAIN ANALYZEの事前検証convention・部分失敗対応の形状の直接のテンプレート、および§0-1原則4での比較対象。
- `docs/spec/bundled-package-detection-plan.md`（§3-3、§4） — コスト構造の対比対象（§0-1原則3）。
- `docs/spec/batch-api-integration-plan.md` — §10-0決定Bで触れた優先順位比較の対象となる競合バックログ項目。
- `docs/spec/infra-rollout-plan.md`§2項目5 — §10-1項目3で触れたマイグレーション番号（V17）の衝突元。
