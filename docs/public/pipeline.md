# 調査パイプライン

CSV1行（`ResearchJobItem`）ごとに、Stage1（製品識別）→Stage2（脆弱性調査）→（条件付き）Stage4（AI最終手段、現状は常にno-op、後述）の順で処理する。Stage3（`NvdKeywordVulnerabilitySource`）は閉域モードブランチではファイルごと物理削除済みで、本番経路にはそもそも存在しない（後述）。

## Stage1: 製品識別（`Stage1IdentificationService`）

3段階（Tier1〜3）で構成。**共通方針（現状）**: closed-mode B2（`docs/spec/closed-mode-plan.md`§9-2）でTier2/3のAI呼び出し経路自体が物理削除済みのため、実際に動作するのはTier1の静的照合と、元々「AI不在時の劣化動作」として用意されていた静的フォールバック規則のみ——静的・無料の経路だけで完結する（詳細はTier2/3節）。

### Tier1: 静的照合

1. **レジストリ照合**: `PackageRegistryLookup`の全10実装（crates.io/Go proxy/Hex/Maven Central/npm/NuGet/Packagist/pub.dev/PyPI/RubyGems）に対して、CSVの`product_name`をそのまま渡して照会。Maven Centralを除く9実装は、ローカルの`registry_package_mirror`テーブルを読むだけの`lookupViaMirror`のみで完結する——ライブHTTP照会だった`lookupLive`は閉域モードバックログ項目193（B3）で物理削除済み。Maven Centralだけは閉域モード用ミラー自体が存在しないため（同項目193〔B3〕§5-4）、`MavenCentralRegistryClient#lookup`は常に空を返す恒久的なno-op。各実装は`RegistryMatch(ecosystem, packageName, purl, confidence, exactVersionConfirmed)`を返し、バージョン実在確認済みならconfidence 0.95、未確認なら0.5（Maven Centralはどちらも返さない）。
2. **CPE辞書照合**: ローカルの `cpe_dictionary` テーブルに対して `pg_trgm` のあいまい一致（`product`/`title`列、閾値0.3、上位3件）。
   - **ローカルの`cpe_dictionary`ミラーのみを参照する**。以前はローカルに候補が1件もない場合、その場でNVD CPE APIに1回だけ生きた照会を行うフォールバック（`NvdCpeSyncService.syncKeywordSinglePage`）があったが、閉域モードバックログ項目273（B4）で物理削除済み（`Stage1IdentificationService`のクラスjavadoc参照）。ローカル辞書（フルシンクのみ、差分同期ではない）が完全に空振りの場合は、名前バリアント検索（`Stage1IdentificationService#findByNameVariants`、こちらもローカル`cpe_dictionary`のみ参照）にフォールバックする。`services.nvd.nist.gov`へのライブ呼び出しはこの経路のどこにも発生しない。
   - CPE一致のバージョンフィールドはあいまい一致の対象外（テキストのみ比較）。永続化時にはvendor:productだけを取り出し、**CSVの実バージョンに差し替えて**保存する（`Stage1IdentificationService.withItemVersion`）。辞書上の古いバージョン番号をそのまま見せると人間の目には不整合に見えるための対応。

レジストリ照合とCPE照合の両方が空振りの場合、Tier3の呼び出し自体は発生するが常に空振りに終わる（後述）ため、結果としてアイテムはUNIDENTIFIEDのままになる。どちらか一方でも候補があれば、Tier2の静的フォールバック規則（CPE候補が複数の場合のみ、後述）を経て確定する。

### Tier2: あいまい候補の判定（現在は常にno-op、静的フォールバック規則が常時適用）

CPE候補が2件以上ある場合のみ発火するが、`Stage1AiArbitration#disambiguateCpeCandidates`・`#verifyWeakRegistryMatchWithAi`・`#verifyVariantDerivedCpeMatchWithAi`はいずれも無条件で`Optional.empty()`を返す1行メソッドで、Claude（`claude-haiku-4-5`）呼び出し経路自体がclosed-mode B2（`docs/spec/closed-mode-plan.md`§9-2）で物理削除済み。かつてAPIキー未登録時の劣化動作としてのみ使われていた`Stage1IdentificationService`側の静的フォールバック規則が、現在は常に（キーの有無に関わらず）適用される:

- **CPE候補が2件以上**: 通常は先頭候補（ランキング1位）をそのまま採用する。ただし**relaxed-containmentパス由来の候補プールに限っては採用せず破棄する**（`degradeToFirstCpeCandidateUnlessRelaxedContainmentDerived`、senior review PR#51 REVISE item1 — Android Studioの`google:android`/`motorola:android`/`samsung:android`のような相乗り誤検出対策）。
- **CPE候補が1件のみ、かつ名前バリアント検索由来**（`variantDerived=true`）: この候補は常に破棄される（`resolveSingleCpeCandidate`）——「未検証の推測を信用するよりUNIDENTIFIEDのままにする」という設計判断。辞書への文字通りの一致（非バリアント由来）による単一候補は、この判定を経由せずそのまま採用される。
- **弱いレジストリマッチ**（`exactVersionConfirmed=false`）で確定CPEによる裏付けが無い場合: 実測ベースの静的ルール（REVISE item3、実データ19件の分析——itemの`vendor`フィールドが非空かつバージョン未確認なら14/14が誤り、`vendor`が空なら5/5が正しい）が適用される。`vendor`が非空かつバージョン未確認ならこの弱いマッチを棄却してCPE再照会にフォールバックし、それ以外（バージョン確認済み、または`vendor`が空）はそのまま採用する。

**非対称性に注意**: 名前バリアント由来のCPE候補は常に破棄される一方、弱いレジストリマッチは（vendor+未確認の組み合わせでない限り）そのまま信用される——どちらもAI判定が使えない状況で、Stage1IdentificationServiceの452行目・522行目・895行目付近が持つ、それぞれ独立に設計された静的ルールが決めている。

### Tier3: Web検索による名称解決（現在は常にno-op）

Tier1が完全に空振りだった場合のみ発火するが、`Stage1AiArbitration#tryTier3`は無条件で`Optional.empty()`を返す1行メソッドで、Claude+`web_search`呼び出し経路自体がclosed-mode B2（`docs/spec/closed-mode-plan.md`§9-2）で物理削除済み。以前は以下のような多段の名称解決を行っていたが、現在はいずれも実行されない——Tier1が完全空振りのアイテムは常にそのままUNIDENTIFIEDになる（参考: マーケットプレース表記ゆれ等を正式名称に解決する目的だった）。

1. （廃止）Claudeに`web_search`ツール（`web_search_20250305`、max_uses=3）を持たせ、正式なベンダー名・製品名を検索させる。
2. （廃止）併せて、有効なエコシステム一覧（`ecosystem_registries`テーブルから取得）をプロンプトに渡し、AIが確信を持てる場合は`ecosystem_candidates`（エコシステム名＋正確なパッケージ名の推測）も返させる。
3. （廃止）バックエンドは解決された正式名称でTier1を再照会し、`ecosystem_candidates`が返っていれば実際にそのレジストリへ照会して検証してから採用する。
4. （廃止）上記いずれも空振りの場合、AIが認識した配布チャネル識別子（`platform_hint`）を`research_job_items.identification_hint`/`hint_platform`/`hint_identifier`に保存する——この永続化コードパス自体は残っているが、これらの列に書き込む本番呼び出し元は現在1つも存在しない（バックログitem306: `hintPlatform`/`hintIdentifier`を実際にセットする呼び出し元が無い）。

`identification_hint`/`hint_platform`/`hint_identifier`列自体はDBスキーマ上に残っているが、上記の理由で常に空のままになる。

## Stage2: 脆弱性調査（`Stage2VulnerabilityResearchService`）

Stage1で `IdentifiedProduct` が得られたアイテムのみ対象。5つの `VulnerabilitySource`（NVD/OSV/GHSA/cve.org/CSAF）を**逐次（1つずつ、並行ではない）**問い合わせる。CSAFを除く4ソースの結果は**完全一致するID文字列でのみ**重複排除して統合する（CSAFの扱いは表の下で個別に説明）。並行化していないのは意図的な設計判断——全Stage2ソースはローカルDBへの問い合わせのみを行い、この毎アイテム経路にはライブAPI呼び出しもレートリミッタも存在しない（`NvdRateLimiter`/`GhsaRateLimiter`/`OsvSyncRateLimiter`のクラス自体は現存するが、いずれもミラーを埋める背景同期（`NvdCveSyncService`/`NvdCpeSyncService`/`GhsaSyncService`/`OsvSyncService`）側でのみ使われる。ライブOSV照会専用だった`OsvRateLimiter`のみ`OsvLiveQueryClient`ごと閉域モードバックログ項目264〔B4〕で物理削除済み）。加えて`ResearchJobProcessingService`が既にジョブ内の複数アイテムを並行処理しているため、ソースループそのものまで並行化した場合の追加のスループット向上は測定・検証されていない（詳細は`Stage2VulnerabilityResearchService`のクラスjavadoc参照）。

| ソース | 発火条件 | 特記事項 |
|---|---|---|
| `NvdVulnerabilitySource` | CPEが確定している場合のみ | ローカルの`nvd_cve_records`/`nvd_cve_cpe_match`ミラー（`NvdCveSyncService`）に対する照会のみ。`cpeName`（vendor:product + 実バージョン）のバージョン範囲判定は`CpeUtils#versionInRange`がこのアプリ側で行う（ライブのNVD CVE API経由の問い合わせ経路は閉域モードバックログ項目264〔B4〕で物理削除済み、設計上の意図的な逸脱、後述） |
| `OsvVulnerabilitySource` | ecosystem/packageNameが確定している場合のみ | ローカルの`osv_advisories`/`osv_affected_packages`/`osv_affected_ranges`/`osv_affected_versions`ミラー（`OsvSyncService`）に対する照会のみ、ライブAPI呼び出しなし。バージョン範囲判定は`OsvVersionRange`がこのアプリ側で行う（以前のOSV.devへの委任方式は廃止済み） |
| `GhsaVulnerabilitySource` | ecosystem/packageNameが確定している場合のみ | ローカルの`ghsa_advisories`/`ghsa_affected_packages`/`ghsa_affected_ranges`/`ghsa_affected_versions`ミラー（`GhsaSyncService`）に対する照会のみ、ライブAPI呼び出しなし。`cve_id`が付いているアドバイザリは常にそちらをfindingのIDとして採用し、GHSA単独（CVE未割当）のもののみ`ghsa_id`にフォールバックする |
| `CveOrgVulnerabilitySource` | 常時（識別済みアイテム全般） | ローカルの`cve_org_records`/`cve_org_affected_products`ミラー（`CveOrgSyncService`）に対する照会のみ、ライブAPI呼び出しなし。CSVの生の`product_name`/`vendor`テキストで照会し、Stage1と同じ`pg_trgm`あいまい一致方式を使う（レジストリ/CPEのエコシステムには乗らないため） |
| `CsafVulnerabilitySource` | 常時（識別済みアイテム全般、CSVの生の`vendor`/`productName`テキストが空でない場合） | ローカルの`csaf_products`/`csaf_product_status`ミラー（`SiemensCsafSyncService`/`RedHatCsafSyncService`）に対する照会のみ、ライブAPI呼び出しなし。**通常の完全一致ID重複排除からは意図的に除外**されている（詳細下記） |

**GHSA（`GhsaVulnerabilitySource`）は`@Component`登録済みで、上記の5ソースに含まれる**: 以前はGitHub未認証REST advisories（60req/hourしか許されない）へのper-item fan-outライブ問い合わせだったため、1,000件ジョブで約18時間のスリープが発生し「1,000件/3時間」目標を単独で突破してしまう問題があり、一時的に`@Component`を外して無効化していた。現在はその per-item ライブ問い合わせ実装自体を、`GhsaSyncService`が事前にバックグラウンド同期するローカルミラー参照方式に置き換えており、ライブAPI呼び出しが無くなったためレート制限の制約自体が解消し、通常のStage2フローに再度組み込まれている。`GhsaRateLimiter`は削除されていないが、現在は`GhsaSyncService`側の同期処理が使う別インスタンスであり、この`find()`呼び出し経路では使われない。詳細は`GhsaVulnerabilitySource`のクラスjavadoc参照。

**CSAF（`CsafVulnerabilitySource`）は他4ソースと異なる二経路の扱いを受ける**（`Stage2VulnerabilityResearchService`のクラスjavadoc参照）: (1) 経路1（通常ケース）——同じCVEを既に他のソースが見つけていれば、通常のID重複排除には加わらず、その既存行にCSAFのvendor status（`csaf_*`列）を注釈として追加するだけ。(2) 経路2（CSAF単独ヒット）——他のどのソースもそのCVEを見つけていない場合のみ、`fixed`/`known_affected`ステータスのときに限り新規findingとして挿入する。`known_not_affected`/`under_investigation`しかなく、かつ注釈対象の既存行も無い場合は、新規findingとしては出さず何もしない（安全側の判定を新規に主張しないため）。

**設計上の意図的な逸脱（現在は解消済み）**: 当初案ではエコシステムごとの専用バージョン比較ロジック（semver/PEP440/Maven/Go）を実装する想定だったが、各ソースがまだライブAPIを叩いていた頃は、各APIが持つサーバーサイドのバージョン範囲解決に委任する方式にしていた（自前の多エコシステム比較器より正確と判断したため）。その後NVD/OSV/GHSAはいずれもミラーベースの実装へ移行しており（NVDはライブAPI経由の問い合わせ経路自体が閉域モードバックログ項目264〔B4〕で物理削除済み）、現在はどのソースも外部APIへ委任せず、このアプリ自身がバージョン範囲を判定している——`CpeUtils#versionInRange`（NVD）・`OsvVersionRange`（OSV/GHSA）に加え、`CveOrgVulnerabilitySource`は`VersionUtils#compare`、`CsafVulnerabilitySource`は`versionMatches`（Siemens専用分岐）および`passesRedHatFixedVersionGate`（Red Hat専用のRPM EVRゲート、ステータス行ごとに適用）で、ベンダーごとに自前判定する。

**既知の簡略化**: CVEとGHSAが同一の実際の脆弱性を指していても、ID文字列が異なれば別々の行として残る（エイリアス解決は未実装）。

## Stage4: AI最終手段調査（`Stage4WebSearchResearchService`、現在は常にno-op）

**呼び出し条件自体は変わっていない**（`ResearchJobProcessingService`が判定、以下のいずれかの場合のみ`#research`を呼ぶ。それ以外＝Stage2が1件でも見つけた場合は呼ばない）:

1. Stage1で識別済み・かつStage2が0件だった場合 → `ecosystem`/`packageName`を渡して呼び出す
2. Stage1で識別自体ができなかった（UNIDENTIFIED）場合で、`item.getHintIdentifier() != null`のとき → `hint_platform`/`hint_identifier`を渡して呼び出す（ただしTier3が常にno-opのため`hintIdentifier`は実際には設定されず、この条件は現状到達不能——上記Tier3節参照）

**しかし呼び出された`#research`自体が無条件のno-op**: `Stage4WebSearchResearchService#research`は、closed-mode B2（`docs/spec/closed-mode-plan.md`§9-2でClaude+`web_search`呼び出し経路自体が物理削除済み）により、渡された引数の内容に関わらず常に`new Stage4ResearchResult(0, ResearchJobItem.INCOMPLETE_REASON_AI_NOT_AVAILABLE)`を返す1行の実装。以前あった、Claudeの`web_search`ツール（max_uses=2）によるWeb検索・CVE/GHSA形式識別子のグローバルユニークキー利用・自由記述識別子の`llm:{パッケージ名}:{識別子}`スコープ方式は、いずれも呼び出されるコード自体が現在は存在しない。呼び出し条件を満たしたアイテムには`INCOMPLETE_REASON_AI_NOT_AVAILABLE`が記録されるのみで、Stage4経由で新たに脆弱性が見つかることは無い。

## Stage3（削除済み）: NVDキーワード検索

`NvdKeywordVulnerabilitySource`は単に`@Component`を外して無効化されているだけではなく、**ファイル自体がclosed-modeブランチから物理削除済み**——`ClosedModeArchitectureGateTest`の`DELETED_PATHS_DENYLIST`が、このクラス（`backend/src/main/java/.../service/vuln/NvdKeywordVulnerabilitySource.java`）とそのテストクラス（`NvdKeywordVulnerabilitySourceTest.java`）が存在しないことを積極的にアサートしている。無効化されていた元々の理由（参考: mainline/masterブランチでの経緯）: NVDの`keywordSearch`にはCVEの関連度ソートがなく、一般的な製品名（例: "express"）で検索すると無関係な古いCVEが大量にヒットするノイズ問題が実測で確認され、非エンジニアユーザー向けアプリとして誤解を招くため無効化されていた。closed-modeブランチではこの実装自体がそもそも存在しないため、再有効化の議論（LLMによる関連度フィルタ等）も対象外。

cve.org（CVE Services API）のキーワード検索は、匿名利用不可（CNA組織APIキーが必須）のため実装していない。

## 各Tier/Stageのコスト特性

| 工程 | コスト | 発火頻度 |
|---|---|---|
| Tier1（静的） | 無料 | 常時 |
| ~~ライブCPE照会~~ | （削除済み） | 閉域モードバックログ項目273〔B4〕でライブNVD CPE APIフォールバック経路自体を物理削除済み。Tier1のCPEマッチングは常にローカル`cpe_dictionary`ミラーのみで完結する |
| ~~Tier2~~ | （削除済み） | closed-mode B2（`docs/spec/closed-mode-plan.md`§9-2）でAI呼び出し経路自体を物理削除済み。CPE候補が2件以上でも、静的フォールバック規則（後述）が常に無料で適用される |
| ~~Tier3~~ | （削除済み） | closed-mode B2で同上。Tier1が完全空振りのアイテムは呼び出し自体は発生するが常に空振りに終わり、UNIDENTIFIEDのままになる |
| Stage2 | 無料 | 識別済みアイテムに常時 |
| ~~Stage4~~ | （削除済み） | closed-mode B2で同上。呼び出し条件を満たしても常に0件+`INCOMPLETE_REASON_AI_NOT_AVAILABLE`を返すno-op |
