# 調査パイプライン

CSV1行（`ResearchJobItem`）ごとに、Stage1（製品識別）→Stage2（脆弱性調査）→（条件付き）Stage4（AI最終手段）の順で処理する。Stage3は実装済みだが本番経路には組み込まれていない（後述）。

## Stage1: 製品識別（`Stage1IdentificationService`）

3段階（Tier1〜3）で構成。**共通方針**: 静的・無料の経路を優先し、LLM呼び出しは曖昧さがある時・完全に手がかりがない時だけ行う。

### Tier1: 静的照合

1. **レジストリ照合**: `PackageRegistryLookup` の全実装（npm/PyPI/Maven/Go/NuGet）に対して、CSVの`product_name`をそのまま渡して照会。各実装は「パッケージ自体が存在するか」「指定バージョンが実在するか」を判定し、`RegistryMatch(ecosystem, packageName, purl, confidence, exactVersionConfirmed)` を返す。バージョン実在確認済みなら confidence 0.95、未確認なら 0.4〜0.5。
2. **CPE辞書照合**: ローカルの `cpe_dictionary` テーブルに対して `pg_trgm` のあいまい一致（`product`/`title`列、閾値0.3、上位3件）。
   - **ローカルに候補が1件もない場合、その場でNVD CPE APIに1回だけ生きた照会を行う**（`NvdCpeSyncService.syncKeywordSinglePage`、`NvdRateLimiter`でレート制限）。ヒットした分はローカル辞書にキャッシュされ、以降の同一クエリは無料になる。これにより「誰も事前同期していない製品は永久に見つからない」という問題を回避している。
   - CPE一致のバージョンフィールドはあいまい一致の対象外（テキストのみ比較）。永続化時にはvendor:productだけを取り出し、**CSVの実バージョンに差し替えて**保存する（`Stage1IdentificationService.withItemVersion`）。辞書上の古いバージョン番号をそのまま見せると人間の目には不整合に見えるための対応。

レジストリ照合とCPE照合の両方が空振りの場合のみ Tier3 へ進む。どちらか一方でも候補があれば Tier2（必要なら）を経て確定する。

### Tier2: あいまい候補のLLM判定

CPE候補が2件以上ある場合のみ発火（1件ならLLM抜きでそのまま採用、0件ならTier1のレジストリ結果のみで確定）。

- Claude（`claude-haiku-4-5`）に候補リストのインデックスを選ばせる方式。**新しい候補を生成させない**（ハルシネーション対策）。
- 候補のCPE文字列は**バージョンをマスクして**（`*`に置換）渡す。理由: 辞書上の古いバージョン番号を見せると、LLMが「バージョンが違うから不一致」と誤判定するバグが実際に発生した（NuGet CLI・Wireshark検証時に発覚、修正済み）。バージョンの妥当性判断は本来この工程の役割ではない。
- APIキー未登録・LLM呼び出し失敗時は、先頭候補を機械的に採用する劣化動作にフォールバックする。

### Tier3: Web検索による名称解決

Tier1が完全に空振りだった場合のみ発火（マーケットプレース表記ゆれ等）。

1. Claudeに `web_search` ツール（`web_search_20250305`、max_uses=3）を持たせ、正式なベンダー名・製品名を検索させる。
2. 併せて、**有効なエコシステム一覧**（`ecosystem_registries`テーブルから取得）をプロンプトに渡し、AIが確信を持てる場合は `ecosystem_candidates`（エコシステム名＋正確なパッケージ名の推測）も返させる。エコシステム値はJSON Schemaのenumで許可リストに制約している。
3. バックエンドは解決された正式名称でTier1を再照会する。`ecosystem_candidates` が返っている場合は、**その特定のレジストリに実際に照会して検証してから**採用する（AIの言い分をそのまま信用しない設計、Tier2と同じ思想）。
4. 上記いずれも空振りの場合、AIが認識した「このアプリが自動照会できない配布チャネルの識別子」（`platform_hint`: VS Code Marketplace拡張ID、Chrome Web Store ID、Docker Hubイメージ名など、固定enumではなく自由記述）があれば `research_job_items.identification_hint`（表示用）と `hint_platform`/`hint_identifier`（構造化・調査用）に保存する。この場合もアイテムのstatusは `UNIDENTIFIED` のまま。ヒントの `note` は「これで合っていますか？」という確認質問の形で日本語生成するようプロンプト指定している（断定を避けるため）。

## Stage2: 脆弱性調査（`Stage2VulnerabilityResearchService`）

Stage1で `IdentifiedProduct` が得られたアイテムのみ対象。3つの `VulnerabilitySource` を**逐次（1つずつ、並行ではない）**問い合わせ、結果を **完全一致するID文字列でのみ**重複排除して統合する。並行化していないのは意図的な設計判断——`ResearchJobProcessingService`が既にジョブ内の複数アイテムを並行処理しているため、ソースループまで並行化してもNVD/GHSAの共有レートリミッタへの同時負荷が増えるだけで明確なスループット向上は見込めない（詳細は`Stage2VulnerabilityResearchService`のクラスjavadoc参照）。

| ソース | 発火条件 | 特記事項 |
|---|---|---|
| `NvdVulnerabilitySource` | CPEが確定している場合のみ | `cpeName`（vendor:product + 実バージョン）でNVDのバージョン範囲解決に委任。専用のバージョン比較ロジックは実装していない（設計上の意図的な逸脱、後述） |
| `OsvVulnerabilitySource` | ecosystem/packageNameが確定している場合のみ | OSV.devの`version`フィールドでバージョン範囲解決に委任 |
| `CveOrgVulnerabilitySource` | 常時（識別済みアイテム全般） | ローカルの`cve_org_records`/`cve_org_affected_products`ミラー（`CveOrgSyncService`）に対する照会のみ、ライブAPI呼び出しなし。CSVの生の`product_name`/`vendor`テキストで照会し、Stage1と同じ`pg_trgm`あいまい一致方式を使う（レジストリ/CPEのエコシステムには乗らないため） |

**GHSA（`GhsaVulnerabilitySource`）は`@Component`を外してあり、上記には含まれない（2026-08-25時点）**: GitHub未認証REST advisoriesは60req/hourしか許されず、Stage2のper-item fan-out（アイテム1件につき1呼び出し）に組み込むと1,000件ジョブで約18時間のスリープだけで「1,000件/3時間」目標を単独で突破してしまうと判明したため、無効化した。OSV.devがGHSAアドバイザリーの大半を既に取り込んでいるため、per-item経路からの脱落は許容される冗長性の喪失として扱っている。クラス自体と`GhsaRateLimiter`は削除せず残してあり、将来の**リポジトリ単位（アイテム単位ではない）**利用を想定している——65秒間隔のレートリミットはリポジトリ単位の呼び出し回数となら両立する。再有効化する場合は、単に`@Component`を付け戻すのではなく、per-item fan-outに戻さない設計にすること（詳細な経緯は`GhsaVulnerabilitySource`のクラスjavadoc参照）。

**設計上の意図的な逸脱**: 当初案ではエコシステムごとの専用バージョン比較ロジック（semver/PEP440/Maven/Go）を実装する想定だったが、各APIが持つサーバーサイドのバージョン範囲解決に委任する方式にした。自前の多エコシステム比較器より正確と判断したため。

**既知の簡略化**: CVEとGHSAが同一の実際の脆弱性を指していても、ID文字列が異なれば別々の行として残る（エイリアス解決は未実装）。

## Stage4: AI最終手段調査（`Stage4WebSearchResearchService`）

**中核方針に基づくゲート条件**: 以下のいずれかの場合のみ発火。それ以外（Stage2が1件でも見つけた場合）は**発火しない** — 「影響のある脆弱性が1件でも見つかれば静的調査だけで完結してよい」という方針を反映した設計であり、取りこぼしがあっても仕様（詳細は[known-limitations.md](./known-limitations.md)）。

1. Stage1で識別済み・かつStage2が0件だった場合 → `ecosystem`/`packageName` を検索スコープにする
2. Stage1で識別自体ができなかった（UNIDENTIFIED）が、Tier3が `platform_hint` を残していた場合 → `hint_platform`/`hint_identifier` を検索スコープにする（この場合だけがUNIDENTIFIEDアイテムに脆弱性の答えを出せる唯一の経路）

Claudeに `web_search` ツール（max_uses=2）を持たせ、構造化DBで見つからなかった脆弱性をWeb検索させる。返ってきた識別子がCVE/GHSA形式なら`vulnerabilities`テーブルのグローバルユニークキーとしてそのまま使い、それ以外の自由記述識別子は `llm:{パッケージ名}:{識別子}` の形でスコープして異なる製品同士の衝突を防ぐ。

## Stage3（未使用）: NVDキーワード検索

`NvdKeywordVulnerabilitySource` は実装・単体テスト済みだが、`@Component` を外してあり本番の `VulnerabilitySource` 一覧には含まれない。理由: NVDの `keywordSearch` にはCVEの関連度ソートがなく、一般的な製品名（例: "express"）で検索すると無関係な古いCVEが大量にヒットするノイズ問題が実測で確認された。非エンジニアユーザー向けアプリとして誤解を招くため無効化した。再有効化にはLLMによる関連度フィルタが必要（未実装）。

cve.org（CVE Services API）のキーワード検索は、匿名利用不可（CNA組織APIキーが必須）のため実装していない。

## 各Tier/Stageのコスト特性

| 工程 | コスト | 発火頻度 |
|---|---|---|
| Tier1（静的） | 無料 | 常時 |
| ライブCPE照会 | 無料（NVD無料枠） | ローカル辞書が空振りの時のみ |
| Tier2 | Claude API課金（web_search無し、軽量） | CPE候補が2件以上の時のみ |
| Tier3 | Claude API課金（web_search込み） | Tier1が完全空振りの時のみ |
| Stage2 | 無料 | 識別済みアイテムに常時 |
| Stage4 | Claude API課金（web_search込み、最も高価） | Stage2が0件、またはヒントのみ存在する時のみ |
