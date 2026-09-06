# アーキテクチャ

> **注記**: 本ドキュメントは`closed-mode`ブランチの実装を説明しています。閉域モードのデータ非送信設計についての詳細は[CLOSED_MODE_DATA_HANDLING.md](./CLOSED_MODE_DATA_HANDLING.md)を参照してください。

## 技術スタック

| コンポーネント | 技術 | 役割 |
|---|---|---|
| backend | Spring Boot 3.5.16 (Java 21) + Thymeleaf | 認証・GUI・調査パイプライン全体のオーケストレーション |
| DB | PostgreSQL 16（`pg_trgm`拡張使用） | 永続化・CPE辞書/レジストリ/脆弱性データの各種ローカルミラーとそのあいまい検索 |

閉域モードでは外部のLLMマイクロサービスは存在しません。旧バージョンにあったPython/FastAPI製`llm-service`（Claude API呼び出し用ラッパー）はソースディレクトリごと削除済みで、`docker-compose.yml`にも定義がありません。2サービス（`backend`・`postgres`）のみが`docker-compose.yml`でオーケストレーションされ、`backend`は8080番、`postgres`は5432番で待受します。

## 認証・セッション

Spring Security によるフォームベースセッション認証。パスワードはBCryptハッシュ化。認証必須（`/register` `/login` `/css/**` `/js/**` のみ`permitAll`）。管理者ロール（`ROLE_ADMIN`）は実装済み——`ADMIN_EMAIL`環境変数に設定した1メールアドレス（複数指定は未対応）でログインしたユーザーにのみ、ログインのたびに動的付与される（DBに永続化されるフラグではない、`AppUserDetailsService`）。`ADMIN_EMAIL`はSpring起動時に一度だけ読み込まれるため、設定変更にはバックエンドの再起動が必要。`ROLE_ADMIN`保持者のみ`/admin/**`（CPE辞書・CVE.org・CSAF・GHSA/OSVミラー・レジストリミラー・NVD CVEミラーの手動同期画面）へアクセス可能。

## ルーティング一覧

| メソッド | パス | 用途 |
|---|---|---|
| GET | `/` | ホーム画面 |
| GET/POST | `/register` | アカウント登録 |
| GET | `/login` | ログインフォーム |
| GET | `/guide` | 初期設定・使い方ガイド |
| GET | `/jobs` | 調査ジョブ一覧（自分のジョブのみ） |
| GET | `/jobs/new` | CSVアップロードフォーム |
| POST | `/jobs` | CSVアップロード→ジョブ作成（同期でCSV解析、非同期で調査実行） |
| GET | `/jobs/{id}` | ジョブ詳細・結果一覧（所有者チェックあり） |
| GET/POST | `/settings/secrets` | APIキー登録画面（閉域モードではNVD APIキーのみ登録可能。Claude APIキーの読み出し経路自体が削除済みのため、登録フォームにも選択肢として現れない） |
| POST | `/settings/secrets/{provider}/delete` | APIキー削除 |
| GET | `/admin/cpe-dictionary` | CPE辞書の手動同期画面 |
| POST | `/admin/cpe-dictionary/sync` | NVD CPE APIからキーワード同期を実行 |
| GET | `/admin/cve-org` | CVE.org同期画面 |
| GET | `/admin/csaf-siemens` | Siemens CSAFアドバイザリー同期画面 |
| GET | `/admin/csaf-redhat` | Red Hat CSAFアドバイザリー同期画面 |
| GET | `/admin/ghsa` | GHSAミラー同期画面 |
| GET | `/admin/osv` | OSVミラー同期画面 |
| GET | `/admin/registry-mirror` | レジストリミラー（9エコシステム）同期画面 |
| GET | `/admin/nvd-cve` | NVD CVEミラー同期画面 |

管理者ロールの詳細は上記「認証・セッション」節を参照（2026-08-30訂正、旧「管理者専用ロールは未実装」という記述は陳腐化していたため削除）。`/admin/cve-org`・`/admin/csaf-siemens`・`/admin/csaf-redhat`・`/admin/ghsa`・`/admin/osv`・`/admin/registry-mirror`・`/admin/nvd-cve`はいずれも同様に`ROLE_ADMIN`必須。

## 非同期処理

CSVアップロード（`POST /jobs`）は以下の順で動く。

1. `ResearchJobService.createJob` が同期的にCSVをパースし、`research_jobs` / `research_job_items` を作成してコミット
2. コントローラがコミット後に `ResearchJobProcessingService.processJobAsync` を呼び出す（`@Async`）
3. ジョブ内の各アイテムを順番に処理（Stage1→Stage2→Stage4、詳細は [pipeline.md](./pipeline.md)）
4. 全アイテム処理後、ジョブステータスを `COMPLETED` に更新

**自己呼び出しの罠を避けるための設計**: `@Async` と `@Transactional` はSpring AOPプロキシ経由でのみ効くため、同一クラス内メソッドからの直接呼び出し（`this.foo()`）では素通りしてしまう。これを避けるため、ジョブ作成（`ResearchJobService`）と非同期処理起動（`ResearchJobProcessingService`）を別Beanに分離し、コントローラがコミット後に明示的に後者を呼び出す構成にしている。

## 識別・調査パイプライン本体は外部通信手段を持たない

閉域モードでは、CSVアップロード後のStage1（製品識別）・Stage2（脆弱性調査）・Stage4（最終リサーチ）は、いずれも**ローカルDBのミラーテーブルにのみ**問い合わせます。旧バージョンにあった以下の外部ライブ呼び出しは物理的に削除されています。

- Stage1のレジストリ照合（npm/PyPI/crates.io/RubyGems/Packagist/NuGet/Hex/pub.dev/Go proxy）: 各`*RegistryClient`はローカルDBのミラーテーブルのみに問い合わせる実装で、ライブHTTP照会（`lookupLive`相当）のコード自体が削除済み。`RestClient`等のフィールドも保持しません。**Maven Centralだけは例外**で、閉域モード用ミラー自体を一度も持ったことがなく、`MavenCentralRegistryClient#lookup`は常に`Optional.empty()`を返す恒久的no-opです（外部通信は発生しませんが、`RegistryRoutingPolicy`が`groupId:artifactId`形式をMaven Centralのみにルーティングするため、Maven座標のレジストリ照合は常に空振りになります。ただし製品識別そのものが止まるわけではなく、`Stage1IdentificationService#identify`はレジストリ照合とは独立にローカルCPE辞書照合を常に実行するため、CPE辞書に該当エントリがあるJava製品は引き続き識別されます）。
- Stage1のCPE照合: 旧バージョンにあった「ローカル辞書が空振りの場合にNVD CPE APIへライブ照会する」フォールバックは削除済みで、`pg_trgm`によるローカルCPE辞書のあいまい検索のみで完結します。
- Stage2の脆弱性調査（NVD CVE／OSV／GHSA／cve.org／CSAF）: いずれも対応する`*VulnerabilitySource`実装がローカルDBのリポジトリ／`JdbcTemplate`のみを保持し、ライブAPI呼び出し経路は削除済みです。
- Stage1のTier2/3（あいまい候補のAI判定・Web検索名称解決）とStage4（最終リサーチ）: `Stage1AiArbitration`・`Stage4WebSearchResearchService`はいずれもAI呼び出し経路が物理的に削除されており、常に「AI利用不可」のフォールバック（未確定候補は破棄、またはUNIDENTIFIEDのまま）を返します。Claude API（Anthropic Messages API）を呼び出す経路自体がコードベースに存在しません。

この設計の詳細と検証方法は[CLOSED_MODE_DATA_HANDLING.md](./CLOSED_MODE_DATA_HANDLING.md)を参照してください。

## バックグラウンド一括同期が使う外部API

上記の識別・調査パイプライン本体とは別に、ローカルミラーを構築・更新するための一括同期処理（クラス名に`Sync`が付く専用クラス群、詳細は[CLOSED_MODE_DATA_HANDLING.md](./CLOSED_MODE_DATA_HANDLING.md)）が、以下の外部APIをバックグラウンドで叩きます。CSVアップロードそのものを直接のトリガーにはしません。ただし、レジストリミラー同期を有効化した場合、そのシードリストには管理者が明示的に登録した固定名に加え、過去のアップロードから識別処理を経て解決された製品名（`identified_products`）も含まれます——CSV由来のデータと無関係とは言い切れない経路です。詳細は[CLOSED_MODE_DATA_HANDLING.md](./CLOSED_MODE_DATA_HANDLING.md)の「レジストリミラー同期が参照するパッケージ名について」を参照してください。

| API | 用途 | 認証 |
|---|---|---|
| npm / PyPI / crates.io / RubyGems / Packagist / NuGet / Hex / pub.dev / Go proxy（9エコシステム、Maven Centralは含まない——前述の通りMaven Centralには閉域モード用ミラー自体が存在しない） | 各`*MirrorSyncService`によるレジストリミラー同期（既定無効） | 不要 |
| NVD CPE API v2.0 | `NvdCpeSyncService`によるCPE辞書ミラー同期。管理画面（`/admin/cpe-dictionary`）からの手動キーワード同期にも使われる | 任意（ユーザー登録のNVDキー、無料） |
| NVD CVE API v2.0 | `NvdCveSyncService`によるNVD CVEミラー同期 | 任意（同上） |
| OSV公開データダンプ（`osv-vulnerabilities.storage.googleapis.com`） | `OsvSyncService`によるOSVミラー同期 | 不要 |
| GitHub Releases API（`api.github.com` — `CVEProject/cvelistV5`のリリース資産をダウンロード） | `CveOrgSyncService`によるCVE.orgミラー同期（CVE Services API自体は呼ばれない） | 不要 |
| CSAF（Red Hat / Siemens） | `RedHatCsafSyncService` / `SiemensCsafSyncService`によるCSAFミラー同期 | 不要 |
| GitHub API（`api.github.com` — `github/advisory-database`のtarball/commits/advisories）および`raw.githubusercontent.com` | `GhsaSyncService`によるGHSAミラー同期 | 不要 |

**GHSAはStage2の脆弱性照会対象に含まれますが、参照先はローカルミラーのみです**: `GhsaVulnerabilitySource`はStage2実行時にGitHubへライブ問い合わせすることはなく、`GhsaSyncService`が事前にミラーしたローカルテーブルのみを照会します。ミラー同期自体はbaseline投入後、管理者操作とは独立して日次で自動実行されます。詳細は[pipeline.md](./pipeline.md)のStage2節と`GhsaVulnerabilitySource`のクラスjavadoc参照。

NVD系の同期処理はプロセス全体で共有する `NvdRateLimiter` でレート制限している（APIキー無し: 最小間隔6.5秒 / キー登録済み: 最小間隔0.7秒）。間隔はキーの有無に依存し、その鍵の出所は同期経路によって異なる。

- 管理画面からの手動キーワード同期（`/admin/cpe-dictionary/sync`）: 操作中の管理者自身の登録キー
- CPE辞書のフル同期のうち、管理画面ボタン（`/admin/cpe-dictionary/sync-all`）経由・起動時トリガー（`CPE_FULL_SYNC_ON_STARTUP`）経由の実行: 常に無キー
- CPE辞書の週次スケジュール実行（`CpeDictionaryScheduledResync`）: `ADMIN_EMAIL`に設定されたユーザーの登録キー（`getAdminNvdApiKey()`経由）
- NVD CVEバックフィルのスケジュール実行（`NvdCveBackfillScheduledRunner`）: 同じく`ADMIN_EMAIL`ユーザーの登録キー
- NVD CVEバックフィルの管理画面ボタン実行（`/admin/nvd-cve/sync-now`）: 常に無キー

Claude API（Anthropic Messages API）を呼び出す経路は、同期処理も含めコードベース全体に存在しません。
