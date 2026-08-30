# アーキテクチャ

## 技術スタック

| コンポーネント | 技術 | 役割 |
|---|---|---|
| backend | Spring Boot 3.5.16 (Java 21) + Thymeleaf | 認証・GUI・調査パイプライン全体のオーケストレーション |
| llm-service | Python / FastAPI + `anthropic` SDK | Claude API呼び出しの薄いラッパー（Tier2/3・Stage4専用） |
| DB | PostgreSQL 16（`pg_trgm`拡張使用） | 永続化・CPE辞書のあいまい検索 |

3サービスとも `docker-compose.yml` でオーケストレーションされ、`backend` は8080番、`llm-service` は8000番、`postgres` は5432番で待受する。`backend` → `llm-service` はサービス名 `http://llm-service:8000` で通信する（`app.llm-service-url` / 環境変数 `LLM_SERVICE_URL`）。

## 認証・セッション

Spring Security によるフォームベースセッション認証。パスワードはBCryptハッシュ化。認証必須（`/register` `/login` `/css/**` `/js/**` のみ`permitAll`）。管理者ロール（`ROLE_ADMIN`）は実装済み——`ADMIN_EMAIL`環境変数に設定した1メールアドレス（複数指定は未対応）でログインしたユーザーにのみ、ログインのたびに動的付与される（DBに永続化されるフラグではない、`AppUserDetailsService`）。`ADMIN_EMAIL`はSpring起動時に一度だけ読み込まれるため、設定変更にはバックエンドの再起動が必要。`ROLE_ADMIN`保持者のみ`/admin/**`（CPE辞書・CVE.org・CSAF・GHSA/OSVミラーの手動同期画面）へアクセス可能。

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
| GET/POST | `/settings/secrets` | APIキー登録画面 |
| POST | `/settings/secrets/{provider}/delete` | APIキー削除 |
| GET | `/admin/cpe-dictionary` | CPE辞書の手動同期画面 |
| POST | `/admin/cpe-dictionary/sync` | NVD CPE APIからキーワード同期を実行 |
| GET | `/admin/cve-org` | CVE.org同期画面 |
| GET | `/admin/csaf-siemens` | Siemens CSAFアドバイザリー同期画面 |
| GET | `/admin/csaf-redhat` | Red Hat CSAFアドバイザリー同期画面 |
| GET | `/admin/ghsa` | GHSAミラー同期画面 |
| GET | `/admin/osv` | OSVミラー同期画面 |

管理者ロールの詳細は上記「認証・セッション」節を参照（2026-08-30訂正、旧「管理者専用ロールは未実装」という記述は陳腐化していたため削除）。`/admin/cve-org`・`/admin/csaf-siemens`・`/admin/csaf-redhat`・`/admin/ghsa`・`/admin/osv`（CVE.org/CSAF/GHSA/OSVミラー同期画面）も同様に`ROLE_ADMIN`必須だが、本表には未掲載——ルーティング一覧自体の更新は別途必要。

## 非同期処理

CSVアップロード（`POST /jobs`）は以下の順で動く。

1. `ResearchJobService.createJob` が同期的にCSVをパースし、`research_jobs` / `research_job_items` を作成してコミット
2. コントローラがコミット後に `ResearchJobProcessingService.processJobAsync` を呼び出す（`@Async`）
3. ジョブ内の各アイテムを順番に処理（Stage1→Stage2→Stage4、詳細は [pipeline.md](./pipeline.md)）
4. 全アイテム処理後、ジョブステータスを `COMPLETED` に更新

**自己呼び出しの罠を避けるための設計**: `@Async` と `@Transactional` はSpring AOPプロキシ経由でのみ効くため、同一クラス内メソッドからの直接呼び出し（`this.foo()`）では素通りしてしまう。これを避けるため、ジョブ作成（`ResearchJobService`）と非同期処理起動（`ResearchJobProcessingService`）を別Beanに分離し、コントローラがコミット後に明示的に後者を呼び出す構成にしている。

## 外部API連携一覧

| API | 用途 | 認証 |
|---|---|---|
| npm Registry | Stage1 Tier1（レジストリ照合） | 不要 |
| PyPI JSON API | 同上 | 不要 |
| Maven Central Solr Search API | 同上 | 不要 |
| Go Module Proxy | 同上 | 不要 |
| NuGet Flat Container API | 同上 | 不要 |
| NVD CPE API v2.0 | CPE辞書同期・Stage1のライブCPE照会 | 任意（ユーザー登録のNVDキー、無料） |
| NVD CVE API v2.0 | Stage2脆弱性調査（`cpeName`によるバージョン範囲解決） | 任意（同上） |
| OSV.dev `/v1/query` | Stage2脆弱性調査 | 不要 |
| cve.org（CVE Services API、`CveOrgSyncService`によるミラー同期のみ、Stage2実行時はライブ呼び出し無し） | Stage2脆弱性調査（`CveOrgVulnerabilitySource`、ローカルミラー照会） | 不要（同期処理側） |
| Anthropic Messages API | Tier2/3・Stage4 | ユーザー個別のClaude APIキー（暗号化保存） |

**GitHub REST（advisories／GHSA）は2026-08-25時点で意図的に未接続**: `GhsaVulnerabilitySource`は実装済みだが`@Component`を外してあり、Stage2の`VulnerabilitySource`一覧には含まれない。未認証60req/hourの制限がStage2のper-item fan-outと組み合わさると1,000件ジョブで約18時間のスリープを要し、スループット目標を破壊するため。クラスは削除せず、将来の**リポジトリ単位（per-itemではない）**利用のために保持している。詳細は[pipeline.md](./pipeline.md)のStage2節と`GhsaVulnerabilitySource`のクラスjavadoc参照。

NVD系はプロセス全体で共有する `NvdRateLimiter` でレート制限している（APIキー無し: 最小間隔6.5秒 / ジョブ実行ユーザーがNVDキー登録済み: 最小間隔0.7秒）。
