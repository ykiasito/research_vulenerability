# データベーススキーマ

PostgreSQL 16。Flywayでマイグレーション管理（`backend/src/main/resources/db/migration/`）。

## マイグレーション履歴

| バージョン | 内容 |
|---|---|
| V1 | 初期スキーマ（`users`/`user_secrets`/`research_jobs`/`research_job_items`/`identified_products`/`vulnerabilities`/`job_item_vulnerabilities`/`cpe_dictionary`/`vendor_advisory_sources`）、`pg_trgm`拡張有効化 |
| V2 | `cpe_dictionary.cpe_string`のユニーク制約（upsert用）、外部キー列へのインデックス追加 |
| V3 | `ecosystem_registries`テーブル新設（npm/pypi/maven/go/nugetを初期投入） |
| V4 | `research_job_items.identification_hint`（ヒント表示テキスト）追加 |
| V5 | `identified_products.version_confirmed`（レジストリでのバージョン実在確認結果）追加 |
| V6 | `research_job_items.hint_platform` / `hint_identifier`（ヒントの構造化フィールド、AI再調査用）追加 |
| V7 | `vulnerabilities.fixed_version`（推奨アップデートバージョン）追加 |
| V8 | `cve_org_records` / `cve_org_affected_products` / `cve_org_sync_state`テーブル新設（CVE.org連携） |
| V9 | `cpe_dictionary` / `cve_org_affected_products`のpg_trgm検索クエリをGINインデックス対応に書き換え、`cve_org_affected_products.package_name`のtrgmインデックス追加 |
| V10 | `ecosystem_registries`にrubygems/crates.io/packagist/hex/pubを追加投入（OSV対応14エコシステム中10に到達） |
| V11 | `research_job_items.vulnerability_research_incomplete`（Stage2が全ソース失敗で未検証だったことを示すフラグ）追加 |
| V12 | V11のbooleanを`research_job_items.research_incomplete_reason`（`SOURCES_FAILED`/`IDENTIFICATION_TOO_WEAK`の理由コード）に置き換え |
| V13 | 旧CPE分割ロジックの不具合で壊れていた`cpe_dictionary`のvendor/product列を、対象4,815行についてescape対応の再分割でバックフィル |
| V14 | `ecosystem_registries`にChocolatey（Windowsパッケージマネージャ）を追加投入 |
| V15 | `research_jobs.version_plausibility_warning`（CSVのバージョン値がレジストリ実在確認と乖離している場合の警告フラグ）追加 |
| V16 | `job_item_vulnerabilities`に同梱コンポーネント帰属列(`bundled_component_name`/`bundled_component_version`)、`research_jobs.bundled_component_check_enabled`（同梱コンポーネント検査のオプトインフラグ）追加 |
| V17 | ベンダー公開CSAF（Common Security Advisory Framework）アドバイザリのローカルミラー4テーブル(`csaf_advisories`/`csaf_products`/`csaf_product_status`/`csaf_sync_state`)新設、`job_item_vulnerabilities`にCSAF注釈列追加（Phase1はSiemensのみ投入） |
| V18 | `csaf_product_status`に`(vendor, advisory_id, cve_id, csaf_product_id, status)`のユニーク制約追加（重複行防止をDB層でも保証） |
| V19 | GitHub Security Advisories(GHSA)のローカルミラー6テーブル新設(`ghsa_advisories`/`ghsa_affected_packages`/`ghsa_affected_versions`/`ghsa_affected_ranges`/`ghsa_sync_state`/`ghsa_sync_failures`) |
| V20 | CSAF Phase2（Red Hat）対応: `csaf_products`に`raw_leaf_name`・生成列`component_name_normalized`追加、`(vendor, component_name_normalized)`インデックス追加 |
| V21 | CSAF Phase2レビュー指摘の是正: `csaf_products.advisory_updated_at`（親アドバイザリの更新日時を非正規化）追加、V20のインデックスを`advisory_updated_at DESC`込みの複合インデックスに置き換え、trgmインデックスをSiemens限定の部分インデックスに変更 |
| V22 | V21の是正フォローアップ: 適用済みV21の`advisory_updated_at`を既存行についてバックフィル、インデックスを`DESC NULLS LAST`（実クエリのORDER BYと一致させる）で再作成 |
| V23 | `job_cost_ledger`テーブル新設（`JobCostBudgetService`のreserve/reconcile結果をDB永続化し、ジョブ完了後に$/item実績をSQLで抽出可能にする） |
| V24 | `job_cost_ledger.job_item_id`にインデックス追加（外部キー列は自動でインデックスされないため、`research_job_items`削除時のON DELETE CASCADEが全表スキャンになっていたのを是正） |
| V25 | OSV.dev独自（非GHSA査読）アドバイザリのローカルミラー6テーブル新設(`osv_advisories`/`osv_affected_packages`/`osv_affected_versions`/`osv_affected_ranges`/`osv_sync_state`/`osv_sync_failures`)、V19のGHSAミラーと同型 |
| V26 | `research_job_items.raw_product_name`（CSV記載の製品名の生テキスト、注記除去前のもの。表示/エクスポート用。識別処理自体は引き続き除去済みの`product_name`を使う）追加 |
| V27 | `job_cost_ledger`に呼び出し単位の内訳列(`input_tokens`/`output_tokens`/`web_search_requests`/`call_site`)追加（見積り定数をログgrepではなくSQLで再導出可能にする） |

## テーブル一覧

### `users`
アカウント。`email`（unique）、`password_hash`（BCrypt）。

### `user_secrets`
ユーザーごとのAPIキー（暗号化済み）。`provider`は`claude`または`nvd`のCHECK制約。**`nvd`は現状未使用**（登録はできるが、どのNVD呼び出しにも読み出されていない）。`(user_id, provider)`でユニーク。`encrypted_key`はAES-256-GCM暗号文（`base64(iv):base64(ciphertext+tag)`）。

### `research_jobs`
CSVアップロード1回＝1ジョブ。`status`: `PENDING`/`PROCESSING`/`COMPLETED`/`FAILED`。

### `research_job_items`
CSVの1行＝1アイテム。`status`: `PENDING`/`IDENTIFIED`/`UNIDENTIFIED`。
`identification_hint`（表示用テキスト）、`hint_platform`/`hint_identifier`（構造化、Stage4のヒント調査で使用）はTier3が識別子を見つけたが自動照会できなかった場合のみ非NULL。

### `identified_products`
Stage1の識別結果。1アイテムにつき最大1行（`job_item_id`は論理上一意）。
`method`: `static`（Tier1のみ）/ `llm_disambiguate`（Tier2） / `llm_web_search`（Tier3）。
`cpe`はCSVの実バージョンに差し替え済み（辞書上の生の値ではない）。
`version_confirmed`: `true`=レジストリでバージョン実在確認済み、`false`=パッケージは実在するがこのバージョンは確認できず、`null`=レジストリ照合なし（CPEのみでの識別、バージョンは未検証）。

### `vulnerabilities`
脆弱性のグローバルマスタ。`cve_or_ghsa_id`はユニーク（AIの自由記述識別子は`llm:{パッケージ名}:{識別子}`の形でスコープしてから格納）。`source`: `nvd`/`osv`/`ghsa`/`llm_web_search`（`nvd_keyword`は本番未使用）。

### `job_item_vulnerabilities`
アイテムと脆弱性のN:M中間テーブル。`(job_item_id, vulnerability_id)`が複合主キー。`discovered_via_tier`列があるが現状の書き込み値は実質`source`と同義（将来的な精緻化余地）。

### `cpe_dictionary`
NVD CPE辞書のローカルミラー。`pg_trgm`のGINインデックス（`product`/`title`列）であいまい検索。管理画面からのキーワード同期、またはStage1のライブ照会（1ページ限定）で随時追記される。

### `ecosystem_registries`
Stage1が照会できるパッケージレジストリのカタログ。`enabled=true`の行がTier3のAIに渡す「有効なエコシステム一覧」の元データ。

### `vendor_advisory_sources`
V1から存在するが**未使用**（CSAF/RSS/scrapeアダプタが未実装のため、行の投入すら行われていない）。

### `job_cost_ledger`
`JobCostBudgetService`の`reconcile`/`reconcileBundledComponent`が呼ばれるたび（＝AIコール1回の結果が確定するたび）に1行追加される、実消費額の永続ログ。`ledger`は`MAIN`（常時有効な$0.005/item予算）または`BUNDLED_COMPONENT`（同梱コンポーネント検査のオプトイン予算）。`reserved_cost_usd`は呼び出し前の保守的見積り、`actual_cost_usd`はClaude APIレスポンスの実トークン数/web_search回数から計算した実額（失敗時は0で予約分を実質返却）。ジョブの予算追跡がすでに終了（`endJobBudget`）していても、実際に使われたドルは変わらないため書き込みは無条件に行われる。`job_item_id`があるので、`research_job_items`とJOINして「ジョブ全体のアイテム数」で割れば$/item平均を事後にSQLで抽出できる。

V27（2026-08-29）で追加された4列:

- `call_site`: そのAI呼び出しがllm-serviceのどのエンドポイントを叩いたかを示す文字列（`ledger`とは別軸で、`ledger`は「どの予算枠から予約したか」、`call_site`は「その枠の中でどの呼び出しだったか」）。対応関係:
  - `TIER2` → `POST /v1/identify/disambiguate`（`ledger=MAIN`）
  - `TIER3` → `POST /v1/identify/web-search`（`ledger=MAIN`）
  - `STAGE4` → `POST /v1/research/web-search`（`ledger=MAIN`）
  - `BUNDLED_CHANGELOG` → `POST /v1/bundled-components/discover-changelog`（`ledger=BUNDLED_COMPONENT`）
  - `BUNDLED_EXTRACT` → `POST /v1/bundled-components/extract`（`ledger=BUNDLED_COMPONENT`）
- `input_tokens` / `output_tokens` / `web_search_requests`: Claude APIレスポンスの実測値（`computeActualCost`が`actual_cost_usd`を算出する際の元データ）。V27適用前に書かれた行はこの4列とも`NULL`のまま。

**job 185汚染行の除外に関する注意**: job 185（2026-08-29実施、150件）の67行は、`llm-service/main.py`の`_count_web_searches`計測バグ（`web_search_tool_result`のエラーブロックも成功として二重・三重カウントしていた）を含むビルドで書き込まれたものであり、`actual_cost_usd`が水増しされている。かつV27適用前に書かれたため`call_site`は`NULL`。今後、`job_cost_ledger`から$/item平均や見積り定数の再導出を行う際は、`call_site IS NOT NULL`（またはjob 185を明示的に除外する`job_id > 185`）の条件を必ず加えること。詳細は`JobCostBudgetService.java`のコメント、`docs/public/nfr-status-2026-08.md`1章参照。
