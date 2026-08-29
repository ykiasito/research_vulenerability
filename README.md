# 脆弱性事前調査Webアプリ

CSVアップロード型の脆弱性事前調査Webアプリです。導入予定のソフトウェア一覧（製品名・バージョン・用途等）をCSVでアップロードすると、既知の脆弱性（CVE等）の有無を製品ごとに調査して結果を返します。非エンジニア向けのGUIを想定しており、**社内利用を前提としています**。

技術スタック: Spring Boot(Java 21, Thymeleaf) + Python/FastAPI(Claude LLMマイクロサービス) + PostgreSQL 16、すべてDocker Composeで構成。

このプロジェクトの詳細な設計・仕様ドキュメントは社内向けのため、本リポジトリには含まれていません。

## セットアップ

### 前提条件

- Docker / Docker Compose v2 が使えること
- `openssl`・`curl` が使えること（`install.sh` が鍵の自動生成・起動確認に使用します)

### 手順

```
./install.sh
```

初回実行時、`.env.example` から `.env` を新規作成し、暗号化キー(`APP_SECRET_ENCRYPTION_KEY`)とDBパスワード(`POSTGRES_PASSWORD`)を自動生成した上で、Docker Composeでビルド・起動します。既に `.env` が存在する場合は上書きしません。

`.env` には他にも `ADMIN_EMAIL`(管理者権限を与えるログインメールアドレス)・`JOB_RETENTION_DAYS`(ジョブの自動削除日数)といった、環境ごとに自分の値を設定すべき項目があります。必要に応じて `.env` を直接編集してください。

起動後は `http://localhost:8080` からアクセスできます。

## 重要な注意事項

**このアプリは社内利用・非公開ネットワークでの利用を前提としています。インターネットに露出する環境にそのままデプロイしないでください。**

具体的には、現状のdocker-compose構成には以下の制約があります:

- TLS(HTTPS)が設定されていません。通信は平文です。
- セッションCookieに `Secure` 属性が設定されていません。

（2026-08-29対応済み）PostgreSQL(5432番ポート)・llm-service(8000番ポート)は `docker-compose.yml` で `127.0.0.1` 限定バインドに変更済みで、ホスト外部からは到達できません。ただしこれはDocker Composeをそのまま動かした場合の話であり、リバースプロキシ経由での転送設定や、ホスト自体を直接インターネットに晒す構成にすると意味を失います。

インターネット等の信頼できないネットワークに接続する環境で動かす場合は、上記に加えてリバースプロキシによるTLS終端、Cookieの `Secure` 属性設定を必ず行ってください。

## テスト実行(開発者向け)

`mvn test` を実行するには、稼働中のPostgresに対して事前に専用の `vulncheck_test` ロール・データベースを作成しておく必要があります。手順は以下の通りです。**Postgresコンテナ内で `psql` から実行してください**(`docker exec -it <postgresコンテナ> psql -U vulncheck -d vulncheck`)。

```sql
-- 1. テスト専用ロールを作成(LOGIN以外の特別な属性は付与しない — SUPERUSER/CREATEDB/CREATEROLEいずれもfalseのまま)
CREATE ROLE vulncheck_test WITH LOGIN PASSWORD 'vulncheck_test';

-- 2. テスト専用データベースを作成(所有者は本番ロールvulncheckのまま — vulncheck_test自身をDB所有者にしない)
CREATE DATABASE vulncheck_test OWNER vulncheck;

-- 3. vulncheck_testロールがこのDBへ接続できるようにする
GRANT CONNECT ON DATABASE vulncheck_test TO vulncheck_test;

-- 4. public スキーマでのテーブル作成(Flywayマイグレーション実行に必要)・参照を許可
--    (vulncheck_test データベースに接続してから実行すること)
\c vulncheck_test
GRANT USAGE, CREATE ON SCHEMA public TO vulncheck_test;

-- 5. 【必須】本番vulncheck・postgresデータベースへのPUBLIC経由の接続を遮断する
--    PostgreSQLはデフォルトでdatacl(データベースACL)がNULLの場合、PUBLICロールにCONNECT/TEMP権限を
--    暗黙付与する。これを塞がないと、上で作ったvulncheck_test(パスワードはこの通りリポジトリに平文で
--    載っている既知の値)が本番vulncheckデータベースへ接続でき、テーブル自体は読めなくてもカタログ全体
--    (テーブル名・列名・ロール名・pg_settings)の列挙や無制限の一時テーブル作成(ディスク枯渇リスク)が
--    可能になってしまう。
REVOKE CONNECT ON DATABASE vulncheck FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
```

実行後、以下のSQLで `f`(接続不可)が返ることを確認してください:

```sql
SELECT has_database_privilege('vulncheck_test', 'vulncheck', 'CONNECT');
```

**警告: `vulncheck_test` のパスワードは `vulncheck_test` 固定であり、`backend/src/test/resources/application.yml` にそのまま平文で書かれています(このリポジトリは公開リポジトリなので、この値は誰でも読める既知の値です)。本番 `vulncheck` データベースに到達できる環境で、このロール・パスワードの組み合わせを作成してはいけません。**上記手順5のREVOKEを省略した場合、このロールは本番データベースへの偵察・DoS(一時テーブルによるディスク枯渇)の経路になります。ローカル開発専用のPostgresインスタンス(このリポジトリの `docker-compose.yml` が起動するもの)以外では、このロールを作成しないでください。

`@AutoConfigureTestDatabase(Replace.NONE)` を使うテストクラスは、必ず上記の `vulncheck_test` 専用DB(`backend/src/test/resources/application.yml` でハードコード済み)に対してのみ実行してください。実dev DB(`vulncheck`)に向けて実行することは禁止です。
