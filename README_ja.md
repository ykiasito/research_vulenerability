# 脆弱性事前調査Webアプリ

CSVアップロード型の脆弱性事前調査Webアプリです。導入予定のソフトウェア一覧（製品名・バージョン・用途等）をCSVでアップロードすると、既知の脆弱性（CVE等）の有無を製品ごとに調査して結果を返します。非エンジニア向けのGUIを想定しており、**個人利用を前提としています**。

技術スタック: Spring Boot(Java 21, Thymeleaf) + PostgreSQL 16、すべてDocker Composeで構成。

このブランチは `closed-mode` です: CSVアップロード→識別処理のパイプライン中に**外部LLM/AI APIを一切呼び出さない**、完全オフライン動作を前提に設計されています。`llm-service` というコンポーネントはこのブランチには存在しません——他ブランチで使われているPython/FastAPI(Claude LLMマイクロサービス)は `closed-mode` では完全に削除済みです。このブランチの `docker-compose.yml` はサービスを2つ(`backend`・`postgres`)しか定義していません。3つ目のコンテナ(`llm-service`)や8000番ポートに関する記述をどこかで見た場合、それはこのブランチには当てはまりません。

このプロジェクトの詳細な設計・仕様ドキュメントは個人利用のため、本リポジトリには含まれていません。

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

## 初回データ投入(重要——結果を信用する前に必ず実施)

新規インストール直後は、CPE辞書も脆弱性データのミラーも**すべて空**の状態です。この状態でCSVをアップロードしてジョブを実行すると、すべて「既知の脆弱性なし」という結果になります——ただしこれは照合先のデータが無いだけであり、実際にリストの製品が安全であることを意味しません。ジョブ結果を信用する前に、また他の人がこのアプリにアクセスできるようにする前に、必ず**以下の順番で**実施してください。

1. **`ADMIN_EMAIL` のアカウントを、他の誰かがアプリへアクセスできるようになる前に真っ先に登録する**。`/register` エンドポイントは誰でもアクセス可能で、`.env` の `ADMIN_EMAIL` と一致するメールアドレスで登録した人にROLE_ADMINが付与されます(以下の手順は全て `/admin/**` 配下の管理者専用画面で行うため必要)。8080番ポートは既定でネットワーク全体から到達可能で(下記「重要な注意事項」参照)TLSも掛かっていないため、`docker compose up` 直後、他のユーザーにこのアプリを公開する前に、まず管理者アカウントを登録してください。
2. 管理画面(`/admin/cpe-dictionary`)からCPE辞書のフル同期を実行する。これが無いと製品・バージョンの識別処理には実質何も照合先がありません。
3. GHSA・OSVのベースライン投入(`/admin/ghsa` の「ベースライン同期」・`/admin/osv` の「ベースライン同期」)を実行する。日次の自動同期は、この初回ベースラインが一度投入された後の更新分だけを担当するもので、最初のデータ投入自体は行いません。
4. 管理画面(`/admin/nvd-cve` の「同期を実行」)からNVD CVEバックフィルを実行する。1回のクリック(1ティック)には時間・リクエスト数の上限があり完走までに数回のクリックが必要な場合があります(完了したかどうかは結果表示で分かります)。この手順は実質必須です——CPEで識別した行(Chrome・OpenSSL・nginx等)の脆弱性情報の主要な出所がここだからです。
5. 管理画面(`/admin/registry-mirror` の「同期を開始」)からレジストリミラー同期を実行する。対応する9エコシステム(npm・PyPI・crates.io・RubyGems・Packagist・NuGet・Hex・pub.dev・Go modules)を一括でカバーします。
6. 以上がすべて一度完了して初めて、ジョブ結果を信用してよい、またこれ以上ネットワーク公開範囲を広げる作業に進んでよい状態になります。

## 重要な注意事項

**このアプリは個人利用・非公開ネットワークでの利用を前提としています。インターネットに露出する環境にそのままデプロイしないでください。**

具体的には、現状のdocker-compose構成には以下の制約があります:

- TLS(HTTPS)が設定されていません。通信は平文です。
- セッションCookieに `Secure` 属性が設定されていません。

（2026-08-29対応済み）PostgreSQL(5432番ポート)は `docker-compose.yml` で `127.0.0.1` 限定バインドに変更済みで、ホスト外部からは到達できません。ただしこれはDocker Composeをそのまま動かした場合の話であり、リバースプロキシ経由での転送設定や、ホスト自体を直接インターネットに晒す構成にすると意味を失います。

**PostgreSQLと異なり、backend(8080番ポート)は全ホストインタフェースにバインドされており、localhost限定ではありません**——ホストへ到達できる任意のマシンから到達可能で、そもそも他のマシンからこのアプリを使えているのはこの設定のためです。Docker Compose自体はこれ以上の制限をかけないため、到達範囲を絞りたい場合はホスト側のファイアウォールやネットワーク分離で対応してください。上記「初回データ投入」で、他の誰かがアクセスできるようになる前に `ADMIN_EMAIL` アカウントを先に登録するよう述べているのも、localhost限定ポートより重要度が高い理由です。

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

---

English version: [README.md](README.md)
