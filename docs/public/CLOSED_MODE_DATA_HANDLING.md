# 閉域モードにおけるデータ非送信について

## 前提

このリポジトリの「閉域モード(closed-mode)」ビルドは、CSVアップロードで投入されたデータ(製品名・バージョン・vendor名等)を外部へ一切送信しない設計になっています。ユーザーがCSVをアップロードして識別処理を実行しても、そのジョブの処理過程で外部URLへのHTTPリクエストが発生することはありません。

このドキュメントでは、その設計がなぜ・どのように成り立っているかと、第三者が自分の環境で同じことを検証する方法をまとめます。

## 外部HTTPリクエストが発生しうる箇所

このコードベースで `RestClient`/`RestTemplate`/`WebClient`/`HttpURLConnection` を実際に使用しているクラスは、以下の**バックグラウンド一括同期専用クラスのみ**です。いずれもクラス名に「Sync」が付いており、CSVアップロード処理の経路(識別処理本体)からは呼び出されません。

| データソース | クラス |
| --- | --- |
| NVD CPE辞書 | `NvdCpeSyncService` |
| NVD CVE | `NvdCveSyncService` |
| CSAF(Red Hat / Siemens) | `RedHatCsafSyncService` / `SiemensCsafSyncService` |
| CVE.org | `CveOrgSyncService` |
| GHSA | `GhsaSyncService` |
| OSV | `OsvSyncService` |
| パッケージレジストリ(npm / PyPI / crates.io / RubyGems / Packagist / NuGet / Hex / pub.dev / Go proxy) | 各 `*MirrorSyncService`(9クラス) |

これらは管理者が明示的にトリガーする、またはスケジュール実行される定期的な一括ミラー同期の実装であり、ユーザーが今アップロードしたCSVの内容とは無関係に、リポジトリが既に保持しているミラーデータを最新化するための処理です。

## 識別処理本体は外部通信能力自体を持たない

CSVアップロード後の製品識別・脆弱性調査パイプラインは、そもそも外部へHTTPリクエストを送る**物理的な手段**を持っていません。

- **レジストリ照会クラス群**(`CratesIoRegistryClient`・`NpmRegistryClient`・`PyPiRegistryClient`等、Stage1製品識別で使われる10クラス)は、いずれもローカルDBのミラーテーブルにのみ問い合わせる実装です。ライブ照会(`lookupLive`のようなHTTPを叩くメソッド)自体がコードから物理的に削除されており、`RestClient`等のフィールドやコンストラクタ引数も持ちません。
- **脆弱性データソース群**(NVD/OSV/GHSA/CVE.org/CSAF)も同様にローカルDBのみに依存します。例えばNVD CVEの照会を担う `NvdVulnerabilitySource` は、ライブAPIを叩く経路(`fetchFromNvd`)が削除された上で、`jdbcTemplate`と`transactionManager`以外のフィールドを持たず、外部通信可能な型(`RestClient`/`RestTemplate`/`WebClient`/`HttpURLConnection`/`Socket`等、およびそのサブタイプ)を一切保持しません。
- **AI(Claude LLM)呼び出し経路**も物理的に削除済みで、常に「利用不可」を返すのみです。LLMマイクロサービス自体がDocker Compose構成に存在せず(`docker-compose.yml`に`llm-service`サービス定義なし)、そのソースディレクトリ自体もリポジトリに含まれていません。

## 同期系リクエストもユーザーデータを直接参照しない

上記の同期系クラスが使うパッケージ名等の入力は、CSVの生データを直接参照するものではありません。具体的には次の2種類の合算です。

1. 管理者が明示的に登録した固定のシードリスト。
2. 本アプリが過去のジョブで自ら識別処理を行った結果として、既にDBに正規化済みの形で記録済みのパッケージ名(エコシステム名+パッケージ名のペア)。

いずれも、今アップロードされたCSVファイルそのものや、その行データ・vendor固有情報を都度そのまま外部に送信する経路ではありません。また、これらの同期処理自体は既定で無効化されており(スケジュール実行フラグはいずれもデフォルト`false`)、管理者が環境変数で明示的に有効化しない限り動作しません。

## 結論

閉域モードでCSVをアップロードし識別処理を実行した場合に発生しうる外部URLリクエストは **0件** です。外部通信が発生しうるのは、管理者が明示的に有効化した場合にのみ動く、ユーザーデータと無関係なバックグラウンド一括同期処理に限られます。

## 既存の自動テストによる裏付け

この不変条件は機械的なテストで検証されており、通常のテスト実行のたびに自動的に再検証されます。

- `ClosedModeArchitectureGateTest` — LLM連携クラス・ライブレジストリ照会・ライブOSV照会の不在、レジストリクライアント/NVD CVEデータソースが外部通信可能な型のフィールドを持たないこと、`docker-compose.yml`に`llm-service`定義が無いこと等をリフレクション・静的ファイル読み込みで検証。
- `ClosedModeBeanArchitectureGateTest` — Spring DIコンテナ上で、外部API用の`RestClient`Beanが存在しないこと、レジストリ照会Bean群が全てミラー専用であることを検証。

## 第三者による検証方法

自分の環境でこの設計を独立して確認する場合、以下の方法が使えます。

- **ネットワークトラフィックの直接観測**: バックエンドを動かしているコンテナ内で `ss`/`netstat`/`tcpdump` 等を使い、CSVアップロード〜識別処理の実行中にDB以外への接続が発生しないことを確認する。
- **アプリケーションログでの確認**: 同期系コンポーネントはそれぞれ固有のUser-Agent文字列(例: `vulncheck-server/0.1 (cpe dictionary sync)` のような、コンポーネントごとに異なる識別子)を使ってHTTPリクエストを送るため、識別処理を実行した時間帯のログにこれらの文字列が一切出現しないことを確認する。
- **設定値の確認**: 同期処理のトリガー用環境変数(例: 各種`*_SYNC_ENABLED`/`*_SCHEDULED_RESYNC_ENABLED`系)が意図せず有効化されていないことを確認する。
- **自動テストでの再現**: `<リポジトリルート>`でリポジトリ標準のテスト実行手順に沿って、以下のように対象テストのみを指定して実行する。

  ```
  mvn test -Dtest=ClosedModeArchitectureGateTest,ClosedModeBeanArchitectureGateTest
  ```
