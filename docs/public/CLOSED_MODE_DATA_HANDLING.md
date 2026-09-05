# 閉域モードにおけるデータ非送信について

> **注記**: `docs/public/`配下の他の文書(特に`architecture.md`)は非閉域モード(通常)ビルドを説明しています。本文書は`closed-mode`ブランチの実装についての正本であり、他の文書とは前提が異なります。

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

これらはいずれも定期的な一括ミラー同期の実装であり、特定のCSVアップロード内容とは無関係に動作します(自動実行の契機・既定の有効/無効は同期対象によって異なるため、詳細は後述の「同期系リクエストの契機とユーザーデータとの関係」を参照してください)。

## 識別処理本体は外部通信能力自体を持たない

CSVアップロード後の製品識別・脆弱性調査パイプラインは、そもそも外部へHTTPリクエストを送る**物理的な手段**を持っていません。

- **レジストリ照会クラス群**(`CratesIoRegistryClient`・`NpmRegistryClient`・`PyPiRegistryClient`等、Stage1製品識別で使われる10クラス)は、いずれもローカルDBのミラーテーブルにのみ問い合わせる実装です。ライブ照会(`lookupLive`のようなHTTPを叩くメソッド)自体がコードから物理的に削除されており、`RestClient`等のフィールドやコンストラクタ引数も持ちません。
- **脆弱性データソース群**(NVD/OSV/GHSA/CVE.org/CSAF)も同様にローカルDBのみに依存します。例えばNVD CVEの照会を担う `NvdVulnerabilitySource` は、ライブAPIを叩く経路(`fetchFromNvd`)が削除された上で、`jdbcTemplate`と`transactionManager`以外のフィールドを持たず、外部通信可能な型(`RestClient`/`RestTemplate`/`WebClient`/`HttpURLConnection`/`Socket`等、およびそのサブタイプ)を一切保持しません。
- **AI(Claude LLM)呼び出し経路**も物理的に削除済みで、常に「利用不可」を返すのみです。LLMマイクロサービス自体がDocker Compose構成に存在せず(`docker-compose.yml`に`llm-service`サービス定義なし)、そのソースディレクトリ自体もリポジトリに含まれていません。

## 同期系リクエストの契機とユーザーデータとの関係

同期処理はいずれもCSVアップロードそのものを直接のトリガーにはしませんが、自動実行される契機・既定の有効/無効は同期対象によって異なります。ひとまとめに「全て admin opt-in」「全て起動しただけで自動発火」とは言えないため、以下のように区別します。

### 既定で無効、環境変数で明示的に有効化しない限り動かないもの

| 同期 | 有効化フラグ(既定`false`) |
| --- | --- |
| NVD CPE辞書の起動時フル同期(`CpeDictionaryBootstrapSync`) | `cpe-full-sync-on-startup`(`CPE_FULL_SYNC_ON_STARTUP`) |
| NVD CPE辞書の週次フル再同期(`CpeDictionaryScheduledResync`) | `cpe-scheduled-resync-enabled` |
| レジストリミラー(9エコシステム)の週次同期(`RegistryMirrorScheduledSync`) | `registry-mirror-scheduled-sync-enabled` |
| NVD CVEバックフィル(`NvdCveBackfillScheduledRunner`) | `nvd-cve-backfill.enabled`(`NVD_CVE_BACKFILL_ENABLED`) |

### 有効化フラグが存在せず、既定設定のまま起動しただけで発火するもの

以下3つの日次デルタ同期には有効化フラグ自体が無く、`@Scheduled`ジョブが起動時から無条件で登録されるだけでなく、同期対象のメソッド自体も呼び出された瞬間に外部へHTTPリクエストを送ります。管理者が何も設定しなくても、既定設定のまま動かしているだけで毎日自動的に発火します。

- CVE.org(`CveOrgScheduledSync` → `CveOrgSyncService#syncDelta`): 呼び出し直後に GitHub Releases API(最新リリース解決)を取得。
- CSAF Red Hat(`RedHatCsafScheduledSync` → `RedHatCsafSyncService#doSyncDelta`): baselineが未実行でも警告ログを出すのみで処理を継続し、`changes.csv`を無条件取得。
- CSAF Siemens(`SiemensCsafScheduledSync` → `SiemensCsafSyncService#doSync`): baselineの有無に関わらず`provider-metadata.json`を無条件取得。

### 有効化フラグは無いが、baseline未完了のうちは実質発火しないもの

以下2つは`@Scheduled`ジョブ自体は起動時から無条件で登録されますが、呼び出し先の`doSyncDelta`が冒頭でDB上のbaseline完了状態をチェックし、baselineが未完了なら**ネットワーク呼び出しの前に早期return**します。baselineの投入は`AdminController`経由(`/admin/ghsa/sync-baseline`・`/admin/osv/sync-baseline`)の管理者による手動トリガーのみなので、**新規インストール直後は、管理者がbaselineを手動起動するまでこの2つは外部リクエストを一切発行しません**。

- GHSA(`GhsaScheduledSync` → `GhsaSyncService#doSyncDelta`)
- OSV(`OsvScheduledSync` → `OsvSyncService#doSyncDelta`)

上記のいずれも公開されている脆弱性アドバイザリの全件差分取得であり、特定のCSVアップロード内容とは無関係です。

### レジストリミラー同期が参照するパッケージ名について

レジストリミラー同期(既定無効、上表参照)を有効化した場合、外部レジストリに問い合わせるパッケージ名は次の2種類の和集合です。

1. 管理者が明示的に登録した固定のシードリスト。
2. 本アプリが過去の全ジョブ(全ユーザー横断)で識別処理を通じて解決済みのパッケージ名(エコシステム名+パッケージ名の正規化済みペア)。

(2)は、過去にアップロードされたCSVの内容が識別処理を経て正規化されたパッケージ名という形で、外部レジストリへの問い合わせに反映される経路が実際に存在することを意味します。「CSVの内容と無関係」とまでは言えません。ただし送信されるのは正規化済みのパッケージ名単位であり、CSVの行データそのもの(バージョン・vendor名・その他の付随情報)がまとめて送信されるわけではありません。

### CPE辞書のキーワード同期(管理者による手動送信)について

`POST /admin/cpe-dictionary/sync`(`AdminController`)は、管理画面から自由記述の`keyword`パラメータを受け取り、`NvdCpeSyncService#syncByKeyword`経由でNVD CPE APIへ`keywordSearch`として送信します。`NvdCpeSyncService`自身のコメントに「keyword is the CSV-supplied product name(see AdminController's syncByKeyword)」とある通り、実運用では管理者がCSV上の製品名をそのままこのキーワードとして入力することが想定されています。

これは識別処理パイプライン自体が自動的に行うものではなく、**管理者が手動でこのエンドポイントを操作した場合に限り**発生する経路です。ただし、CSV由来の製品名が管理者の操作を介して外部へ送信されうるという点では、レジストリミラーのシード名と同種の、開示すべき経路です。

## 結論

閉域モードでCSVをアップロードし識別処理を実行した、その処理自体の中で発生しうる外部URLリクエストは **0件** です。この結論は識別処理パイプライン自体が外部通信の物理的な手段を持たないことに基づいており、バックグラウンド同期処理の設定状態には左右されません。

一方で、以下のような経路では、CSVアップロード・識別処理そのものとは別に外部通信が発生しえます。

- CVE.org/CSAF(Red Hat・Siemens)の日次デルタ同期は、有効化フラグが存在せず既定設定のまま起動しただけで自動的に外部へHTTPリクエストを送信します(公開アドバイザリの全件差分取得であり、個々のCSVアップロード内容とは無関係)。
- GHSA/OSVの日次デルタ同期も同様に無条件でスケジュール登録されますが、管理者がbaselineを手動投入するまでは実際には発火しません。
- レジストリミラー同期(既定無効)を明示的に有効化した場合は、過去のアップロード内容が識別処理を経て解決したパッケージ名が外部レジストリへの問い合わせ対象になり得ます。
- 管理者がCPE辞書のキーワード同期エンドポイントを手動操作した場合、CSV由来の製品名を含みうるキーワードがNVD CPE APIへ送信されます。

これらはいずれも「CSVをアップロードして識別処理を実行する」という操作そのものが引き起こす通信ではありません。

## 既存の自動テストによる裏付け

この不変条件は機械的なテストで検証されており、通常のテスト実行のたびに自動的に再検証されます。

- `ClosedModeArchitectureGateTest` — LLM連携クラス・ライブレジストリ照会・ライブOSV照会の不在、レジストリクライアント/NVD CVEデータソースが外部通信可能な型のフィールドを持たないこと、`docker-compose.yml`に`llm-service`定義が無いこと等をリフレクション・静的ファイル読み込みで検証。
- `ClosedModeBeanArchitectureGateTest` — Spring DIコンテナ上で、`llmServiceRestClient`・`externalApiRestClient`という名前のBeanが存在しないこと、レジストリ照会Bean群が全てミラー専用であることを検証する(同期用の`RestClient` Bean自体は`RestClientConfig`に14個定義されており存在する——このテストが検証しているのはあくまで「LLM連携用・per-item live lookup用の特定のBean名が存在しないこと」であって、「外部API用のRestClient Beanが一切存在しないこと」ではない)。

## 第三者による検証方法

自分の環境でこの設計を独立して確認する場合、以下の方法が使えます。

- **ネットワークトラフィックの直接観測**: バックエンドを動かしているコンテナ内で `ss`/`netstat`/`tcpdump` 等を使い、CSVアップロード〜識別処理の実行中にDB以外への接続が発生しないことを確認する。
- **アプリケーションログでの確認**: 同期系コンポーネントはそれぞれ固有のUser-Agent文字列(例: `vulncheck-server/0.1 (cpe dictionary sync)` のような、コンポーネントごとに異なる識別子)を使ってHTTPリクエストを送るため、識別処理を実行した時間帯のログにこれらの文字列が一切出現しないことを確認する。CVE.org/CSAF(Red Hat・Siemens)の日次デルタ同期には有効化フラグ自体が存在しないため、これらについてはこのログ確認が主な検証手段になる。
- **設定値の確認**: `cpe-full-sync-on-startup`・`cpe-scheduled-resync-enabled`・`registry-mirror-scheduled-sync-enabled`・`nvd-cve-backfill.enabled`(いずれも既定`false`)が意図せず有効化されていないことを確認する。CVE.org/CSAF(Red Hat・Siemens)には対応するフラグが無く既定のまま自動的に動作するため、これらは設定値の確認では検知できない(上のログ観測、またはネットワークトラフィックの直接観測で確認する)。GHSA/OSVもフラグは無いが、管理画面からbaseline同期を手動実行していないかどうかで判断する。
- **自動テストでの再現**: `<リポジトリルート>`でリポジトリ標準のテスト実行手順に沿って、以下のように対象テストのみを指定して実行する。

  ```
  mvn test -Dtest=ClosedModeArchitectureGateTest,ClosedModeBeanArchitectureGateTest
  ```
