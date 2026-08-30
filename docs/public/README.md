# 仕様書インデックス

CSV駆動の脆弱性調査Webアプリの技術仕様書。実装済みの内容を反映しており、当初の企画段階の計画とは異なる箇所（設計変更・スコープカット）がある。差分は各ドキュメント内で明示している。

- [architecture.md](./architecture.md) — 技術スタック、認証・セッション設計、ルーティング一覧、非同期処理の設計、外部API連携一覧。
- [pipeline.md](./pipeline.md) — 調査パイプラインの4段構成(Stage1製品識別〜Stage4 AI最終手段)の詳細設計、各Tier/Stageのコスト特性。
- [database-schema.md](./database-schema.md) — PostgreSQLスキーマ、Flywayマイグレーション履歴、主要テーブルの役割。
- [known-limitations.md](./known-limitations.md) — 未実装機能、意図的な設計判断(バグではないもの)、セキュリティ関連の対応状況、テスト範囲、ローカル開発用DBロールのセットアップ手順。
- [goals-and-constraints.md](./goals-and-constraints.md) — コスト・精度・スループットの3本柱の数値目標と現状の測定結果、自律タスク実行時の制約の要約。
- [nfr-status-2026-08.md](./nfr-status-2026-08.md) — 非機能要件(コスト・静的精度・スループット・テストカバレッジ・セキュリティ・デプロイ readiness・信頼性)の詳細な実測記録と経緯。
- [test-design-policy.md](./test-design-policy.md) — 検証用CSV・精度検証ジョブの設計方針(実データ限定、アドバーサリアルケースの意図的な混入等)とレビューチェックリスト。
- [stage1-golden-benchmark.md](./stage1-golden-benchmark.md) — Stage1製品識別の項目単位リグレッションゲート(JUnitゴールデンベンチマーク)の設計と運用方法。
- [name-variance-refactoring-plan.md](./name-variance-refactoring-plan.md) — 表記揺れ対応リファクタリング方針（2026-08-24、調査・実装済み）
- [batch-api-integration-plan.md](./batch-api-integration-plan.md) — Anthropic Batch API統合の検討（2026-08-25、設計のみ・未実装）
- [bundled-package-detection-plan.md](./bundled-package-detection-plan.md) — 同梱コンポーネント（Bundled Package）検出の設計案（2026-08-26、設計のみ・未実装）
- [csaf-vendor-advisory-plan.md](./csaf-vendor-advisory-plan.md) — CSAFベンダーアドバイザリー対応の設計案（2026-08-27、設計のみ・未実装）
- [ghsa-mirror-plan.md](./ghsa-mirror-plan.md) — GHSAミラー構築の設計案（2026-08-27、設計のみ・未実装）
- [osv-mirror-plan.md](./osv-mirror-plan.md) — OSV.devローカルミラー構築の設計案（2026-08-28、設計のみ・未実装）
- [infra-rollout-plan.md](./infra-rollout-plan.md) — インフラロールアウト計画（git/CI-CD/ステージング環境、2026-08-27、計画のみ・未着手）
- [ec2-deployment-guide.md](./ec2-deployment-guide.md) — EC2デプロイの実践的な手順・考慮事項（2026-08-30作成、`infra-rollout-plan.md`の内容を実行可能な形にまとめ直したもの）

各`*-plan.md`の「設計のみ・未実装」「計画のみ・未着手」等の表記はファイル自身のタイトル・冒頭注記に基づく。実装が進み記述が古くなっていないかは`known-limitations.md`と突き合わせて随時確認すること。

各ドキュメントは作成・改訂された時点のスナップショットとして書かれており、後続の改訂で数値や結論が更新されている場合はドキュメント内に追記・訂正の形で残している（数字を差し替えて経緯を消すのではなく、訂正の経緯自体を記録として残す方針）。最新の正式な指標定義・判定は`goals-and-constraints.md`を優先して参照すること。

> 本ディレクトリ（`docs/public/`）は内部設計ドキュメント（`docs/spec/`）のうち、タスク管理・稼働ログ用途のファイルを除いて公開用に整理したものです。社外秘の会社名・個人情報・実際の課金額等の内部運用の生々しい詳細は除去・一般化しています。

## 目的

ユーザーがCSV（製品名・バージョン・用途等）をアップロードすると、既知の脆弱性の有無を製品ごとに調査して返す。想定利用シーンは「これから導入するソフトウェアに、影響のある既知の脆弱性がないか事前確認する」こと。

**中核方針**: このアプリの役割は「影響のある脆弱性が存在するか否か」の二値判定であり、脆弱性の網羅的なカタログ化ではない。静的情報源（NVD/OSV/GHSA）で1件でも実在する脆弱性が見つかれば、それ以上AIによる追加調査は行わない。AI（Claude API）はコスト最優先の設計方針から、静的経路で解決できない場合の最終手段としてのみ使用する。

## 現在のステータス（2026-08-23時点）

- CSVアップロード〜結果表示のGUIフローは動作確認済み
- Stage1（製品識別）〜Stage4（AI最終手段調査）まで実装・実キーでのライブ動作確認済み
- CI/CD・本番デプロイ（EC2 + GitHub Actions想定）は未着手
