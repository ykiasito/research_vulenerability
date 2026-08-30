# 同梱コンポーネント（Bundled Package）検出 設計案（2026-08-26 設計のみ・未実装）

**実装状況の要約（2026-08-30追記、`known-limitations.md`と突き合わせ）**: タイトルの「設計のみ・未実装」は執筆当時のものであり、その後実装が進んでいる——`known-limitations.md`は`BundledComponentResearchService`・CSVエクスポートの`bundled_component_findings`列・`JobCostBudgetService.reconcileBundledComponent()`など、稼働中の実装を前提とした既知の制約を複数記述している。以下の本文（設計案そのもの）は当時の検討過程の記録として変更していない。なお、`docs/spec/goals-and-constraints.md`により同梱パッケージ関連の追加改善は3本柱目標達成まで次フェーズへ明示的に先送りされている（既存実装自体は動いている）。

**本ドキュメントは設計のみ。実装コードは一切含まない。**

対象は、製品のパッケージマネージャ依存関係としては一切見えず、**製品自身の公式リリースノート/チェンジログにしか記載がない同梱コンポーネント**（例: あるデスクトップアプリのリリースノートに「同梱の7-Zipを26.02に更新」とだけ書かれているが、そのアプリ自体は7-Zipをパッケージマネージャの依存関係として持たない）の脆弱性を検出する機能である。旧称「Stage 3.5」。

過去の調査（`project_ai_cost_target`メモリ「Still open」節、2026-08-25）が既にあり、素朴設計（チェンジログ本文をCVE/GHSA IDの正規表現でスキャンしOSVで検証）は実例で失敗することが確認済みである。本ドキュメントはその結論を現行コード（2026-08-26時点、5ラウンドの精度検証スレッド完了後）に対して再検証し、具体的なアーキテクチャに落とし込む。

---

## 0. 前提（既存調査の要約と、その後の検証状況）

`project_ai_cost_target`メモリからの引用（原文ママ）:

> Original plan (regex-scan changelog text for CVE/GHSA IDs, validate against OSV) was tested against a real user-provided example (Chocolatey CLI ~4.6.0 bundling 7-Zip) and failed on both ends: real release-note text has no formal ID to regex for (just "Update bundled 7zip executables to 26.02"), and Chocolatey CLI itself isn't identifiable by Stage1 at all (not in any of the 10 registries, no NVD CPE entry). Revised design (not yet built): **LLM extracts only `(component, version)` pairs from changelog text — never a CVE ID directly — and OSV alone adjudicates whether that pair is vulnerable.**

この「OSV alone」という前提は、本ドキュメント作成時に**実測で誤りだと判明した**（§3-1で詳述）。また、「Stage1がそもそも識別できない製品には本機能は原理的に乗らない」というシーケンシング依存の指摘自体は本ドキュメント作成時点（2026-08-26初版）では未解消だったが、**その後`ChocolateyRegistryClient`のデプロイにより、"非レジストリ識別の手段が何も無い"という一般的な形では解消した**（§0-2で2026-08-26に再検証・更新。flagship例1件の誤ID解決という狭い課題は残るが、対象母集団は実測で非ゼロと確認済み）。

### 0-1. この2日間で変わったこと（5ラウンド精度検証スレッド、jobs 35-39）

`docs/spec/stage1-golden-benchmark.md`・`docs/spec/name-variance-refactoring-plan.md`の通り、2026-08-25〜26にかけてStage1の**CPE辞書・レジストリ照合の精度**が大きく改善された（ベンダー語汚染除去、バージョン重複排除、非対称containment判定、`target_sw`ゲート、弱いレジストリ一致の棄却規則、30ケースのゴールデンベンチマークによる回帰防止）。これらは**すでにレジストリまたはCPE辞書に存在する製品を正しく引き当てる精度**の改善であり、**そもそもレジストリにもCPE辞書にも存在しない製品を新たに識別可能にするものではない**。

### 0-2. 前提の再々検証（2026-08-26追記: `ChocolateyRegistryClient`デプロイ後の実測）

`project_three_pillar_targets`メモリは2026-08-25時点で「非レジストリ製品の識別（winget/Chocolateyコミュニティフィード/ベンダー自身のフィード）を、Stage 3.5より先に優先すべき」と明記していた。**本節の初版（下記グレップ結果の時点）ではこれが未着手だったが、その後`ChocolateyRegistryClient`（`ChocolateyRegistryClient.java`、Chocolateyコミュニティフィード`community.chocolatey.org/api/v2/`照合、Tier1の11個目のレジストリとしてデプロイ済み）が実装・デプロイされ、job 40（400件）で識別数が368→387に改善した（未識別13件、大半はChocolateyにも実在しない製品）。** これはまさに本節初版が「本機能より先に着手すべき」と指摘していた作業そのものであり、以下はそのデプロイ後の再検証結果である。

**(a) flagship例（Chocolatey CLI自体）は依然として未解決——ただしこれまでの「識別手段が何も無い」ではなく、狭い「誤ID」問題に縮小した。** `ChocolateyRegistryClient`の素朴な正規化（小文字化＋空白→ハイフン）は"Chocolatey CLI"を候補ID`chocolatey-cli`に変換するが、実在のパッケージIDは`chocolatey`（サフィックスなし）である。ライブ照合で確認した:

```
curl "https://community.chocolatey.org/api/v2/Packages(Id='chocolatey-cli',Version='4.6.0')"  → HTTP 404（完全一致キー照合、非2xx）
curl "https://community.chocolatey.org/api/v2/FindPackagesById()?id='chocolatey-cli'&$select=Version" → <entry>要素0件（存在確認フォールバックも空振り＝IDが存在しない）
curl "https://community.chocolatey.org/api/v2/FindPackagesById()?id='chocolatey'&$select=Version"     → <entry>要素40件（実IDは存在する）
```

これは`ChocolateyRegistryClient`のクラスJavadoc（`ChocolateyRegistryClient.java:94-99`）が明示的に「対象外」としているケースそのものである——ラウンド4で実装された存在確認フォールバック（`FindPackagesById()`）は「正しいIDだがバージョンが違う」ケースを救うためのものであり、「そもそもIDが間違っている」ケース（`chocolatey-cli`のような誤IDも同様に404/空振りする）は救えない。誤ID解決には`Search()`ベースのファジーID解決という**別の、まだ実装されていない**フォローアップが必要（Javadocが明記）。**したがってflagship例そのものは、現行デプロイ済みクライアントでは今も回収できない。**

**(b) しかし、flagship例1件の成否より重要なのは母集団の大きさであり、これは今回はじめて非ゼロで測定できた。** job 40で`ecosystem='chocolatey'`として識別された89件のうち、Stage2（静的ソース: nvd/nvd_keyword/osv/ghsa/cve_org）の発見件数が0件——すなわち§5推奨の発火条件(B)のもとで実際にこの新機能のトリガー対象になる件数——は**41件（89件中46%）**だった（`job_item_vulnerabilities`を`discovered_via_tier <> 'llm_web_search'`で絞ったEXISTS判定、job=40実測）。

```sql
-- job 40, ecosystem='chocolatey'で識別済み: 89件
-- うちStage2発見件数=0（§5オプションBの発火条件を満たす）: 41件
```

**結論（本節の更新）**: 「Stage1が識別できない製品には本機能が原理的に乗らない」というシーケンシング上の障害は、**"非レジストリ識別の手段が何も無い"という一般的な形では2026-08-26時点で解消済み**（Chocolateyフィードが稼働し、実測で46%の該当母集団を生んでいる）。残っているのは**flagship例1件（Chocolatey CLI）の誤ID解決という狭い個別課題**であり、これは本機能全体の実装可否を左右するブロッカーではなくなった——母集団はすでに非ゼロかつ小さくない規模で存在する。この評価の更新は§7の優先順位にも反映する。

---

## 1. 現状アーキテクチャの要約（コード引用）

### 1-1. Stage1の識別フロー

`Stage1IdentificationService#identify`（`Stage1IdentificationService.java:184-219`）: ローカルCPE辞書照合（`localCpeLookup`、DB完結）とレジストリ照合（`resolveRegistryMatch`、10エコシステムへのライブHTTP）を並行実行し、両方とも空振りの場合のみTier3（`tryTier3`、`:241-`、LLM+web_search）へフォールバックする。Tier3は「マーケットプレイス表示名→公式名」の解決を試みるだけで、**元々どの構造化ソースにも存在しない製品（Chocolatey CLI等）を新たに発見する手段は持たない**——web_searchで公式名がわかっても、その公式名でTier1を再照会して初めて空振りが解消する設計であり、再照会先の10レジストリ/CPE辞書に元々無ければ結局失敗する。

識別結果は`identified_products`（1アイテムにつき最大1行、`IdentifiedProduct.java`）に`ecosystem`/`packageName`/`cpe`のいずれかまたは両方として保存される。

### 1-2. Stage4の現在のフォールバックフロー

`Stage4WebSearchResearchService.research`（`Stage4WebSearchResearchService.java:51-83`）が唯一のAI+web_search脆弱性調査パスで、2箇所から呼ばれる（`ResearchJobProcessingService.java:264-271`のヒントベース呼び出し、`:326-333`のecosystem/packageNameベース呼び出し）。**重要な事実**: `llm-service/main.py`の`web_search_research`エンドポイント（`main.py:429-434`, `459-462`）は現在も

```python
"identifier": {"type": "string", "description": "CVE/GHSA ID if known, otherwise a short descriptive identifier."}
```

という形で**LLM自身にCVE/GHSA IDを直接生成させている**。`Stage4WebSearchResearchService.scopedId`（`:85-93`）は`CVE-\d{4}-\d+`/`GHSA-...`の形式チェックのみ行い、**そのIDが実在するかどうかは一切検証しない**——形式が正しければそのままグローバルユニークキーとして`vulnerabilities`テーブルに書き込まれる。これが`project_ai_cost_target`メモリの言う「42件監査中の偽陽性4件は全てLLMがCVE IDを捏造したケース」の直接の原因コードであり、本機能の設計原則（LLMにCVE IDを生成させない）は**Stage4の既存パスにもまだ適用されていない**。

### 1-3. 脆弱性の永続化経路

`VulnerabilityRepository#upsertAndGetId`（`vulnerabilities`テーブルへupsert、`cve_or_ghsa_id`がユニークキー）→`JobItemVulnerabilityRepository#linkIfAbsent`（`job_item_vulnerabilities`へのN:M紐付け、主キー`(job_item_id, vulnerability_id)`）という2段階（`Stage4WebSearchResearchService.java:73-75`が実例）。

`vulnerabilities.source`（V1マイグレーション、`vulnerabilities`テーブル定義）は**CHECK制約のない自由文字列**（VARCHAR(50)）——`database-schema.md`は運用上の値を`nvd`/`osv`/`ghsa`/`llm_web_search`と記載しているが、これは規約であってDB制約ではない。**新しい`source`値（例: `bundled_component`）の追加にマイグレーションは不要**。

一方`job_item_vulnerabilities`（V1）は`job_item_id`/`vulnerability_id`/`discovered_via_tier`/`citation_url`のみで、**「このCVEはどの同梱コンポーネントに属するか」を表現する列が存在しない**。これは§4-4で扱う表示上の課題に直結する。

---

## 2. リリースノート/チェンジログの発見方法

これは未解決の実問題であり、本節はその実現可能性を現行コードとエコシステム特性に照らして評価する。

### 2-1. 対象製品クラス別の現実性

| ソース | 対象 | 現実性 |
|---|---|---|
| GitHub Releases API（`/repos/{owner}/{repo}/releases/tags/{version}`） | GitHubホストされたOSSプロジェクト | 技術的には無料・構造化。ただし**製品の GitHub リポジトリURLを知っている必要があり、現行コードはそれを一切保持していない**（§2-2）。無認証60req/hourの壁は本プロジェクトが既に2度実害を受けた制約（GHSA、`project_vuln_research_server`メモリ）と同一で、per-item呼び出しにすると同じ問題が再発する。 |
| パッケージレジストリ自身のchangelogフィールド | npm/PyPI等でメタデータに`repository`/`changelog`URLを持つ場合がある | レジストリで識別できる製品は、そもそも「パッケージマネージャ依存関係として見える」側であり、**本機能が対象とする「同梱されていて依存関係として見えない」製品の定義から外れることが多い**（同梱物自体はレジストリパッケージではない）。 |
| ベンダー自身の公式チェンジログページ | 全般 | URLパターンが製品ごとに異なり、統一APIがない。ハードコード表は`name-variance-refactoring-plan.md`が明示的に否定してきた設計（「一般化できない不規則ケースの表」は最後の手段、本件は最初からその表になってしまう）。 |
| LLM web_search（Tier3/Stage4と同型） | 全般（フォールバック） | 確実に動くが、Stage4と同等以上のコスト（web_search 1回あたり$0.01の従量課金）が**製品特定のたびに**発生する。 |

### 2-2. 具体的なギャップ: リポジトリURLはどこにも保存されていない

`NpmRegistryClient.java`を確認したところ、`repository`/`homepage`フィールドへの参照は**ゼロ**（`grep`該当なし）。他の9レジストリクライアントも同様の実装パターン（パッケージ名・バージョン確認のみ）と推測される。つまりGitHub Releases APIルートを使うには、まず**全レジストリクライアントに`repository`URL抽出を追加する**という、それ自体が独立した実装コストを持つ前提作業が必要になる。

### 2-3. 結論

**構造化・無料で解決できるのは「レジストリ経由で識別でき、かつそのリポジトリがGitHubにある」という限定的な部分集合のみ**であり、しかもその部分集合は本機能が主眼とする「同梱されていて依存関係に出てこない」ケースとは重なりが薄い。本機能の主眼（Chocolatey CLI的な、非レジストリ・非CPEのデスクトップ配布物）に対しては、**チェンジログの発見自体に少なくとも1回のLLM web_search呼び出しが必要**というのが現実的な結論である。これは§5のコスト試算・スコープ判断に直接影響する。

---

## 3. `(component, version)` 抽出 + 検証パイプライン

### 3-1. 【最重要の修正】 「OSV単独で裁定」は実測で不十分と判明

過去メモリの結論「OSV alone adjudicates」を、flagship例そのもの（7-Zip 26.02）で実際に検証した。

**事実1**: NVD CPE辞書には7-Zipの正確なバージョン行が実在する。

```sql
SELECT vendor, product, cpe_string FROM cpe_dictionary WHERE product ILIKE '%7-zip%';
 7-zip | 7-zip | cpe:2.3:a:7-zip:7-zip:26.02:*:*:*:*:*:*:*   ← 完全一致
 7-zip | 7-zip | cpe:2.3:a:7-zip:7-zip:26.01:*:*:*:*:*:*:*
 ...
```

**事実2**: OSV.dev API（`https://api.osv.dev/v1/query`）を実際に叩くと、7-Zipは**エコシステムを持たないため空振り**する（実測、HTTP 200・`{}`）。

```
curl -X POST https://api.osv.dev/v1/query -d '{"version":"26.02","package":{"name":"7-zip"}}'
 → 200 {}
```

一方、既存Stage2が使う正規のエコシステム+パッケージ名（例: Maven `log4j-core`）では同じAPIが正常に実データを返すことを確認済み（APIそのものは正常）。**OSVのクエリは`package.ecosystem`必須で、`npm`/`PyPI`/`Maven`等14種類の登録エコシステムの外側には汎用の"CPEクエリ"や"名前だけクエリ"が存在しない。** 7-Zipのようなネイティブ実行ファイル配布物（パッケージレジストリに存在しない）はOSVのカバレッジモデルの外側にある。

**結論**: 同梱コンポーネントの典型例（OS/デスクトップ向けのネイティブバイナリ、例: 7-Zip・OpenSSL・zlib・curl等）はほぼ全てOSVの14エコシステムに属さない。**OSVだけを裁定源にすると、本機能が最初に想定していた実例そのものを検出できない。** 代わりにこれらはNVD CPE辞書側（`cpe:2.3:a:7-zip:7-zip:...`）に実体を持つ確率がはるかに高い——これは偶然ではなく、CPE辞書がOS/デスクトップソフトウェア全般を対象にしているのに対し、OSVはOSSパッケージエコシステムを対象にしているという、両ソースの設計上の守備範囲の違いによる。

**設計変更**: 「OSV単独」ではなく、**OSVとNVD CPE辞書の両方を裁定源とし、抽出された`component`の性質に応じてどちらか（または両方）を使う**。幸い、この2つ目の経路（CPE照合→NVD CVE API）は**既存コードがほぼそのまま転用できる**——`NvdVulnerabilitySource.fetchFromNvd`（`NvdVulnerabilitySource.java:60-99`）は既に「vendor:product+厳密バージョンでNVD CVE APIを呼ぶ」ロジックを持っており、CPE文字列の組み立ても`CpeUtils.buildCpe`を再利用できる。新規に必要なのは「抽出された自由文字列の`component`名から、`Stage1IdentificationService.localCpeLookup`相当のtrigram照合でCPE辞書のvendor:productを引く」処理のみ（これも既存の`CpeDictionaryRepositoryCustom`をそのまま呼べる）。

### 3-2. LLM抽出プロンプトの形状（設計）

Tier2の`disambiguate`と同型（候補選択のみ、新規IDや新規事実の生成をさせない）に倣うのではなく、これは「自由記述テキストからの構造化事実抽出」であるため、Tier3/Stage4の`web_search_identify`寄りの形状になる。**web_searchツールは付けない**（チェンジログ本文は既にリリースノート発見ステップで取得済みのテキストとして渡す設計とし、抽出ステップ自体はテキスト理解のみで完結させる——コストを抑える主要因の一つ）。

想定リクエスト（`llm-service/main.py`の既存パターンに倣うJSON Schema出力）:

```
入力: changelog_text（発見ステップで取得した生テキスト、または該当バージョンの差分セクションのみ）
出力スキーマ:
{
  "bundled_components": [
    { "component_name": string, "version": string, "confidence": "high"|"low" }
  ]
}
```

システムプロンプトで明示すべき制約（Stage4の既存プロンプトが持たない、本機能固有の禁止事項）:
- **CVE/GHSA/セキュリティ用語は一切出力させない。** `component_name`と`version`という平文の事実のみを抽出させ、「これは脆弱性修正か」の判断そのものをさせない——判断はOSV/CPE照合が行う。
- 「バージョン番号ではないもの」（"latest", "stable", ビルド番号のみ等）は`version`に含めず除外させる——これがないと事実上の空文字列や不正確な文字列がOSV/NVDクエリに渡り、無意味な空振りクエリを大量発生させる。
- 抽出できるものが無ければ空配列を返させる（Stage4の"findings=空でよい"と同じ、無理に埋めさせない）。

### 3-3. 抽出結果に対する検証（LLM出力を信用する前のガード）

Tier3の`ecosystem_candidates`が「バックエンドが実レジストリに再照会して初めて信用する」設計（`main.py:360-361`のコメント通り）であるのと同じ二重検証パターンを踏襲する:

1. `component_name`が空白のみ/極端に長い（Stage4の`MAX_ID_LENGTH`相当の上限）場合は棄却。
2. `version`が既存の`ResearchJobItem.version`と完全一致する場合（＝製品自身のバージョンを"同梱コンポーネント"として誤抽出したケース）は棄却——実際に起きやすい誤りとして明示的にガードする価値がある。
3. 各`(component_name, version)`につき、CPE辞書に対する軽量trigram照合（`Stage1IdentificationService`の`localCpeLookup`と同じ関数を再利用、DB完結・追加コストなし）を試み、ヒットすればNVD CVE API照会（§3-1）。ヒットしなければOSVの14エコシステムそれぞれへの総当たりは非現実的なので、**コンポーネント名がいずれかのエコシステムの命名規則に明らかに合致する場合のみ**（例: `@scope/pkg`形式ならnpm、`group:artifact`形式ならMaven）その1エコシステムに絞ってOSVを試す。どちらにも当たらなければ「裁定不能」として記録し、脆弱性ありともなしとも判定しない（Stage4のように「見つからなければfindings空」と同じ扱い——見つからない＝安全ではなく、単に確認できなかったという扱いにする、既存の`researchIncompleteReason`の思想と一貫させるべき、§7）。

### 3-4. ユーザーへの見せ方（帰属の明示）

§1-3の通り、`job_item_vulnerabilities`には「どのコンポーネント由来か」を表す列が無い。2案:

- **案A（推奨）**: `job_item_vulnerabilities`に`bundled_component_name VARCHAR(255) NULL`/`bundled_component_version VARCHAR(100) NULL`を追加するマイグレーション（次番はV14）。NULLなら「製品自身の脆弱性」、非NULLなら「同梱コンポーネント経由」——`jobs/detail.html`側は`th:if="${vuln.bundledComponentName != null}"`で分岐し、「⚠ 同梱コンポーネント `7-Zip 26.02` 経由の脆弱性です」のような注記を追加できる。既存の`[discoveredViaTier]`タグ表示（`jobs/detail.html:103`）の隣に置くだけで済み、テーブル構造自体は変えない。
- **案B（マイグレーション不要）**: `vulnerabilities.description`の先頭に`[bundled: 7-Zip 26.02] `のような接頭辞を機械的に付与し、`source`を`bundled_component`にする。実装コストは最小だが、UIが「構造化された注記」ではなく「本文への文字列埋め込み」に依存するため、将来UIを整形したくなった時に文字列パースが必要になる——場当たり的。

**推奨は案A。** 理由: `vulnerabilities`テーブルはグローバルマスタ（同一CVEが複数アイテムから参照されうる）なので、"どのコンポーネント経由か"という情報はアイテム×脆弱性の組ごとに異なりうる（同じCVEが別アイテムでは"製品自身の脆弱性"としてヒットする可能性もある）——この情報は本質的に`job_item_vulnerabilities`（中間テーブル）に属し、`vulnerabilities`側に置くのは意味的に誤り。

---

## 4. コスト試算（$5/1,000件目標との突き合わせ）

`JobCostBudgetService.java:37`の現行上限は`$0.005/item`（`COST_CAP_PER_ITEM_USD`）。既存のTier2/Tier3/Stage4見積もり単価（同ファイル`:61-63`）: Tier2 $0.003、Tier3 $0.03、Stage4 $0.015。

本機能が追加するLLM呼び出しは最大2種類:

| 呼び出し | 内容 | web_search | 見積もり単価（既存単価の算出方法に倣う） |
|---|---|---|---|
| リリースノート発見 | §2の結論通り、非レジストリ製品には概ねweb_search必須 | あり（Stage4と同型、max_uses想定1） | Stage4と同額程度 **$0.015** |
| `(component, version)`抽出 | §3-2、web_searchなし、テキスト理解のみ | なし | Tier2と同程度かそれ以下（入力トークンはchangelog本文の長さ次第で変動するため、Tier2の$0.003より若干高く見積もるのが安全 — **$0.005**程度） |
| OSV/CPE照合 | 既存Stage2パターンの再利用、外部無料API＋ローカルDB | なし（LLM呼び出しではない） | **$0**（Tier2/Stage4と同じく、この段はコストに乗らない） |

**合計、1アイテムあたり本機能がフル発火した場合の追加コスト: 約$0.02**——これは既存のStage4単体（$0.015）を上回り、**現行の$5/1,000件キャップの4倍**に相当する。全アイテムに無条件発火させると、キャップ内には到底収まらない。

もし§5の推奨通り「Stage2が0件だった識別済みアイテムのみ」に絞ったとしても、既存のStage4がまさに同じ条件（Stage2=0件かつ信頼度>0.85）で発火する設計であり、**Stage4とほぼ同じ母集団に対してさらに$0.02/件を上乗せする**ことになる。`project_ai_cost_target`メモリの実測（fix前ベースラインでStage4だけで支出の79%）を踏まえると、Stage4に匹敵する規模の呼び出しをもう1段追加することは、既存の$5/1,000目標の再達成を危うくする規模のインパクトである。

**結論**: 本機能は既存の$5/1,000件キャップの中には収まらない。§5でスコープを絞ってもなお、**本機能専用の別枠予算（例: オプトインジョブのみ、あるいは既存キャップとは別に上限を設ける）が必要**——これは`batch-api-integration-plan.md`が`JobCostBudgetService`の永続化について指摘した論点（§6-1、選択肢α/β）と同種の、実装前にシニアレビューで判断すべき事項として扱うべきである（§7）。

---

## 5. スコープ判断: どの条件で発火させるか

選択肢を検討する。

- **(A) 全アイテム無条件発火**: §4の通りコスト的に論外。**却下**。
- **(B) Stage2が0件だったアイテムのみ（Stage4と同じ発火条件）**: 一見自然だが、これは**論理的に不完全**——同梱コンポーネントの脆弱性は、製品自身の脆弱性とは独立した別の攻撃対象面である。Stage2で製品自身のCVEが1件でも見つかったアイテムでも、同梱コンポーネント側は無関係に脆弱でありうる（7-Zipの脆弱性はChocolatey CLI自身の脆弱性の有無と無関係）。「1件でも見つかれば十分」という本アプリの中核方針（`docs/spec/README.md:14`「静的情報源で1件でも実在する脆弱性が見つかれば、それ以上AIによる追加調査は行わない」）は、**製品自身の脆弱性についての方針であり、同梱コンポーネントという別軸にそのまま適用してよい保証がない**——ただし、この中核方針自体を本機能のためだけに見直すのはスコープが大きすぎる。
- **(C) 識別済み（IDENTIFIED）アイテットのうち、非レジストリ・非CPE（＝ヒントのみ、あるいはUNIDENTIFIED）を除いた全件**: Stage2の結果に関わらず発火。(B)の論理的不完全性は解消するが、母集団が最も大きく、§4のコスト試算がほぼそのまま両面（発火率100%近く）に効いてくる——最もコストが高い選択肢。
- **(D) 製品タイプで絞る（デスクトップインストーラ/ネイティブアプリのみ、ライブラリ/純粋パッケージは除外）**: 直感的には正しい絞り込み（バンドルが起きるのはインストーラ型配布物であり、`npm install`で入る1ライブラリが別のネイティブバイナリを同梱することは稀）。しかし**現行スキーマに「製品タイプ」を表す列が存在しない**——`identified_products`の`ecosystem`がnull（＝レジストリ非該当）であることを代理指標にはできるが、これは「非レジストリ＝デスクトップアプリ」という決めつけであり誤差を伴う（CPEのみで識別された正規のOSSデスクトップアプリと、まだ識別手段のない非レジストリ製品を区別できない）。

**推奨: (B)をベースに、コスト予算が許す場合のみ(C)へ拡張するオプトイン。** 理由:

1. §4の通り本機能はStage4と同等以上のコストを持つ。**Stage4がすでに「Stage2=0件」でしか発火しない設計に絞られている**のは、まさに同じコスト制約（$5/1,000件）の結果である。同じ制約下にある以上、本機能をStage4よりゆるい条件（C）で発火させる根拠は薄い。
2. (B)の論理的不完全性（Stage2で製品自身のCVEが1件見つかった場合に同梱コンポーネントを見逃す）は実害として小さい可能性が高い——**Stage2で既に1件でも見つかっている製品は、そもそもユーザーへの警告としては「導入を再検討すべき」という結論が既に出ている**。同梱コンポーネント側の追加検出が無くても、意思決定としての実害は「もう1つの理由が増えるかどうか」程度に留まる。逆にStage2が0件（＝製品自身は安全に見える）の場合こそ、ユーザーが安心して導入判断を下しかねない場面であり、同梱コンポーネント側の見落としリスクが最も高い。
3. §2の結論（発見自体にweb_searchが要る）と合わせると、本機能は実質的に**「Stage4を発火させたが何も見つからなかった」直後に、同じ製品に対してもう一段掘る**という位置づけになる。Stage4の呼び出し1回の中でリリースノート発見も同時に行えないか（web_searchの結果を使い回せないか）は実装時に検討する価値がある最適化だが、Stage4のプロンプト（脆弱性を直接探させる）と本機能のプロンプト（`(component, version)`だけを抽出させる）は目的が異なるため、単純な使い回しはできない——検索クエリ自体は近いので、**Stage4のリクエストに「ついでにbundled component情報があれば教えて」という項目を追加する拡張**は、独立した新規呼び出しを1本追加するより安く済む可能性があり、実装時に検討すべき選択肢として残す（§7）。

(D)の製品タイプ絞り込みは、現行スキーマでは正確に実現できないため今回は採用しないが、**将来的にStage1が製品タイプを推定できるようになった場合**（例えばTier3のプロンプトに軽微な追加で「インストーラ型かライブラリ型か」を推定させる）、(B)にさらに重ねるフィルタとして有効——現時点では見送り、`still open`に記載する。

---

## 6. 位置づけ: Stage4全体に適用する共有バリデータとして

過去メモリの指摘（「Stage4の既存web_searchフォールバックにも同じパターンを適用すべき」）は、§1-2で確認した通り**現在も未着手**であり、本機能実装の必須前提ではないが、同時に着手する価値が高い。理由:

- `Stage4WebSearchResearchService.scopedId`は今も形式チェックのみでCVE IDの実在を検証していない（§1-2）——本機能が導入する「OSV/CPE裁定を経ないCVE IDは信用しない」というガードを、共有関数として切り出し（例: `VulnIdentifierValidator`のような新規コンポーネント）、Stage4の既存パスと本機能の両方から呼べる形にするのが筋が良い。
- ただし、Stage4の現行プロンプトはLLMに直接「CVE IDを含む脆弱性を報告させる」形状（`main.py:459-462`）であり、これを「`(component, version)`だけ返させる」形状に変えるのは、**本機能とは独立したプロンプト再設計**を要する——スコープが本機能の実装作業自体より大きくなる可能性があるため、**本機能の実装スコープには含めず、後続タスクとして明示的に切り出す**ことを推奨する。

---

## 7. 未解決 / 未決定事項

優先度順。

1. **（優先度、2026-08-26更新: ブロッカー解消・降格）Stage1の非レジストリ識別は`ChocolateyRegistryClient`デプロイにより実用段階に到達した。** §0-2で再実測した通り、本機能のflagship例（Chocolatey CLI自体）は素朴な正規化の誤ID（`chocolatey-cli`≠実ID`chocolatey`）により今も個別には未回収だが、これは`Search()`ベースのファジーID解決という**限定的なフォローアップ課題**に縮小しており、本機能全体の着手可否を左右するブロッカーではない。より重要な実測として、job 40で`ecosystem='chocolatey'`識別済み89件中41件（46%）がStage2発見件数0件——§5推奨の発火条件(B)の対象母集団として**すでに非ゼロかつ相応の規模で存在する**ことを確認した。**この項目はもはや最優先ブロッカーではない**——本機能に着手する前に必須だった「対象母集団が存在するか」という確認は、今回のjob 40実測で肯定的に解決済み。ユーザー/シニアレビューへの確認事項としては「着手するか」ではなく「(a)flagship例の誤ID解決（`Search()`フォールバック）を本機能に先行させるか並行させるか、(b)41/89件という母集団規模で§4のコスト試算・別枠予算の必要性判断（優先度2）を実施するか」に変わる。
2. **専用コスト予算の設計。** §4の通り本機能は既存$5/1,000件キャップに収まらない。オプトイン化・別枠予算・(B)へのさらなる絞り込みのいずれか（または組み合わせ）が必要——`batch-api-integration-plan.md`の`JobCostBudgetService`永続化論点（§6-1、選択肢α/β）と合流しうる判断であり、両機能が実装フェーズで衝突しないよう、着手順序も含めて判断が必要。
3. **リリースノート発見の実現方式が未確定。** §2の通り、GitHub Releases API経由は現行スキーマの拡張（レジストリクライアントへの`repository`URL抽出追加）を要し、かつ本機能の主眼母集団との重なりが薄い。ベンダー自身のチェンジログページは統一的な発見手段がなく、実質web_search頼みにならざるを得ない——この結論自体をシニアレビューで確認したい。
4. **チェンジログが長すぎる/複雑な場合の扱い。** 1回のLLM呼び出しに収まらない長大なリリースノート（例: メジャーアップデートのまとめページ、数十バージョン分の差分）にどう対処するか未検討。該当バージョンのセクションだけを事前に抽出するテキスト処理が必要になる可能性があるが、その抽出自体の精度は未検証。
5. **リリースノートが全く見つからない製品の扱い。** 「確認できなかった」を`researchIncompleteReason`の第3の理由コードとして表現するか、単に「同梱コンポーネント側は未検査」という別軸の状態として持つか、スキーマ上の設計が未定。
6. **アイテムレベルのUI表現。** §3-4で案Aを推奨したが、`jobs/detail.html`側の具体的なUIコピー（日本語の注記文言、警告アイコンの要否等）は未設計。
7. **Stage4本体への同型バリデータ適用（§6）は、本機能とスコープを分離するか同時に行うか。** 分離を推奨したが、この判断自体も確認事項として残す。
8. **Stage4リクエストへの相乗り最適化（§5末尾）の実現可能性。** web_searchクエリを共有できれば呼び出し1本分のコストを節約できるが、プロンプト設計・レスポンススキーマの両立が可能かは未検証。

---

## まとめ: 最も判断を仰ぎたい論点（2026-08-26更新）

本ドキュメント初版が最も重く扱っていた発見——**flagship例（Chocolatey CLI）がStage1で識別不能であり、シーケンシング上のブロッカーだ**という指摘——は、その後`ChocolateyRegistryClient`のデプロイと本節の再検証（§0-2）により**実質的に解消した**。flagship例1件は正規化の誤ID（`chocolatey-cli`≠実ID`chocolatey`）により今も個別には未回収だが、これは`Search()`ベースのファジーID解決という限定的なフォローアップ課題であり、母集団全体の存否とは別問題である。実測（job 40、`ecosystem='chocolatey'`識別済み89件中41件がStage2発見件数0件）により、**§5推奨の発火条件(B)のもとで本機能が実際にトリガーされる対象は、すでに非ゼロかつ小さくない規模（46%）で存在する**ことが確認できた。

したがって、最初に判断を仰ぎたい論点は「本機能に着手すべきか（優先順位の再確認）」から、「§4のコスト試算・別枠予算の判断をどう進めるか」（§7優先度2）と「flagship例個別の誤ID解決（`Search()`フォローアップ）を本機能の実装と同時に行うか、後回しにするか」の2点に変わった。§3-1（NVD/CPE併用の裁定設計）・§5（発火条件(B)＋(C)へのオプトイン拡張という推奨）・§6（Stage4向け共有バリデータの切り出しは別スコープとする判断）は、いずれも今回の再検証と独立であり、そのまま実装の出発点として有効である。
