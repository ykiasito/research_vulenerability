# 表記揺れ対応 リファクタリング方針(2026-08-24 調査・実装)

観点は2つ。**(1) 精度**、**(2) 外部APIを叩かずローカル完結**(データ取得は60GBまで許容)。

---

## 1. 調査サマリ

ジョブ30(1,000件)/ ジョブ31(350件)の実データを解析した結果、**表記揺れ対応の失敗は「あいまい検索の精度不足」ではなく、3つの構造的欠陥**であることが判明した。いずれも実測値で裏付けている。

未識別40件の内訳を見ると、**そのほとんどがNVDに確実にCPEが存在する有名製品**だった:
Apache HTTP Server / ImageMagick / TeamViewer / Microsoft Teams / LibreOffice / Docker Desktop /
VMware Workstation Player / OBS Studio / Cisco AnyConnect / Citrix Workspace / Sublime Text / Paint.NET ほか。

つまり「見つけられないはずのないものを取りこぼしていた」。

---

## 2. 根本原因(実測値付き)

### 原因1: ベンダー語によるクエリ汚染 【最重要・修正済み】

`localCpeLookup()` は検索クエリを `vendor + " " + productName` で組み立てていた。
このためベンダー語がスコアを支配し、**本来の製品が候補枠から押し出されていた**。

実測(クエリ = `"Amazon Web Services TeamViewer"`):

| 候補 | trigramスコア |
|---|---|
| `amazon_web_services_aws-c-io` | **0.51** |
| `amazon_web_services_freertos` | **0.50** |
| `teamviewer`(正解) | 0.35 |

候補上限が3件だったため、正解の `teamviewer` は**一度も候補に上がらず**未識別で終わっていた。
TeamViewerは辞書に存在していたにもかかわらず、である。Microsoft Teams なども同一原因。

> なお、CSVのベンダー欄が汚れているのはテストデータ生成の都合だが、**実運用でも同じ壊れ方をする**。
> 実際のCSVではベンダー欄が空・誤記・販社名・親会社名であることが普通にあり、
> 「ベンダーを埋めるほど精度が下がる」という逆インセンティブが生じていた。

### 原因2: バージョン重複行が候補枠を食い潰す 【修正済み】

CPE辞書は**バージョンごとに1行**を持つ。NVD実データで計測すると:

- 全 1,815,743 行のうち **72.7% が同一製品のバージョン違い**
- ユニークな `vendor:product` は約 **495,697**
- TeamViewer 単体で数十行を占有

候補上限3件に対し、1製品が枠を占領しうる構造だった。

### 原因3: CPE辞書が 0.1% しか同期されていない 【解消済み(2026-08-24 深夜に全件同期完了)】

| | 件数 |
|---|---|
| ローカル `cpe_dictionary`(修正前) | **1,791** |
| ローカル `cpe_dictionary`(全件同期後) | **1,815,263** |
| NVD 全体 | 1,815,743 |

全件同期の実績: **103分 / DB 692MB**(`cpe_dictionary` 単体)、DB全体で1,669MB。
同期後、昨夜取りこぼしていた製品はほぼすべて辞書上に存在することを確認:
ImageMagick 2,877件 / TeamViewer 155件 / LibreOffice 2,146件 / Sublime Text 218件 /
VMware Workstation Player 780件 / Apache HTTP Server 28,923件。

> **訂正(2026-08-25)**: 当初ここに「OBS Studio 3,421件」と記載したが、これは `%studio%` に
> 一致した件数であり、OBS Studio 自体ではなかった。厳密に確認したところ
> **OBS Studio はNVDに一件も存在しない**(`product ILIKE '%obs%studio%' OR title ILIKE '%OBS Studio%'` → 0)。
> したがって OBS Studio の正しい結果は「未識別」であり、ジョブ32で `nvidia:studio` が
> 割り当てられていたのは誤識別である(4-B-2参照)。同様に JDownloader / Robo 3T も辞書に存在しない。

`syncByKeyword` 経由で「過去に検索されたキーワード」だけが蓄積される設計のため、
辞書の中身は `lodash` 448件など極端に偏っていた。
結果、デスクトップアプリ系はほぼ毎回ライブNVD照会にフォールバックし、
遅い・レート制限に当たる・タイムアウトする、の三重苦になっていた。

---

## 3. 実施済みの修正(2026-08-24 夜)

いずれも実装・テスト・デプロイ済み(全119テストパス)。

### 3-1. ベンダーを「検索語」から「並べ替え信号」へ

- 辞書検索は**製品名のみ**で実行(`localCpeLookup`)
- ベンダーは候補の**並べ替え加点**に降格(`rankCpeCandidates` / `vendorAgrees`)
- ベンダー不一致は**棄却しない**(現実のベンダー欄は不正確なため)

### 3-2. 候補プールの拡大 + 製品単位の重複排除

- 候補プール `3 → 40`(`CPE_CANDIDATE_POOL`)、最終的にTier2へ渡すのは従来通り3件
- **DB側**: `DISTINCT ON (vendor, product)` をサブクエリで適用してから上限を掛ける
  (`CpeDictionaryRepositoryImpl`)
- **アプリ側**: CPE文字列から解析した `vendor:product` で再度重複排除(`identityKey`)

検証(修正後の実クエリ結果): TeamViewer の約30版行が**1件に集約**され、スコア1.0で首位に。

### 3-3. containment判定の対象を製品名のみに限定

ベンダー語だけの一致で `cpe:2.3:a:mozilla:mozilla:-` に誤マッチする不具合を修正。
**94件が「Mozilla Mozilla」と誤識別されていた**ものを解消。

### 3-4. 全件同期を可能にする土台

- ページサイズ `2000 → 10000`(NVD上限、182リクエストで全件)
- **専用HTTPクライアント** `nvdSyncRestClient`(読み取りタイムアウト5分)
  → 既存クライアントは10秒で、1ページ実測29.5秒のため**全件同期は原理的に不可能だった**
- **バッチupsert** `upsertBatch`(1行1文だと180万行で数時間の往復オーバーヘッド)
- `CpeDictionaryBootstrapSync`(`CPE_FULL_SYNC_ON_STARTUP` で起動時に一度だけ実行)
  → **アプリと同一JVMで動かすことで `NvdRateLimiter` を研究ジョブと正しく共有する**
  (別プロセスで走らせると実効レートが二重になる。過去に同じ失敗をしている)

### 3-5. 回帰テスト追加

- `searchesTheCpeDictionaryByProductNameAloneNeverVendorPrefixed`
- `collapsesVersionDuplicateRowsSoOneProductDoesNotFillTheCandidateWindow`
- `promotesTheCandidateWhoseCpeVendorAgreesWithTheUserSuppliedVendor`
- `rejectsAMatchThatOnlyOverlapsOnTheVendorWordNotTheProductName`

---

## 4. ローカル完結化のデータ戦略(60GB枠の使い方)

実測に基づく容量見積もり。**合計しても10GB未満**で、60GB枠には十分収まる。

| データ源 | 取得手段 | 容量(実測/推定) | 状態 |
|---|---|---|---|
| **NVD CPE辞書** | CPE API 2.0(10,000件/頁 × 182頁) | DB **692MB**(実測) | **完了(1,815,263件 / 103分)** |
| CVE.org | GitHub Release(baseline+delta) | DB **976MB**(実測) | 導入済み |
| **OSV.dev** | `gs://osv-vulnerabilities/all.zip` | 圧縮1.5GB / 展開11GB / 878,910件 → DB **3〜4GB**(推定) | 未着手・推奨 |
| GHSA | `github/advisory-database` を git clone | 小(OSVと大部分重複) | 未着手・OSV後に再評価 |
| crates.io | `static.crates.io/db-dump.tar.gz` | 圧縮 **1.65GB**(実測) | 未着手 |
| RubyGems / Hex.pm | 公式index(`specs.4.8.gz` / `names`+`versions`) | 各数百KB〜 | 未着手・軽量 |
| NuGet | V3 Catalog(追記型イベントログ) | 中 | 未着手 |
| npm / PyPI / Packagist / Maven / pub.dev / Go | **全件ミラー非現実的** | — | TTLキャッシュで対応すべき |

### レート制限の厳しさ順(ミラー化の優先度と一致するもの)

| 順位 | 対象 | 制限 | 実害 | ミラーで解決可能か |
|---|---|---|---|---|
| 1 | **GHSA** | 60req/**時**(未認証) | **実際に2回発生** | ✅ 完全解決 |
| 2 | **crates.io** | 1req/秒(公式明記) | 未発生(対策済) | ✅ 完全解決 |
| 3 | Maven Central | 数値非公開・能動的にブロック | **実際に発生** | ❌ 一括ダンプなし。バックオフ強化で対応 |
| 4 | Hex.pm | 100req/分 | 未発生 | ✅(緊急性低) |

### 推奨順序

1. **NVD CPE 全件**(実行中) — 表記揺れ対応の本丸
2. **OSV.dev 全件** — CVE.orgと同じ実装パターンを流用可能、Stage2の主力
3. **レジストリ結果の TTLキャッシュ** — 元プランに記載済みで未実装。npm/PyPI等はこれで対応
4. crates.io / RubyGems / Hex.pm のミラー
5. GHSA(2の後に要否再判定)

---

## 4-B. 検証結果と、そこで判明した**新しい**課題(2026-08-25)

### 4-B-1. ジョブ32(再検証)の結果 — 取りこぼしは実質ゼロ

ジョブ30/31で未識別だった**53件を再投入**した結果:

| | 件数 |
|---|---|
| IDENTIFIED | **45** |
| UNIDENTIFIED | 8 |

未識別8件の内訳を精査したところ、**実質的な取りこぼしは0件**だった:

- 6件 … テストデータに意図的に混ぜたダミー製品(`DoesNotExistApp888`, `NonExistentToolABC999` ほか)。
  **識別されない方が正しい。**
- 2件 … `JDownloader` / `Robo 3T`。180万件の辞書を検索しても**NVDに本当にCPEが存在しない**
  (`SELECT count(*) ... ILIKE '%jdownloader%'` → 0)。原理的に識別不能。

→ 検証計画6-2の成功基準「**NVDに存在するのに未識別だった40件が解消するか**」は**達成**。

### 4-B-2. 失敗モードが「未識別」から「**誤識別**」へ移った 【最重要の新発見・修正済み】

辞書が1,791件 → 1,815,263件(**約1000倍**)になった副作用として、
**どんな名前にも「何かしら」がtrigram距離内に必ず存在する**状態になった。
結果、失敗は未識別ではなく**自信ありげな誤識別**として現れるようになった。

ジョブ30/31/32のCPE付き識別を全件精査して発見した実例:

| 入力 | 誤って割り当てられたCPE | 原因 |
|---|---|---|
| GitHub Desktop | `docker:desktop` | NVDは Docker Desktop を vendor=`docker` / product=`desktop` として登録している |
| Power BI Desktop | `docker:desktop` | 同上 |
| Tableau Desktop | `docker:desktop` | 同上 |
| OBS Studio | `nvidia:studio` | 後方一致 |
| 7-Zip File Manager | `horde:file_manager` | 後方一致 |
| Paint.NET | `microsoft:.net` | 後方一致 |
| ramsey/uuid | `satori:uuid` | 後方一致 |
| github.com/go-redis/redis | `pivotal_software:redis` | 後方一致(クライアントライブラリをサーバ本体と誤認) |
| ioredis | `pivotal_software:redis` | **語中一致** |
| failureaccess | `microsoft:access` | **語中一致** |
| javapoet | `ibm:java` | **語中一致** |
| **guice** | **`sap:gui`** | **語中一致。しかも confidence 0.95** |

**これは未識別より有害である。** 未識別は画面上で「判定不可」として利用者に差し戻されるが、
誤識別は**他社製品のCVEを自社製品に静かに紐付ける**。
特に `guice` の例は、Maven レジストリで `org.openidentityplatform.commons:guice` が
バージョンまで確認できた(`version_confirmed=t`)ために **0.95** という高い確度が付き、
その確度が**無関係なtrigram一致で拾った `sap:gui` にそのまま貸し出されて**いた。

#### 原因

`plausibleContainmentOnly` の包含判定が**対称**(`a.contains(b) || b.contains(a)`)だったこと。
このうち「**クエリが候補を含む**」向きが有害だった。辞書が小さいうちは無害だったが、
180万件では短いスラグがあらゆる複合名の内部に潜んでいる。

#### 修正(実装・テスト済み)

包含の2方向を**非対称**に扱うようにした:

- **候補がクエリを含む** … 従来どおり許可。候補の方が広い文字列なので説明されない語がない
  (`Sublime Text` → `sublime_text_3`)。
- **クエリが候補を含む** … 候補の方が狭い。以下2条件を課す:
  1. **語境界での一致**を要求 — 語中一致(`failureaccess`/`access`, `guice`/`gui`)を一掃
  2. 一致位置より**前方**に残った語は、**CPEのベンダーで説明できること**

2の「前方だけ」が要点である。**製品名は先頭に正体が宿る**:

- `Docker Desktop` → 残余 `docker` = CPEベンダー `docker` → **採用**(正しい)
- `GitHub Desktop` → 残余 `github` ≠ `docker` → **棄却**(正しい)
- `IntelliJ IDEA Community Edition` → 一致が先頭から。後方の `community edition` は説明的 → **採用**

後方の語を不問にしたことで、**版種別語の手書きリストが不要**になった。
リストは際限なく増え、漏れた1語のたびに実在製品を静かに取りこぼす。
`Community Edition` / `Portable` / `Enhanced Edition` / `- Git supercharged` はいずれも
リストなしで正しく通る。

ベンダー照合は単純な部分一致ではなく、**語一致 or 4文字以上の部分一致**とした。
CPEベンダースラグは短いため、緩い判定だと `github.com/go-redis/redis` の残余 `go` が
`google` の部分文字列として通ってしまう。一方で連結スラグ
(`Charles Proxy` → `charlesproxy:charles`)は救う必要がある。

**検証**: ジョブ30/31/32のCPE付き識別を全件当てて、上記12件の誤識別がすべて棄却され、
かつ正解が1件も失われないことを確認。回帰テスト4本を追加(全123テストパス)。

### 4-B-3. 修正後の実測(ジョブ33)

誤識別12件 + **失ってはならない正解14件**の計26件を投入して確認した。

**正解14件は全件維持(退行ゼロ)**:
Adobe Acrobat Reader / Apache HTTP Server / Charles Proxy / Docker Desktop / Google Chrome /
ImageMagick / IntelliJ IDEA Community Edition / Microsoft Teams / Mozilla Firefox / TeamViewer /
VLC Media Player Portable / Zoom Rooms / log4j-core / qBittorrent Enhanced Edition。

誤識別12件のうち**11件が解消**:

| 入力 | 修正前 | 修正後 | 評価 |
|---|---|---|---|
| Paint.NET | `microsoft:.net` | **`dotpdn:paint.net`** | 正解に到達 |
| Power BI Desktop | `docker:desktop` | **`microsoft:power_bi`** | 正解に到達 |
| javapoet | `ibm:java` | **`maven:com.squareup:javapoet`** | 正解に到達 |
| ioredis | `pivotal_software:redis` | **`npm:ioredis`** | 正解に到達 |
| ramsey/uuid | `satori:uuid` | **`packagist:ramsey/uuid`** | 正解に到達 |
| animal-sniffer-annotations | `doctrine-project:annotations` | **`maven:org.codehaus.mojo:animal-sniffer-annotations`** | 正解に到達 |
| 7-Zip File Manager | `horde:file_manager` | 未識別 | 安全側に解消 |
| OBS Studio | `nvidia:studio` | 未識別 | **正しい**(NVD非収録) |
| failureaccess | `microsoft:access` | 未識別 | 安全側に解消 |
| guice | `sap:gui` (0.95) | CPEなし / `maven:...:guice` (0.50) | 偽CPEと過大確度が消滅 |
| Tableau Desktop | `docker:desktop` | `schneider_electric:tableau_desktop` | 製品スラグは正解、ベンダー選択は誤り(後述。ジョブ34で解消確認済み) |

**未解消1件**: `GitHub Desktop` → `jenkins:github`(Jenkinsの GitHub プラグイン)。
先頭語 `github` で一致し、後方の `desktop` が説明されないまま通っている
— 4-B-2で「意図的に受容する残存リスク」として挙げた形そのものである。

なお **GitHub Desktop はNVDにCPEが存在しない**(0件)ため、**正解は「未識別」**であり、
どんな照合規則でも正答は出せない。後方語を語彙リストで縛れば潰せるが、実測すると
`Power BI Desktop`(`desktop` が後方)と `Widgetlens Pro Ultra` 系の実例が巻き添えで落ちる。
現状は**11件の解消と引き換えに1件を残す**方が明確に有利と判断した。
このクラスはむしろ Tier2 のAI裁定が担当すべき領域である(APIキーがないため未検証)。

### 4-B-4. 同名製品のベンダー選択 【2026-08-25 ジョブ34で解消確認・クローズ】

`Tableau Desktop` は辞書に **2つのベンダー**で登録されている:

```
tableau:tableau_desktop            ← 正しい
schneider_electric:tableau_desktop ← 誤り
```

製品スラグは完全一致しており、静的な trigram 順だけではどちらを選ぶか決まらない
(CSVのベンダー欄は "Adobe" という無関係な値だったため加点も効かない)問題として記録していた。

**ジョブ34(実データ400件、2026-08-25)で再検証した結果、解消を確認した。**
`Tableau Desktop` は `llm_disambiguate` 経由で `cpe:2.3:a:tableau:tableau_desktop:2023.1:*:*:*:*:*:*:*`
(confidence 0.98)に正しく解決されている。想定していた「Tier2のAI裁定に回す」対応が
実際にそのまま機能した — 静的な同点候補をハードルールで裁定する専用ロジックは追加不要だった。
このクラスの残タスクはない。

---

## 5. 未実施の提案(要判断)

### A. 正規化・エイリアス辞書の強化

CPEの製品スラグは `http_server` / `acrobat_reader` のようにアンダースコア連結。
現在の `normalizeForContainment` は小文字化・`_`→空白・バックスラッシュ除去のみ。
以下は未対応:

- 版種別語の除去(`Community Edition`, `Professional`, `x64`, `Portable`)
- 記号ゆれ(`Notepad++` / `notepad\+\+`, `Paint.NET` / `paint.net`, `MPC-HC`)
- 「ベンダー名が製品名に含まれる」ケース(`Microsoft Teams` ↔ `microsoft:teams`)
  → 全件同期後は `teams` 側で一致するため改善見込みだが、要検証
- 既知エイリアス表(`VS Code` ↔ `Visual Studio Code`, `httpd` ↔ `Apache HTTP Server`)

### B. スコアリングの明示化 【4-B-2で部分的に実施済み・残りは優先度低】

当初「全件辞書では候補が激増するため明示的スコアが必要になる可能性が高い」と書き、
判断は全件同期後に持ち越していた。**同期後に実測した結論**:

想定していた「完全一致 > 正規化後完全一致 > 語単位一致率 > trigram」という多段スコアではなく、
**語境界 + 前方残余のベンダー説明責任という2つのハード条件**(4-B-2)で観測された誤識別が
すべて除去できた。スコアの重み調整という曖昧な作業を回避できたぶん、こちらの方が良い。

残る「汎用語ペナルティ」は、現時点で実データ上の失敗例が観測できていないため**保留**とする。
新たな誤識別が観測された時点で再検討する。

### D. レジストリ由来の確度をCPEに貸し出さない 【4-B-2で発見・未修正】

`guice` の事例で表面化した設計上の問題。Maven でパッケージ名とバージョンまで確認できたことによる
**0.95** という確度が、同時に(独立した経路で)拾われた CPE `sap:gui` にもそのまま適用されていた。
包含ゲートの修正でこの特定の誤マッチ自体は消えたが、**確度の帰属が混線している構造は残っている**。

レジストリ照合とCPE照合は別々の証拠であり、確度も別々に持つべきである。案:

- `IdentifiedProduct` にCPE側の確度を分けて持たせる、あるいは
- レジストリ確認済み(`version_confirmed=t`)の場合、**CPEは同一製品と裏付けが取れたときのみ**添付する

影響範囲はStage2の調査対象選定にまで及ぶため、スキーマ変更を伴う。要判断。

### C. Maven Central のバックオフ強化

ミラー化できないため、429/タイムアウト時の指数バックオフとサーキットブレーカーで対応する。

---

## 6. 検証(実施済み)

1. ✅ `cpe_dictionary` の件数・DB容量を実測 → 1,815,263件 / 692MB(20GB枠に対し十分小さい)
2. ✅ **ジョブ32** … 30/31の未識別53件を再投入 → 45件識別、残8件は
   ダミー6件 + NVD非収録2件。**成功基準「NVDに存在するのに未識別だった40件の解消」を達成**(4-B-1)
3. ✅ **ジョブ33** … 4-B-2で発見した誤識別12件 + 失ってはならない正解14件の計26件を投入
   → **誤識別11件解消・正解14件は全件維持(退行ゼロ)**(4-B-3)

### 今後の検証課題

- **確度分布の再測定**: ジョブ32は 0.95=1件 / 0.60=42件 / 0.50=2件 と、ジョブ31(0.95=78%)から
  大きく偏っている。これは投入した53件が「レジストリで裏が取れないデスクトップアプリ」に
  偏っているため妥当だが、**同一CSVでの前後比較はまだ取れていない**。
  ジョブ30/31のCSV全体を再実行するのが本来の比較になる(それぞれ1000件/350件、実行時間の都合で未実施)。
- **ライブNVD照会の削減度**: ローカル完結度の指標としてログから計測する予定だったが未計測。

---

## 7. 制約により未実施

- **AIキー(トークン)を要する検証**: Tier2/Tier3のAI裁定精度は測定していない。
  本方針の数値はすべて**AI無し(静的のみ)**の値。
- **本番環境構築**: 指示によりストップ。

---

## 8. 短縮形/展開形の候補生成メカニズム(2026-08-25 実装)

ジョブ34(実データ400件)の未識別を分析した調査で、NVDにCPEが実在するのに未識別になった
実バグ4件(VS Code / GIMP / Rufus / Norton 360)を特定。うち2件は本物の候補生成バグ、
残り2件は候補生成とは無関係と判明した。

### 調査結果

- **VS Code**(短縮形)/ **GIMP の完全展開形「GNU Image Manipulation Program」**: 同一バグの
  双方向。pg_trgm類似度がどちらの向きでも閾値未満(実測: `similarity('visual_studio_code','vs code')`
  =0.29、`similarity(...,'code')`=0.26、いずれも0.3未満)であることを確認 — 候補生成の実バグ。
- **Rufus**: ローカル辞書は `akeo:rufus` / `rufus_project:rufus` の**2件とも正しく候補に上がっている**
  (containment判定も通過)。ジョブ34のDBを確認したところ、同一usage_text・同一製品の重複行
  (バージョン違いの2行)のうち1行は `llm_disambiguate` で正しく解決(confidence 0.85)、
  もう1行は未識別のまま — **候補生成は既に機能しており、原因はTier2 AI裁定の非決定性**
  (usage_textが実際の製品と無関係な内容だったため)。候補生成の範囲外、かつ本方針#5により
  AI裁定ロジック自体には手を入れない。
- **Norton 360**: `broadcom:norton_360` / `symantec:norton_360` の**2件とも正しく候補に上がる**
  (containment判定も通過)。ジョブ34では `identified_products` に行が存在せず未識別 —
  usage_text が「設定ファイル用の軽量エディタ」など製品と無関係だったことによる
  Tier2 AI裁定の棄却が濃厚(Rufusと同一パターン)。Tableau Desktopと同種の
  「ベンダー名が経年変化(Symantec→Broadcom)」ケースではあるが、それ自体は候補生成を
  妨げていない。

### 実装したメカニズム

汎用的な候補生成(特定製品名ペアのハードコード表ではない)を
`Stage1IdentificationService#localCpeLookup` に追加。文字列一致検索(既存の pg_trgm +
containment)が空だった場合のみ発火し、最大3クエリ/件を上限とする
(`MAX_NAME_VARIANT_QUERIES_PER_ITEM`):

1. **縮約(展開形→頭字語)**: `NameVariantGenerator.contractToAcronym` — 意味のある単語3つ以上
   から機械的に頭字語を生成("GNU Image Manipulation Program" → "gimp")し、既存の
   pg_trgm+containmentパイプラインへそのまま通す。
2. **ベンダー接頭辞の除去→再検索**: `NameVariantGenerator.stripLeadingVendor` — 製品名が
   アイテム自身のベンダー欄で始まっている場合に単語境界で除去し、残りで再検索。
3. **展開(頭字語→展開形)**: `Stage1IdentificationService#expandLeadingInitialism` —
   pg_trgmでは原理的に発見できない方向(上記の実測値)のため、辞書の`product`列に対する
   ILIKE部分一致検索(`CpeDictionaryRepositoryCustom#findByProductContaining`、上限500件、
   `gin_trgm_ops`索引で高速化)でアンカー語を含む候補を集め、**アンカーより前の単語の頭文字が
   クエリの先頭語と一致する候補のみ**採用する("visual studio" → "vs")。実データで検証
   (product列に"code"を含む424製品中、"vs"の頭字語条件に一致するのは4件、すべてVisual Studio Code
   本体または拡張機能 — 無関係な誤検出ゼロ)。

**最後の手段としてのハードコード表**(要件により候補生成本体と物理的に分離すること、が
制約)は今回**未作成**: 調査の結果、Rufus/Norton 360 は候補生成レベルでは既に解決しており、
表に載せるべき「一般化できない不規則ケース」が見つからなかったため。

**性能制約の遵守**: 追加のライブNVD呼び出しは一切なし(ローカル辞書のみ)。候補生成の結果は
`CpeNameVariantCache`(`RegistryLookupCache`と同じ設計: プロセス全体・TTL6時間・上限クリア)で
(vendor, productName)単位にメモ化し、同一ジョブ内のバージョン重複行がキャッシュを再利用する。

**回帰テスト**: 既存の偽陽性回帰テスト(GitHub Desktop / guice / failureaccess 等)はすべて
維持したまま新規テストを追加し、全168テストがパス(Stage1は40、新設の
`NameVariantGeneratorTest`が8、`CpeNameVariantCacheTest`が3)。

---

## 付録: 主要な実測値

| 項目 | 値 | 測定日 |
|---|---|---|
| ローカルCPE辞書 | 1,791件 / 1,048 kB | 2026-08-24 |
| NVD CPE 総件数 | 1,815,743 | 2026-08-24 |
| CPEバージョン重複率 | 72.7%(ユニーク製品 約495,697) | 2026-08-24 |
| NVD CPE 1ページ | 10,000件 / 3.0MB / **29.5秒** | 2026-08-24 |
| 旧CPE XMLフィード | **403(廃止)** | 2026-08-24 |
| OSV.dev 全件 | 圧縮1.5GB / 展開11GB / 878,910ファイル | 2026-08-24 |
| crates.io db-dump | 1.65GB(圧縮) | 2026-08-24 |
| CVE.org ミラー | 381,912件 / 976MB | 2026-08-24 |
| 「Mozilla Mozilla」誤識別 | 94件(修正済) | 2026-08-24 |
| CPE辞書 全件同期 | 1,815,263件 / 692MB / 103分 | 2026-08-24 |
| ジョブ32(未識別53件の再投入) | 45件識別 / 8件未識別(内訳: ダミー6・NVD非収録2) | 2026-08-25 |
| 包含向きの非対称化 | 誤識別12件中11件解消 / 正解14件は全件維持 | 2026-08-25 |
| GitHub Desktop | **NVDにCPEが存在しない**(0件)= 正解は「未識別」 | 2026-08-25 |
| Tableau Desktop | 同一スラグに2ベンダー(`tableau` と `schneider_electric`)→ジョブ34でAI裁定が正しく解決(0.98) | 2026-08-25 |
| OBS Studio / JDownloader / Robo 3T | **NVDにCPEが存在しない**(各0件) | 2026-08-25 |
| VS Code / GIMP展開形 | pg_trgm類似度が双方向とも閾値未満(0.26〜0.29)→候補生成メカニズムで解決 | 2026-08-25 |
| Rufus / Norton 360 | 候補生成は成功済み、未識別の原因はTier2 AI裁定の非決定性(範囲外) | 2026-08-25 |
| テスト総数 | 168(Stage1は40、NameVariantGenerator/CpeNameVariantCache新設) | 2026-08-25 |
