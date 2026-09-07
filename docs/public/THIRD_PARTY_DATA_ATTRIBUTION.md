# 第三者脆弱性データソースの出典・ライセンス表示について

## 目的

このアプリは脆弱性の識別・調査のために、以下5系統の第三者データソースをローカルにミラーリングして利用しています。

- NVD / CPE辞書(NIST)
- CVE.org(MITRE)
- GHSA(GitHub Advisory Database)
- OSV(Google、集約元含む)
- CSAF Red Hat
- CSAF Siemens(ProductCERT)

このうちNVD/CPE辞書を除く5系統は、いずれもライセンス上、商用利用時に帰属表示(著作権表示または原文へのリンク)を義務付けています。本文書は、それぞれのライセンス名・帰属表示義務の有無・帰属表示文言の実例・一次情報源へのリンクを一覧としてまとめたものです。

**重要**: 以下の帰属表示文言例は、一般的なCC-BY 4.0の要求事項(著作権者の表示・ライセンスへのリンク・改変の有無の明示)および各ソースの一次規約を参照した上での参考例であり、法的助言ではありません。実際の文言・要件は一次情報源側で随時更新されうるため、商用製品として配布・提供する前には必ず一次情報源の最新版を確認し、必要に応じて法務判断を得てください。

## 一覧

| ソース | ライセンス | 帰属表示義務 |
|---|---|---|
| NVD / CPE辞書(NIST) | パブリックドメイン(米国政府著作物) | 不要(謝辞は任意) |
| CVE.org(MITRE) | MITRE独自の永続的・無償・世界的著作権ライセンス | **必須** |
| GHSA(GitHub Advisory Database) | CC-BY 4.0 | **必須** |
| OSV(Google、集約元含む) | CC-BY 4.0(集約元によりCC0の場合あり) | **必須**(CC0の集約元を除く) |
| CSAF Red Hat | CC-BY 4.0 | **必須** |
| CSAF Siemens(ProductCERT) | 独自のSpecial Provisions | **必須** |

## 各ソースの詳細

### NVD / CPE辞書(NIST)

- **ライセンス**: パブリックドメイン(米国政府著作物、17 U.S.C. § 105)
- **帰属表示義務**: 不要。謝辞は任意。
- **参考表示例(任意)**: 「This product uses data from the National Vulnerability Database (NVD), National Institute of Standards and Technology (NIST).」
- **一次情報源**: https://nvd.nist.gov/general (NVDの利用条件), https://nvd.nist.gov/products/cpe (CPE辞書)

### CVE.org(MITRE)

- **ライセンス**: MITRE独自の永続的・無償・世界的著作権ライセンス(CVE Terms of Use)
- **帰属表示義務**: **必須**。複製物にMITREの著作権表示とライセンス文言を残すこと。
- **表示文言実例**: 「Includes data from the CVE® Program (https://www.cve.org). CVE and the CVE logo are registered trademarks of The MITRE Corporation. Use of this data is subject to the CVE Terms of Use (https://www.cve.org/Legal/TermsOfUse).」
  正確な著作権表示年・文言は一次情報源の最新版を確認すること。
- **一次情報源**: https://www.cve.org/Legal/TermsOfUse
- **参考**: このアプリのCVE.org同期は CVE List V5(https://github.com/CVEProject/cvelistV5)の差分ミラーとして実装されている。

### GHSA(GitHub Advisory Database)

- **ライセンス**: CC-BY 4.0
- **帰属表示義務**: **必須**
- **表示文言実例**: 「Includes data from the GitHub Advisory Database (https://github.com/github/advisory-database), licensed under CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Some entries have been reformatted for internal storage; no factual content has been altered.」
  実際に改変(フォーマット変換等)を行っている場合は、その旨を明示する文言を残すことがCC-BY 4.0上望ましい。
- **一次情報源**: https://github.com/github/advisory-database (リポジトリのLICENSEファイル), https://docs.github.com/en/code-security/security-advisories/global-security-advisories/browsing-security-advisories-in-the-github-advisory-database

### OSV(Google、集約元含む)

- **ライセンス**: CC-BY 4.0(一部の集約元はCC0)
- **帰属表示義務**: **必須**(CC0扱いの集約元データを除く)
- **表示文言実例**: 「Includes vulnerability data from OSV (Open Source Vulnerabilities, https://osv.dev), licensed under CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/).」
- **注意**: OSVは複数の集約元(各エコシステムのセキュリティアドバイザリ)を束ねたメタデータベースであり、レコードによって元データのライセンスが異なりうる。厳密な運用では、個々のレコードに含まれるライセンス情報(存在する場合)まで確認すること。
- **一次情報源**: https://osv.dev, https://google.github.io/osv.dev/faq/ (FAQ、データの出典・ライセンスに関する説明を含む), https://github.com/google/osv.dev

### CSAF Red Hat

- **ライセンス**: CC-BY 4.0
- **帰属表示義務**: **必須**。Red Hat, Inc.への帰属表示および原文へのリンク。
- **表示文言実例**: 「Includes Red Hat Security Data (CSAF), © Red Hat, Inc., licensed under CC-BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Source: https://security.access.redhat.com/data/csaf/v2/advisories/」
- **一次情報源**: https://www.redhat.com/en/about/terms-use (Red Hatの利用条件), https://security.access.redhat.com/data/csaf/v2/advisories/ (CSAFデータ配布元)

### CSAF Siemens(ProductCERT)

- **ライセンス**: Siemens独自のSpecial Provisions(利用条件)
- **帰属表示義務**: **必須**。原文へのリンクを残すこと。改変を行う場合は技術的正確性を維持すること。条件に違反した場合、Siemensがいつでも許可を取り消せる点に留意する。
- **表示文言実例**: 「Includes Siemens ProductCERT Security Advisories (CSAF), source: https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json および https://cert-portal.siemens.com/productcert/html/ 配下の各アドバイザリページ。Reproduced under the terms published by Siemens ProductCERT.」
- **一次情報源**: https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json (CSAFデータ配布元), https://cert-portal.siemens.com/productcert/html/ (アドバイザリ一覧・利用条件の記載箇所)

## 今後の対応

現時点ではこのドキュメントとしての整備のみを行っている。アプリ内UI(footerや`/about`相当のページ)への帰属表示の露出は別タスクとして今後検討する。

商用製品として配布・提供する前には、必ず各ソースの一次情報源で最新のライセンス条項・帰属表示要件を確認し、必要であれば法務判断を得ること。特にCVE.orgとCSAF Siemensは、CC-BYのような標準ライセンスではなく発行元独自の条項であるため、文言・条件の変更が起きやすい点に注意する。
