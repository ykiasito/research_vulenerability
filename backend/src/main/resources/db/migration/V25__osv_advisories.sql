-- V25__osv_advisories.sql
-- Local mirror of OSV.dev's own non-GHSA-reviewed advisories, restricted to the 10 package
-- ecosystems this app supports (see docs/spec/osv-mirror-plan.md for the full design rationale).
-- Same six-table shape as V19's ghsa_* tables (GHSA mirror) — OSV.dev publishes GHSA-reviewed
-- advisories and its own non-GHSA advisories (PyPI Advisory Database/PYSEC, Go Vulnerability
-- Database/GO, RustSec/RUSTSEC, Drupal/DRUPAL-CONTRIB, Erlang Ecosystem Foundation/EEF-CVE, plus
-- OSS-Fuzz-derived OSV-* records) in the exact same JSON schema, so the same table split applies
-- unchanged. `GHSA-*`/`MAL-*` ids are excluded at ingest time (plan §4-1) — they never reach this
-- schema at all, since GhsaSyncService's ghsa_advisories already covers that population.
--
-- The one structural difference from V19: no raw_json column (plan's most important scope
-- decision) — re-derivation/debugging from the original document is deliberately given up in
-- exchange for not pulling multi-GB of raw JSON into the DB for a data set this narrow.

-- One row per non-GHSA OSV.dev advisory. osv_id: PYSEC-2023-1 / GO-2023-1234 / RUSTSEC-2023-0001 /
-- DRUPAL-CONTRIB-2026-111 / EEF-CVE-2026-12345 / OSV-2026-1234, etc. — format/length vary by
-- source, so VARCHAR(40) is wider than GHSA's fixed-format VARCHAR(20). An id longer than 40 chars
-- is rejected before it ever reaches an insert attempt (app-side validation, not a DB constraint
-- violation) — see OsvSyncService's input validation.
CREATE TABLE osv_advisories (
    osv_id          VARCHAR(40) PRIMARY KEY,
    cve_id          VARCHAR(30),               -- aliases[]からCVE-*を抽出(finding発行時のID優先順位にも使う)
    ghsa_id         VARCHAR(20),               -- aliases[]にGHSA-*があれば参考情報として保持。
                                                -- このIDで新たにghsa_advisoriesを参照しにいく仕組みは
                                                -- ここでは作らない(参照はOsvVulnerabilityLookupRepository
                                                -- 側のLEFT JOINで行う)。
    summary         TEXT,
    details         TEXT,
    severity        VARCHAR(20),
    cvss_score      NUMERIC,                   -- GHSAミラーと同じ理由で当面NULL — OSVのseverity[]は
                                                -- 生のCVSSベクター文字列のみで、事前計算済み数値スコアを
                                                -- 持たない。ベクター文字列パーサは本フェーズのスコープ外。
    withdrawn_at    TIMESTAMPTZ,               -- NOT NULL = 撤回済み。find()対象から除外(ghsa_advisoriesと同型)
    published_at    TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL,      -- JSON本文のmodifiedフィールドをそのまま格納するのみ。
                                                -- delta同期のカーソルには使わない(カーソルは
                                                -- modified_id.csv側のタイムスタンプ、osv_sync_state.last_cursor参照)
    html_url        TEXT,
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_osv_advisories_updated_at ON osv_advisories (updated_at);

-- osv_affected_packages / osv_affected_versions / osv_affected_ranges は
-- ghsa_affected_packages / ghsa_affected_versions / ghsa_affected_ranges (V19) と列構成・制約とも同一。
-- package_name_normalized には OsvPackageNameNormalizer.normalize() をそのまま再利用する。
CREATE TABLE osv_affected_packages (
    id                       BIGSERIAL PRIMARY KEY,
    osv_id                   VARCHAR(40) NOT NULL REFERENCES osv_advisories(osv_id) ON DELETE CASCADE,
    ecosystem                VARCHAR(30) NOT NULL,
    package_name             TEXT NOT NULL,
    package_name_normalized  TEXT NOT NULL,
    UNIQUE (osv_id, ecosystem, package_name_normalized)
);
CREATE INDEX idx_osv_affected_packages_lookup ON osv_affected_packages (ecosystem, package_name_normalized);
CREATE INDEX idx_osv_affected_packages_advisory ON osv_affected_packages (osv_id);

CREATE TABLE osv_affected_versions (
    affected_package_id  BIGINT NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE,
    version               TEXT NOT NULL,
    PRIMARY KEY (affected_package_id, version)
);
CREATE INDEX idx_osv_affected_versions_package ON osv_affected_versions (affected_package_id);

-- range_type/introduced_version/fixed_version/last_affected_versionの意味論はghsa_affected_rangesと
-- 完全に同一 — OsvVersionRange.matches()をそのまま再利用できる根拠。
CREATE TABLE osv_affected_ranges (
    id                     BIGSERIAL PRIMARY KEY,
    affected_package_id    BIGINT NOT NULL REFERENCES osv_affected_packages(id) ON DELETE CASCADE,
    range_type             VARCHAR(16) NOT NULL,
    introduced_version     TEXT,
    fixed_version          TEXT,
    last_affected_version  TEXT,
    CHECK (fixed_version IS NULL OR last_affected_version IS NULL)
);
CREATE INDEX idx_osv_affected_ranges_package ON osv_affected_ranges (affected_package_id);

-- 単一行の同期状態。ghsa_sync_stateとほぼ同型。
-- baseline_source_generation: baseline取得時に10本のzipそれぞれから記録したx-goog-generation
-- (またはetag/last-modified)を連結・保持する列 — 後から「このbaselineがどのGCSスナップショット
-- 由来か」を突き合わせられるようにする、デバッグ・監査用途の完全性メタデータ。取り込み可否の
-- ゲートとしては引き続き自己較正方式の完全性ゲート(COUNT(DISTINCT osv_id)が期待値の90%以上)を
-- 使う — このgeneration列は事後の追跡用であり、取り込み時点の判定には使わない。
CREATE TABLE osv_sync_state (
    id                          SMALLINT PRIMARY KEY DEFAULT 1,
    baseline_loaded             BOOLEAN NOT NULL DEFAULT false,
    sync_in_progress            BOOLEAN NOT NULL DEFAULT false,
    -- last_cursorはmodified_id.csv側のタイムスタンプドメインで一貫させる(JSON内のmodifiedフィールドは
    -- osv_advisories.updated_at列に格納するだけで、カーソルには使わない)。delta同期はtimestampグループ
    -- (modified_id.csv上で同一タイムスタンプを共有する行の集合)単位でしか前進させないグループアトミック
    -- 方式を取るため、last_cursorは常に「完全に処理し終えたtimestampグループの、csv側タイムスタンプ」を
    -- 指す — 1行ごとの前進ではない。グループ内に1件でも失敗があれば、そのグループのタイムスタンプまでは
    -- 前進させず、1つ前に完了したグループのタイムスタンプのまま次回実行に持ち越す
    -- (docs/spec/osv-mirror-plan.md §6-2手順7参照)。
    last_cursor                 TIMESTAMPTZ,
    last_synced_at              TIMESTAMPTZ,
    last_sync_error             TEXT,
    baseline_source_generation  TEXT,   -- 10本のzipのx-goog-generation(またはetag)を連結して保持(上記コメント参照)
    CHECK (id = 1)
);
INSERT INTO osv_sync_state (id) VALUES (1);

-- ghsa_sync_failuresと同型。ghsa_id列と異なりosv_idは書式が不定なので、GHSAの厳格な正規表現
-- バリデーション(GhsaSyncService.GHSA_ID_PATTERN相当)は使えず、長さ・文字種の緩い妥当性チェックに留める。
CREATE TABLE osv_sync_failures (
    osv_id                VARCHAR(40) PRIMARY KEY,
    consecutive_failures  INT NOT NULL DEFAULT 0,
    last_error            TEXT,
    last_attempted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    dead_lettered_at      TIMESTAMPTZ
);
