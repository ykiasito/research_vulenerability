-- V37__registry_package_mirror.sql
-- Closed-mode backlog item 176 pilot: a local mirror of package-registry existence data (package
-- name + published version list only, no artifact bodies), so Stage1 Tier1 registry lookups can be
-- answered without a live HTTP call once a closed-mode deployment can't reach npm/PyPI/crates.io/
-- etc. Pilot scope is crates.io only (see CratesIoMirrorSyncService/CratesIoRegistryClient) -- the
-- ecosystem column exists so a later rollout to the other 9 registries can reuse this same table
-- rather than one per ecosystem, but nothing else writes to it yet.
--
-- One row per (ecosystem, package_name) rather than one row per version: a version-per-row design
-- would multiply this table's row count by however many published versions each package has
-- (crates.io alone has 140k+ packages, many with dozens to hundreds of versions each) for no
-- benefit this app actually needs -- Stage1 only ever asks "does this exact version string exist
-- for this package", which a single text[] membership check answers just as well as a join would,
-- at a fraction of the row count.
CREATE TABLE registry_package_mirror (
    id              BIGSERIAL PRIMARY KEY,
    ecosystem       VARCHAR(50) NOT NULL,
    -- Normalized the same way as the read-time query key (see
    -- com.vulncheck.app.service.vuln.OsvPackageNameNormalizer, the same normalizer already backing
    -- ghsa_affected_packages/osv_affected_packages' own package_name_normalized columns) -- e.g.
    -- crates.io folds "-"/"_" and case when reserving a name, so "Serde_Json" and "serde-json" must
    -- resolve to the same mirror row.
    package_name    TEXT NOT NULL,
    versions        TEXT[] NOT NULL DEFAULT '{}',
    last_synced_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique rather than a plain index: this is also the ON CONFLICT target for
-- RegistryPackageMirrorRepositoryImpl#upsertBatch's upsert.
CREATE UNIQUE INDEX uq_registry_package_mirror_ecosystem_package
    ON registry_package_mirror (ecosystem, package_name);
