-- V38__registry_mirror_seed_name.sql
-- Closed-mode backlog item 185: once Phase B3 removes the live *RegistryClient lookups,
-- identified_products (populated only by RegistryMatch, see Stage1IdentificationService) stops
-- growing -- every RegistryMatch from that point on comes from lookupViaMirror itself, so the
-- mirror's own seed set becomes a closed loop (see RegistryMirrorSyncService's class javadoc). This
-- table is the operator-supplied growth path chosen over a full-registry bulk crawl (rejected: it
-- would need a bespoke bulk-enumeration consumer per ecosystem the 9 *MirrorSyncService classes
-- were never built for -- see e.g. CratesIoMirrorSyncService's class javadoc -- and, per
-- docs/spec/closed-mode-plan.md section 5-6, hundreds of GB of one-time transfer for some
-- ecosystems, which conflicts with closed mode's "minimize new external communication" posture).
-- An admin pastes/uploads a package name list (see AdminController's
-- /admin/registry-mirror/seed-names) which lands here; RegistryMirrorSyncService#syncEcosystem folds
-- these rows into its seed set alongside identified_products, so both a scheduled resync and the
-- next manual "sync all" pick them up without any further action.
CREATE TABLE registry_mirror_seed_name (
    id           BIGSERIAL PRIMARY KEY,
    ecosystem    VARCHAR(50) NOT NULL,
    package_name TEXT NOT NULL,
    added_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Unique rather than a plain index: this is also the ON CONFLICT target for
-- RegistryMirrorSeedNameRepositoryImpl#insertBatch's upsert (re-uploading the same name is a no-op,
-- not a duplicate row).
CREATE UNIQUE INDEX uq_registry_mirror_seed_name_ecosystem_package
    ON registry_mirror_seed_name (ecosystem, package_name);
