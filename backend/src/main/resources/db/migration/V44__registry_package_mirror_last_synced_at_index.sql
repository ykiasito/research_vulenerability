-- V44__registry_package_mirror_last_synced_at_index.sql
-- Closed-mode backlog item 395: registry_package_mirror (see V37) only had a unique index on
-- (ecosystem, package_name). RegistryPackageMirrorRepository#maxLastSyncedAt() (closed-mode item
-- 382, added on the closed-mode branch and reused by the job-detail page's 5-second polling, which
-- currently mitigates this with a TTL cache) runs `SELECT MAX(last_synced_at) FROM
-- registry_package_mirror`, which without an index on that column forces a full sequential scan.
-- Currently pilot scope is crates.io only (see V37's header), but the table is designed to grow to
-- all 9 registry ecosystems, so this only gets worse over time -- add the missing index now rather
-- than waiting for it to show up as a slow-query complaint.
CREATE INDEX idx_registry_package_mirror_last_synced_at
    ON registry_package_mirror (last_synced_at);
