-- V42__cpe_dictionary_sync_state.sql
-- Closed-mode backlog item 283: the NVD CPE Dictionary mirror (cpe_dictionary, V1/V31) has only
-- ever supported a full re-pull (NvdCpeSyncService#syncAllAndRelease, ~103 minutes / ~692MB
-- measured). This table backs a new lastModStartDate/lastModEndDate-filtered delta sync
-- (NvdCpeSyncService#syncDeltaAndRelease) so the weekly scheduled resync (CpeDictionaryScheduledResync)
-- only has to pull what NVD reports as changed since the last successful sync, once one exists.
--
-- Single-row table (id=1), same CHECK(id=1) singleton shape as cve_org_sync_state (V8) and
-- nvd_cve_sync_state (V39).
--
-- initial_sync_completed starts false: there is nothing yet to diff a delta sync against, so
-- CpeDictionaryScheduledResync's first run (and every run before this ever flips true) must still
-- be a full syncAllAndRelease() -- see NvdCpeSyncService#hasCompletedInitialSync. Deliberately not
-- inferred from a cpe_dictionary row count: a sync that aborted early (SyncOutcome#completed()
-- false) still upserts a partial set of rows, and a row-count check would misread that partial
-- dictionary as "already fully synced once", permanently skipping the full resync it still needs.
--
-- last_synced_at is the high-water mark the next delta sync's lastModStartDate window starts from
-- (minus a clock-skew safety margin -- see NvdCpeSyncService#syncDelta). Set whenever an
-- *unfiltered* sync (full or delta, never NvdCpeSyncService#syncByKeyword's keyword-filtered subset
-- sync) completes cleanly, to that sync's own requested lastModEndDate (a delta sync) or its own
-- start time (a full sync) -- never wall-clock "now" at completion, so a clamped/partial window's
-- actual end is never silently skipped on the following tick's cursor advance.
CREATE TABLE cpe_dictionary_sync_state (
    id                     SMALLINT PRIMARY KEY DEFAULT 1,
    initial_sync_completed BOOLEAN NOT NULL DEFAULT false,
    last_synced_at         TIMESTAMPTZ,
    CHECK (id = 1)
);
INSERT INTO cpe_dictionary_sync_state (id) VALUES (1);
