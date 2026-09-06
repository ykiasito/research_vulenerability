package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Single-row table (id is always 1) tracking CVE.org sync progress. */
@Entity
@Table(name = "cve_org_sync_state")
@Getter
@Setter
@NoArgsConstructor
public class CveOrgSyncState {

    @Id
    private Short id = 1;

    @Column(name = "baseline_loaded", nullable = false)
    private boolean baselineLoaded;

    @Column(name = "last_release_tag")
    private String lastReleaseTag;

    @Column(name = "last_synced_at")
    private OffsetDateTime lastSyncedAt;

    /** Set by {@link com.vulncheck.app.service.cveorg.CveOrgSyncService} on every failed sync
     *  attempt (baseline or delta), cleared to {@code null} on the next successful one — closed-mode
     *  backlog item 379, matching {@code GhsaSyncState}/{@code OsvSyncState}'s field of the same
     *  name. */
    @Column(name = "last_sync_error")
    private String lastSyncError;
}
