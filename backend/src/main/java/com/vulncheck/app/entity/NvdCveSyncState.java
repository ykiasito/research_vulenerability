package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Single-row table (id is always 1) tracking NVD CVE mirror sync progress — see V39's migration
 *  comment and {@link com.vulncheck.app.service.NvdCveSyncService}. */
@Entity
@Table(name = "nvd_cve_sync_state")
@Getter
@Setter
@NoArgsConstructor
public class NvdCveSyncState {

    @Id
    private Short id = 1;

    @Column(name = "baseline_completed", nullable = false)
    private boolean baselineCompleted;

    @Column(name = "baseline_started_at")
    private OffsetDateTime baselineStartedAt;

    @Column(name = "last_delta_synced_at")
    private OffsetDateTime lastDeltaSyncedAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;
}
