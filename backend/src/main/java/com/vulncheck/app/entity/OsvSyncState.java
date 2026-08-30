package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Single-row table (id is always 1) tracking OSV mirror sync progress — see V25's migration
 *  comment. */
@Entity
@Table(name = "osv_sync_state")
@Getter
@Setter
@NoArgsConstructor
public class OsvSyncState {

    @Id
    private Short id = 1;

    @Column(name = "baseline_loaded", nullable = false)
    private boolean baselineLoaded;

    @Column(name = "sync_in_progress", nullable = false)
    private boolean syncInProgress;

    @Column(name = "last_cursor")
    private OffsetDateTime lastCursor;

    @Column(name = "last_synced_at")
    private OffsetDateTime lastSyncedAt;

    @Column(name = "last_sync_error")
    private String lastSyncError;

    @Column(name = "baseline_source_generation")
    private String baselineSourceGeneration;
}
