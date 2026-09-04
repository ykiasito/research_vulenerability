package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Single-row table (id is always 1) tracking whether the NVD CPE Dictionary mirror ({@code
 * cpe_dictionary}) has ever completed an unfiltered sync, and the high-water mark the next delta
 * sync's {@code lastModStartDate} window should start from — closed-mode backlog item 283. See
 * {@code V42__cpe_dictionary_sync_state.sql} and {@code
 * NvdCpeSyncService#hasCompletedInitialSync}/{@code #syncDeltaAndRelease}.
 */
@Entity
@Table(name = "cpe_dictionary_sync_state")
@Getter
@Setter
@NoArgsConstructor
public class CpeDictionarySyncState {

    @Id
    private Short id = 1;

    @Column(name = "initial_sync_completed", nullable = false)
    private boolean initialSyncCompleted;

    @Column(name = "last_synced_at")
    private OffsetDateTime lastSyncedAt;
}
