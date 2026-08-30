package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One row per CSAF vendor's sync progress — see V17's migration comment for why this is a
 *  multi-row table (unlike {@code cve_org_sync_state}'s single row). */
@Entity
@Table(name = "csaf_sync_state")
@Getter
@Setter
@NoArgsConstructor
public class CsafSyncState {

    @Id
    private String vendor;

    @Column(name = "last_synced_at")
    private OffsetDateTime lastSyncedAt;

    @Column(name = "last_cursor")
    private String lastCursor;

    public CsafSyncState(String vendor) {
        this.vendor = vendor;
    }
}
