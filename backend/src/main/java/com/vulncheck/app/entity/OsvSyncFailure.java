package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Dead-letter ledger row for one {@code osv_id} — see V25's migration comment and {@code
 *  OsvSyncService}'s "poison pill" handling. */
@Entity
@Table(name = "osv_sync_failures")
@Getter
@Setter
@NoArgsConstructor
public class OsvSyncFailure {

    @Id
    @Column(name = "osv_id")
    private String osvId;

    @Column(name = "consecutive_failures", nullable = false)
    private int consecutiveFailures;

    @Column(name = "last_error")
    private String lastError;

    @Column(name = "last_attempted_at", nullable = false)
    private OffsetDateTime lastAttemptedAt;

    @Column(name = "dead_lettered_at")
    private OffsetDateTime deadLetteredAt;

    public OsvSyncFailure(String osvId) {
        this.osvId = osvId;
    }
}
