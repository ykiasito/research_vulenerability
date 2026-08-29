package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** Dead-letter ledger row for one {@code ghsa_id} — see V19's migration comment and {@code
 *  GhsaSyncService}'s §6-1 "poison pill" handling. */
@Entity
@Table(name = "ghsa_sync_failures")
@Getter
@Setter
@NoArgsConstructor
public class GhsaSyncFailure {

    @Id
    @Column(name = "ghsa_id")
    private String ghsaId;

    @Column(name = "consecutive_failures", nullable = false)
    private int consecutiveFailures;

    @Column(name = "last_error")
    private String lastError;

    @Column(name = "last_attempted_at", nullable = false)
    private OffsetDateTime lastAttemptedAt;

    @Column(name = "dead_lettered_at")
    private OffsetDateTime deadLetteredAt;

    public GhsaSyncFailure(String ghsaId) {
        this.ghsaId = ghsaId;
    }
}
