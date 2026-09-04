package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One resumable date-window chunk of the NVD CVE mirror backfill/delta sync — see V39's migration
 * comment and {@link com.vulncheck.app.service.NvdCveSyncService} for the full design rationale
 * (why chunking exists, how adaptive splitting works, how {@link #nextStartIndex} makes a chunk
 * resumable down to the individual NVD API page).
 */
@Entity
@Table(name = "nvd_cve_sync_chunk")
@Getter
@Setter
@NoArgsConstructor
public class NvdCveSyncChunk {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "window_start", nullable = false)
    private OffsetDateTime windowStart;

    @Column(name = "window_end", nullable = false)
    private OffsetDateTime windowEnd;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    private NvdCveSyncChunkStatus status = NvdCveSyncChunkStatus.PENDING;

    @Column(name = "next_start_index", nullable = false)
    private int nextStartIndex;

    @Column(name = "total_results")
    private Integer totalResults;

    @Column(name = "upserted_count", nullable = false)
    private int upsertedCount;

    @Column(name = "attempt_count", nullable = false)
    private int attemptCount;

    @Column(name = "last_error")
    private String lastError;

    @Column(name = "started_at")
    private OffsetDateTime startedAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;
}
