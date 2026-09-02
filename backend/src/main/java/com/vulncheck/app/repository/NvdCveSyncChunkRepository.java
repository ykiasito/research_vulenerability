package com.vulncheck.app.repository;

import com.vulncheck.app.entity.NvdCveSyncChunk;
import com.vulncheck.app.entity.NvdCveSyncChunkStatus;
import java.time.OffsetDateTime;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface NvdCveSyncChunkRepository extends JpaRepository<NvdCveSyncChunk, Long> {

    /** Every chunk still needing attention (i.e. not {@link NvdCveSyncChunkStatus#COMPLETED}),
     *  oldest window first — {@link com.vulncheck.app.service.NvdCveSyncService} processes chunks
     *  in this order per run, matching §4-2-4's "PENDINGチャンクをwindow_start昇順で取り予算を
     *  使い切るまで処理" design. Only ~84-120 rows total (one per 120-day window across
     *  [1999-01-01, now), plus adaptive splits), so loading the full list per tick is cheap. */
    List<NvdCveSyncChunk> findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus status);

    /** Whether any chunk still needs attention — used to decide whether this run finished the
     *  entire backfill (no chunks left besides {@link NvdCveSyncChunkStatus#COMPLETED} ones) or
     *  merely ran out of budget partway through. */
    long countByStatusNot(NvdCveSyncChunkStatus status);

    /** Backs {@code NvdCveSyncChunkSplitService}'s idempotent child-window insert: a window pair
     *  that already exists must be skipped rather than re-inserted, since {@code UNIQUE
     *  (window_start, window_end)} would otherwise reject a retried split (e.g. a tick that
     *  re-selects a parent chunk whose children were already committed by an earlier, interrupted
     *  attempt at the same split). */
    boolean existsByWindowStartAndWindowEnd(OffsetDateTime windowStart, OffsetDateTime windowEnd);
}
