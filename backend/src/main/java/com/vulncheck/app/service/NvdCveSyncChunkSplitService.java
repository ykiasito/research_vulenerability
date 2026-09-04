package com.vulncheck.app.service;

import com.vulncheck.app.entity.NvdCveSyncChunk;
import com.vulncheck.app.entity.NvdCveSyncChunkStatus;
import com.vulncheck.app.repository.NvdCveSyncChunkRepository;
import java.time.OffsetDateTime;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Commits {@link NvdCveSyncService}'s adaptive window split ({@code splitChunk}) as a single
 * atomic unit: both new {@code PENDING} child chunks plus the parent's own {@code COMPLETED} save.
 * A separate Spring bean (not a private method of {@link NvdCveSyncService} itself) so {@code
 * @Transactional} actually applies — {@code NvdCveSyncService} calls this method on the injected
 * proxy, not on itself, avoiding the classic Spring AOP self-invocation trap.
 *
 * <p><b>Why atomicity matters here</b>: before this class existed, the child inserts and the
 * parent's {@code COMPLETED} save were three separate, non-transactional writes. A crash (or any
 * exception, including the one closed-mode backlog item 202's REVISE round 1 found: an unhandled
 * {@code lastModified} parse failure downstream in {@code ingest}) between the child inserts and
 * the parent save left the child windows persisted but the parent stuck {@code IN_PROGRESS}
 * forever — the next tick would re-select that same parent, re-run the split, and hit {@code
 * UNIQUE (window_start, window_end)} on the already-persisted children, masking the real failure
 * behind a constraint violation on every subsequent run.
 *
 * <p><b>Idempotent besides being atomic</b>: even after this fix, the same parent chunk can
 * legitimately be re-selected and re-split (e.g. this method's own transaction rolling back after
 * the children commit but before the outer call returns is not possible in Postgres, but a second,
 * fully independent tick picking up a still-{@code IN_PROGRESS} parent after a mid-transaction
 * crash is). {@link #saveChildIfAbsent} checks {@link
 * NvdCveSyncChunkRepository#existsByWindowStartAndWindowEnd} before inserting, so a retried split
 * of the same window is a no-op for windows that already exist rather than a constraint violation.
 */
@Service
@RequiredArgsConstructor
class NvdCveSyncChunkSplitService {

    private final NvdCveSyncChunkRepository nvdCveSyncChunkRepository;

    /**
     * Inserts the two {@code PENDING} child windows ({@code [chunk.windowStart, mid)} and {@code
     * [mid, chunk.windowEnd)}, skipping either that already exists) and marks {@code chunk} itself
     * {@code COMPLETED} with the given page's ingest results — all inside one transaction, so a
     * caller never observes children without a completed parent (or vice versa).
     */
    @Transactional
    public void splitAndComplete(NvdCveSyncChunk chunk, OffsetDateTime mid, int observedTotalResults,
            int upserted, OffsetDateTime now) {
        saveChildIfAbsent(chunk.getWindowStart(), mid);
        saveChildIfAbsent(mid, chunk.getWindowEnd());

        chunk.setTotalResults(observedTotalResults);
        chunk.setUpsertedCount(chunk.getUpsertedCount() + upserted);
        chunk.setStatus(NvdCveSyncChunkStatus.COMPLETED);
        chunk.setCompletedAt(now);
        chunk.setLastError(null);
        nvdCveSyncChunkRepository.save(chunk);
    }

    private void saveChildIfAbsent(OffsetDateTime windowStart, OffsetDateTime windowEnd) {
        if (nvdCveSyncChunkRepository.existsByWindowStartAndWindowEnd(windowStart, windowEnd)) {
            return;
        }
        NvdCveSyncChunk child = new NvdCveSyncChunk();
        child.setWindowStart(windowStart);
        child.setWindowEnd(windowEnd);
        child.setStatus(NvdCveSyncChunkStatus.PENDING);
        nvdCveSyncChunkRepository.save(child);
    }
}
