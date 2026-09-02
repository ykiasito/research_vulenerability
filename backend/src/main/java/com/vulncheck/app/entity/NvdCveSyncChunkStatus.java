package com.vulncheck.app.entity;

/**
 * Status of one {@link NvdCveSyncChunk}. {@link #FAILED} is deliberately not a terminal give-up
 * state — it only records that the chunk's most recent page fetch attempt errored (see {@code
 * NvdCveSyncChunk#getLastError}), and the chunk remains eligible for the next run's retry exactly
 * like {@link #PENDING}/{@link #IN_PROGRESS}. Only {@link #COMPLETED} is excluded from chunk
 * selection (see {@code NvdCveSyncChunkRepository#findByStatusNotOrderByWindowStartAsc}).
 */
public enum NvdCveSyncChunkStatus {
    PENDING,
    IN_PROGRESS,
    FAILED,
    COMPLETED
}
