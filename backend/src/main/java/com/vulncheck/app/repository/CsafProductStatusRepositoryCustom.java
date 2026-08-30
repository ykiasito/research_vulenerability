package com.vulncheck.app.repository;

import com.vulncheck.app.service.vuln.CsafStatusRow;
import java.util.List;

public interface CsafProductStatusRepositoryCustom {

    /**
     * Every {@code tracking_status = 'final'}-advisory status row matching any of {@code
     * candidates}' own (vendor, advisory_id, csaf_product_id) tuple, in one round trip.
     *
     * <p>REVISE item 8 (senior review 2026-08-27): replaces what used to be one {@code
     * findFinalStatuses} query per surviving candidate — up to {@link
     * com.vulncheck.app.service.vuln.CsafVulnerabilitySource}'s {@code CANDIDATE_LIMIT} (30) per job
     * item, times up to 1,000 items per job — with a single batched query, directly furthering the
     * plan's §8-1 rationale for collapsing every CSAF vendor into one class in the first place
     * (reducing Stage2's per-item sequential DB cost, not just its per-vendor sequential cost).
     */
    List<CsafStatusRow> findFinalStatuses(List<CsafProductCandidate> candidates);

    /** Batched insert (go/no-go review item 7) — a single Red Hat advisory can produce up to
     *  ~171,072 status rows; see the {@code Impl} class for the chunking convention (mirrors {@code
     *  CpeDictionaryRepositoryImpl#upsertBatch}). No-op for an empty list. */
    void insertBatch(List<CsafProductStatusInsertRow> rows);
}
