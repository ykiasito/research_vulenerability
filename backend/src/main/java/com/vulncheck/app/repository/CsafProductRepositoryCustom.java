package com.vulncheck.app.repository;

import java.util.List;

public interface CsafProductRepositoryCustom {

    /**
     * PRIMARY match path (Phase 2 go/no-go review item 4) — an exact, case/whitespace-insensitive
     * match against {@code csaf_products.component_name_normalized} (a V20 generated column, btree
     * indexed as {@code (vendor, component_name_normalized, advisory_updated_at)}, V21). See {@code
     * CsafProductRepositoryImpl} for the measured {@code EXPLAIN ANALYZE} plan/timing this replaces
     * the old fuzzy-only path with. Ordered by {@code advisory_updated_at DESC NULLS LAST} (senior
     * review REVISE item 1, 2026-08-27, CRITICAL) — an unordered {@code LIMIT} previously let ties
     * break on physical row order, silently favoring the oldest matching advisories for any common
     * component name; callers relying on "the most relevant/recent {@code limit} hits" now get
     * exactly that instead of an arbitrary subset.
     */
    List<CsafProductCandidate> findCandidateProductsExact(List<String> vendors, String normalizedComponentName, int limit);

    /** Fuzzy-matches {@code componentQuery} against {@code csaf_products.component_name} using its
     *  GIN trigram index (see the {@code Impl} class — same reasoning as {@code
     *  CveOrgAffectedProductRepositoryImpl}: a {@code similarity(col, x) > threshold} native query
     *  can't use this index at all). Returns candidates ordered by best match score, with a recency
     *  tiebreak ({@code advisory_updated_at DESC NULLS LAST}, senior review REVISE item 1) for rows
     *  that score identically (the same all-ties-on-physical-order problem item 1 fixed for {@link
     *  #findCandidateProductsExact}, just reached via a similarity tie instead of an equality match).
     *
     *  <p>FALLBACK path only as of Phase 2 (go/no-go review item 4), scoped to Siemens ONLY as of the
     *  senior review's REVISE item 5 (2026-08-27) — see {@code CsafProductRepositoryImpl}'s
     *  {@code TRGM_FALLBACK_VENDOR} field javadoc for why Red Hat never legitimately reaches this
     *  path. {@link #findCandidateProductsExact} is tried first; this is only reached when that finds
     *  nothing. */
    List<CsafProductCandidate> findCandidateProducts(String componentQuery, double threshold, int limit);

    /** Batched insert (go/no-go review item 7) — a single Red Hat advisory can produce up to ~12,056
     *  product rows; see the {@code Impl} class for the chunking convention (mirrors {@code
     *  CpeDictionaryRepositoryImpl#upsertBatch}). No-op for an empty list. */
    void insertBatch(List<CsafProductInsertRow> rows);
}
