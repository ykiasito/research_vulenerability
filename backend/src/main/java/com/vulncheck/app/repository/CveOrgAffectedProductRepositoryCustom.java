package com.vulncheck.app.repository;

import java.util.List;

public interface CveOrgAffectedProductRepositoryCustom {

    /** Fuzzy-matches {@code productQuery} against product/package_name using each column's GIN
     *  trigram index (see the {@code Impl} class — a {@code similarity(col, x) > threshold}
     *  native query can't use these indexes at all). Returns distinct {@code cve_id}s ordered by
     *  best match score. */
    List<String> findCandidateCveIds(String productQuery, double threshold, int limit);
}
