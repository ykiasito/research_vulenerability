package com.vulncheck.app.repository;

import java.time.OffsetDateTime;

/** One {@code csaf_products} row queued for {@link CsafProductRepositoryCustom#insertBatch} —
 *  {@code raw_leaf_name} is included, {@code component_name_normalized} is not (a V20 generated
 *  column, populated by Postgres itself from {@code component_name}).
 *
 *  @param advisoryUpdatedAt the PARENT advisory's own {@code tracking.current_release_date}
 *                            (V21, senior review REVISE item 1) — denormalized onto every product
 *                            row of that advisory so {@link
 *                            CsafProductRepositoryCustom#findCandidateProductsExact} can order by
 *                            recency without a join. Every row inserted for the same advisory in one
 *                            {@code upsertCsafDocument} call carries the identical value. */
public record CsafProductInsertRow(
        String vendor,
        String advisoryId,
        String csafProductId,
        String componentName,
        String componentVersion,
        String platformName,
        String cpe,
        String purl,
        String rawLeafName,
        OffsetDateTime advisoryUpdatedAt) {
}
