package com.vulncheck.app.repository;

/** One {@code csaf_product_status} row queued for {@link
 *  CsafProductStatusRepositoryCustom#insertBatch}. */
public record CsafProductStatusInsertRow(
        String vendor,
        String advisoryId,
        String cveId,
        String csafProductId,
        String status,
        String fixedVersion,
        String remediationUrl) {
}
