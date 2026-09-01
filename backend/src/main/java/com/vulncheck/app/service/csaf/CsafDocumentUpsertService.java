package com.vulncheck.app.service.csaf;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.CsafAdvisoryRepository;
import com.vulncheck.app.repository.CsafProductInsertRow;
import com.vulncheck.app.repository.CsafProductRepository;
import com.vulncheck.app.repository.CsafProductStatusInsertRow;
import com.vulncheck.app.repository.CsafProductStatusRepository;
import com.vulncheck.app.service.SafeUrlValidator;
import com.vulncheck.app.service.csaf.CsafProductTreeWalker.ResolvedProduct;
import com.vulncheck.app.service.csaf.CsafProductTreeWalker.WalkResult;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Shared, vendor-agnostic upsert of one already-fetched-and-verified CSAF document into {@code
 * csaf_advisories}/{@code csaf_products}/{@code csaf_product_status} — see {@code
 * docs/spec/csaf-vendor-advisory-plan.md} §4. Every vendor sync service (Siemens now, Red Hat
 * later) calls this same method rather than each re-implementing CSAF's standardized JSON shape;
 * only *discovering* which documents to fetch (ROLIE feed vs. changes.csv, ...) is vendor-specific
 * and stays out of this class.
 *
 * <p>Mirrors {@code CveOrgSyncService#upsertCveJson}'s idempotent "delete-then-reinsert the child
 * rows, always" shape: a re-synced advisory (e.g. a later revision) replaces its {@code
 * csaf_products}/{@code csaf_product_status} rows wholesale rather than diffing — cheap at this
 * volume (a handful to a few hundred rows per advisory) and avoids reconciling a restructured
 * {@code product_tree} row-by-row.
 *
 * <p>Deliberately does NOT filter by {@code tracking_status} — a draft/interim document is still
 * upserted into the local mirror (so it's already there, current, if/when it's later finalized);
 * only {@code CsafVulnerabilitySource}'s read path filters to {@code tracking_status = 'final'}
 * (plan §7).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CsafDocumentUpsertService {

    /** The only {@code product_status} categories this app tracks — see V17's migration comment.
     *  CSAF also defines first_affected/last_affected/first_fixed/recommended, which this app has
     *  no use for (plan §3). */
    private static final Set<String> TRACKED_STATUSES = Set.of("fixed", "known_affected", "known_not_affected", "under_investigation");

    private final CsafAdvisoryRepository csafAdvisoryRepository;
    private final CsafProductRepository csafProductRepository;
    private final CsafProductStatusRepository csafProductStatusRepository;
    private final CsafProductTreeWalker productTreeWalker;

    /** @return the advisory's {@code tracking.id}, or null if the document was missing one (and
     *          therefore wasn't upserted at all — nothing to key any of the three tables on). */
    @Transactional
    public String upsertCsafDocument(String vendor, JsonNode root) {
        JsonNode document = root.path("document");
        JsonNode tracking = document.path("tracking");
        String trackingId = tracking.path("id").asText(null);
        if (trackingId == null || trackingId.isBlank()) {
            log.warn("CSAF document for vendor={} has no document.tracking.id — skipping", vendor);
            return null;
        }

        HighestCvss cvss = extractHighestCvss(root.path("vulnerabilities"));
        OffsetDateTime dateUpdated = parseTimestamp(tracking.path("current_release_date").asText(null));

        csafAdvisoryRepository.upsert(
                vendor,
                trackingId,
                tracking.path("status").asText("final"),
                tracking.path("version").asText(null),
                document.path("title").asText(null),
                document.path("distribution").path("tlp").path("label").asText(null),
                cvss.score(),
                cvss.severity(),
                parseTimestamp(tracking.path("initial_release_date").asText(null)),
                dateUpdated,
                root.toString());

        WalkResult walk = productTreeWalker.walk(root.path("product_tree"));

        // REVISE item 3 (senior review 2026-08-27): status rows are now built FIRST, in a pass that
        // never touches the DB, purely to learn which canonical product ids are actually REFERENCED by
        // some product_status entry (measured: 46.6% of persisted product rows were never referenced
        // by anything, wasting slots in CsafVulnerabilitySource's LIMIT-30 candidate window). Products
        // are then persisted ONLY for referenced ids — a two-pass shape rather than "insert everything,
        // then insert statuses" because the FK (csaf_product_status -> csaf_products) requires products
        // to exist before statuses can reference them, so the referenced-id SET has to be known before
        // either INSERT actually runs.
        List<CsafProductStatusInsertRow> statusRows = new ArrayList<>();
        Set<String> referencedCanonicalIds = new HashSet<>();
        // REVISE item 6 (senior review 2026-08-27): when several ORIGINAL product_ids fold to the
        // same canonical product (CsafProductTreeWalker's architecture-variant folding) and an
        // advisory lists more than one of those original ids under the same product_status/CVE, the
        // loop below would otherwise write one identical (cve, canonical product, status) row per
        // original id. insertedStatusKeys dedupes within this single upsert before each insert; V18
        // additionally enforces this at the DB level with a UNIQUE constraint.
        Set<String> insertedStatusKeys = new HashSet<>();
        for (JsonNode vulnerability : root.path("vulnerabilities")) {
            String cveId = vulnerability.path("cve").asText(null);
            if (cveId == null || cveId.isBlank()) {
                continue;
            }
            Map<String, RemediationInfo> remediationByOriginalProductId = extractVendorFixRemediations(vulnerability.path("remediations"));
            JsonNode productStatus = vulnerability.path("product_status");
            for (String status : TRACKED_STATUSES) {
                for (JsonNode productIdNode : productStatus.path(status)) {
                    String originalProductId = productIdNode.asText();
                    String canonicalProductId = walk.productIdRemap().get(originalProductId);
                    if (canonicalProductId == null || !walk.productsByCanonicalId().containsKey(canonicalProductId)) {
                        // Dangling reference (product_id not resolvable in this document's own
                        // product_tree, including a debuginfo/debugsource product CsafProductTreeWalker
                        // dropped entirely) — skip this one row rather than fail the whole document.
                        continue;
                    }
                    if (!insertedStatusKeys.add(cveId + ' ' + canonicalProductId + ' ' + status)) {
                        continue; // already inserted for this (cve, canonical product, status) — see above
                    }
                    referencedCanonicalIds.add(canonicalProductId);
                    RemediationInfo remediation = remediationByOriginalProductId.get(originalProductId);
                    statusRows.add(new CsafProductStatusInsertRow(vendor, trackingId, cveId, canonicalProductId, status,
                            remediation != null ? remediation.text() : null,
                            remediation != null ? remediation.url() : null));
                }
            }
        }

        // Batched, not one INSERT per row (go/no-go review item 7) - a single real Red Hat advisory
        // measured up to ~12,056 product rows and ~171,072 status rows; see
        // CsafProductRepositoryImpl/CsafProductStatusRepositoryImpl for the chunking convention.
        csafProductRepository.deleteByVendorAndAdvisoryId(vendor, trackingId);
        List<CsafProductInsertRow> productRows = new ArrayList<>(referencedCanonicalIds.size());
        for (Map.Entry<String, ResolvedProduct> entry : walk.productsByCanonicalId().entrySet()) {
            if (!referencedCanonicalIds.contains(entry.getKey())) {
                continue; // REVISE item 3 — never referenced by any product_status row, don't persist it
            }
            ResolvedProduct product = entry.getValue();
            productRows.add(new CsafProductInsertRow(vendor, trackingId, entry.getKey(), product.componentName(),
                    product.componentVersion(), product.platformName(), product.cpe(), product.purl(),
                    product.rawLeafName(), dateUpdated));
        }
        csafProductRepository.insertBatch(productRows);

        csafProductStatusRepository.deleteByVendorAndAdvisoryId(vendor, trackingId);
        csafProductStatusRepository.insertBatch(statusRows);

        log.debug("CSAF upsert vendor={} advisory={}: {} products ({} resolved, {} unreferenced and dropped), {} status rows",
                vendor, trackingId, productRows.size(),
                walk.productsByCanonicalId().size(), walk.productsByCanonicalId().size() - productRows.size(), statusRows.size());
        return trackingId;
    }

    private record RemediationInfo(String text, String url) {
    }

    /** {@code remediations[]} (category {@code vendor_fix}) is a standard CSAF vocabulary term, not
     *  vendor-specific — but the fix info is free text (e.g. "Update to V1.8.0 or later version"),
     *  not a clean version field, so it's kept as reference text rather than parsed into a version
     *  this app would compute with (plan §8-2(b) — must never reach {@code
     *  vulnerabilities.fixed_version}). Keyed by the ORIGINAL product_id (remediations reference the
     *  same ids product_status does, pre-fold), matching {@link #upsertCsafDocument}'s lookup.
     *
     *  <p>{@code remediation.url} comes straight from the vendor's own CSAF JSON — just as untrusted as
     *  an LLM's citation URL, and it flows into the same unescaped {@code th:href} sink via {@code
     *  CsafVulnerabilitySource#findingUrl} once persisted. Sanitized here, at ingestion, with the same
     *  {@link SafeUrlValidator} allowlist Stage4/BundledComponent use — a dropped ({@code null}) URL here
     *  makes {@code findingUrl} fall through to its existing hardcoded per-vendor advisory URL, so no
     *  separate fallback branch is needed downstream. */
    private Map<String, RemediationInfo> extractVendorFixRemediations(JsonNode remediations) {
        Map<String, RemediationInfo> byProductId = new HashMap<>();
        for (JsonNode remediation : remediations) {
            if (!"vendor_fix".equals(remediation.path("category").asText(null))) {
                continue;
            }
            String text = remediation.path("details").asText(null);
            String url = SafeUrlValidator.sanitizeHttpUrl(remediation.path("url").asText(null));
            for (JsonNode productIdNode : remediation.path("product_ids")) {
                byProductId.putIfAbsent(productIdNode.asText(), new RemediationInfo(text, url));
            }
        }
        return byProductId;
    }

    private record HighestCvss(BigDecimal score, String severity) {
    }

    /** {@code csaf_advisories} keeps one score/severity per advisory (not per-CVE — a schema-level
     *  simplification, since a document can bundle several CVEs each with their own CVSS score) —
     *  this picks the worst (highest) score across every vulnerability's {@code scores[].cvss_v3},
     *  a "how bad does this advisory get" summary rather than any single CVE's own score. Per-CVE
     *  precision, if ever needed, would require its own column on {@code csaf_product_status}. */
    private HighestCvss extractHighestCvss(JsonNode vulnerabilities) {
        BigDecimal highest = null;
        String highestSeverity = null;
        for (JsonNode vulnerability : vulnerabilities) {
            for (JsonNode score : vulnerability.path("scores")) {
                JsonNode cvssV3 = score.path("cvss_v3");
                if (!cvssV3.has("baseScore")) {
                    continue;
                }
                BigDecimal value = BigDecimal.valueOf(cvssV3.path("baseScore").asDouble());
                if (highest == null || value.compareTo(highest) > 0) {
                    highest = value;
                    highestSeverity = cvssV3.path("baseSeverity").asText(null);
                }
            }
        }
        return new HighestCvss(highest, highestSeverity);
    }

    private OffsetDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException e) {
            try {
                return java.time.LocalDateTime.parse(value).atOffset(java.time.ZoneOffset.UTC);
            } catch (DateTimeParseException e2) {
                return null;
            }
        }
    }
}
