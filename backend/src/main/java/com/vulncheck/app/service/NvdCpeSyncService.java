package com.vulncheck.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Mirrors (a subset of) the NVD CPE Dictionary into the local {@code cpe_dictionary} table, which
 * Stage1 Tier1 then fuzzy-matches against via pg_trgm instead of hitting NVD synchronously per
 * product lookup.
 *
 * <p>Works without an API key (5 req/30s). If the calling user has registered an NVD key via
 * {@code UserApiKeyService}, callers pass it through here and it's sent as the {@code apiKey}
 * request header, raising the limit to 50 req/30s (see {@link NvdRateLimiter}) — a full mirror
 * (~1.3M entries) still isn't practical even with a key, so {@link #syncByKeyword} remains the
 * practical entry point, while {@link #syncAllAndRelease} is the same pagination loop with no
 * keyword filter for when a full mirror is actually wanted.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NvdCpeSyncService {

    private static final String NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    /** NVD's documented maximum for this endpoint. At ~1.8M total CPEs this is the difference
     *  between 182 requests and 908 — and since each request pays a fixed rate-limit wait
     *  (6.5s unkeyed), the page count, not the byte count, dominates total sync time. */
    private static final int RESULTS_PER_PAGE = 10000;

    private final RestClient externalApiRestClient;
    private final RestClient nvdSyncRestClient;
    private final CpeDictionaryRepository cpeDictionaryRepository;
    private final NvdRateLimiter nvdRateLimiter;

    /** Full-sync "already running" guard, shared across every caller of {@link #tryBeginFullSync}
     *  (admin-triggered and startup-triggered) — matching this codebase's existing convention of
     *  an {@code AtomicBoolean running} guard held by the service itself (see {@code
     *  SiemensCsafSyncService}, {@code GhsaSyncService}, {@code OsvSyncService}), rather than by
     *  each caller separately. The CAS in {@link #tryBeginFullSync} is itself the acquisition —
     *  callers must not check-then-call, since that would reopen the exact TOCTOU window this
     *  guard exists to close. */
    private final AtomicBoolean fullSyncRunning = new AtomicBoolean(false);

    /** Syncs only CPEs matching the given keyword — the practical way to populate/test locally. */
    public int syncByKeyword(String keyword, Optional<String> apiKey) {
        return sync(keyword, apiKey);
    }

    /**
     * Attempts to reserve the full-sync slot; returns {@code true} only for the caller that wins
     * the race. Callers that get {@code false} must not proceed to call {@link
     * #syncAllAndRelease} — another full sync (admin-triggered or startup-triggered) is already
     * in flight and would otherwise double the upsert load on {@code cpe_dictionary} and halve
     * the shared {@link NvdRateLimiter}'s effective throughput for every other concurrent caller.
     */
    public boolean tryBeginFullSync() {
        return fullSyncRunning.compareAndSet(false, true);
    }

    /**
     * Full mirror sync, no keyword filter. Slow (rate-limited) — intended for a scheduled/off-hours
     * run. Callers must only invoke this after {@link #tryBeginFullSync} returned {@code true}; the
     * slot is released here unconditionally (success or exception) so a failed sync doesn't
     * permanently wedge the guard.
     */
    public int syncAllAndRelease(Optional<String> apiKey) {
        try {
            return sync(null, apiKey);
        } finally {
            fullSyncRunning.set(false);
        }
    }

    /**
     * Single-page, on-demand keyword lookup — bounded to exactly one rate-limited NVD call, never
     * paginates. Used by {@code Stage1IdentificationService} when the local dictionary has no
     * candidates at all for a product, so an unknown-to-us product can still be resolved live
     * instead of requiring someone to have pre-synced that keyword via the admin screen first.
     * Upserted rows land in the same {@code cpe_dictionary} table, so the lookup doubly serves as
     * an incremental cache warm for future items with the same/similar product name.
     */
    public int syncKeywordSinglePage(String keyword, int resultsPerPage, Optional<String> apiKey) {
        nvdRateLimiter.awaitTurn(apiKey.isPresent());
        JsonNode page = fetchPage(keyword, 0, resultsPerPage, apiKey);
        if (page == null) {
            return 0;
        }
        int upserted = 0;
        for (JsonNode productNode : page.path("products")) {
            if (upsertProduct(productNode.path("cpe"))) {
                upserted++;
            }
        }
        return upserted;
    }

    private int sync(String keyword, Optional<String> apiKey) {
        int startIndex = 0;
        int totalUpserted = 0;
        int totalResults = Integer.MAX_VALUE;

        while (startIndex < totalResults) {
            nvdRateLimiter.awaitTurn(apiKey.isPresent());
            JsonNode page = fetchPage(keyword, startIndex, RESULTS_PER_PAGE, apiKey, nvdSyncRestClient);
            if (page == null) {
                break;
            }

            totalResults = page.path("totalResults").asInt(0);
            JsonNode products = page.path("products");

            // Batched rather than a statement per row: a full sync is ~1.8M rows, where per-row
            // round trips dominate the runtime far more than the NVD transfer itself does.
            List<CpeDictionaryEntry> batch = new ArrayList<>(products.size());
            for (JsonNode productNode : products) {
                CpeDictionaryEntry entry = toEntry(productNode.path("cpe"));
                if (entry != null) {
                    batch.add(entry);
                }
            }
            cpeDictionaryRepository.upsertBatch(batch);
            totalUpserted += batch.size();

            int fetched = products.size();
            startIndex += fetched;
            log.info("NVD CPE sync progress: {}/{} (keyword={})", startIndex, totalResults, keyword);

            if (fetched == 0) {
                break;
            }
        }

        return totalUpserted;
    }

    private JsonNode fetchPage(String keyword, int startIndex, int resultsPerPage, Optional<String> apiKey) {
        return fetchPage(keyword, startIndex, resultsPerPage, apiKey, externalApiRestClient);
    }

    private JsonNode fetchPage(String keyword, int startIndex, int resultsPerPage, Optional<String> apiKey,
            RestClient restClient) {
        UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromHttpUrl(NVD_CPE_API)
                .queryParam("resultsPerPage", resultsPerPage)
                .queryParam("startIndex", startIndex);
        if (keyword != null && !keyword.isBlank()) {
            uriBuilder.queryParam("keywordSearch", keyword);
        }
        URI uri = uriBuilder.build().toUri();

        try {
            return restClient.get()
                    .uri(uri)
                    .headers(headers -> apiKey.ifPresent(key -> headers.set("apiKey", key)))
                    .retrieve()
                    .body(JsonNode.class);
        } catch (Exception e) {
            log.error("NVD CPE API request failed at startIndex={}", startIndex, e);
            return null;
        }
    }

    /** Parsed form of one CPE API product node, or null when it carries no usable {@code cpeName}. */
    private CpeDictionaryEntry toEntry(JsonNode cpe) {
        String cpeName = cpe.path("cpeName").asText(null);
        if (cpeName == null) {
            return null;
        }
        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(cpeName);
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeName);
        entry.setTitle(englishTitle(cpe));
        entry.setVendor(vendorProduct != null ? vendorProduct.vendor() : null);
        entry.setProduct(vendorProduct != null ? vendorProduct.product() : null);
        return entry;
    }

    private String englishTitle(JsonNode cpe) {
        for (JsonNode titleNode : cpe.path("titles")) {
            if ("en".equals(titleNode.path("lang").asText())) {
                return titleNode.path("title").asText(null);
            }
        }
        return cpe.path("titles").size() > 0 ? cpe.path("titles").get(0).path("title").asText(null) : null;
    }

    private boolean upsertProduct(JsonNode cpe) {
        String cpeName = cpe.path("cpeName").asText(null);
        if (cpeName == null) {
            return false;
        }

        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(cpeName);
        String vendor = vendorProduct != null ? vendorProduct.vendor() : null;
        String product = vendorProduct != null ? vendorProduct.product() : null;

        String title = null;
        for (JsonNode titleNode : cpe.path("titles")) {
            if ("en".equals(titleNode.path("lang").asText())) {
                title = titleNode.path("title").asText(null);
                break;
            }
        }
        if (title == null && cpe.path("titles").size() > 0) {
            title = cpe.path("titles").get(0).path("title").asText(null);
        }

        cpeDictionaryRepository.upsert(cpeName, title, vendor, product);
        return true;
    }
}
