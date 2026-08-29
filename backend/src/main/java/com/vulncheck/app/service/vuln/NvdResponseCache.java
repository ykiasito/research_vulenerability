package com.vulncheck.app.service.vuln;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Process-wide memo of "what did NVD say about this exact {@code cpeName}", modeled on {@link
 * com.vulncheck.app.service.registry.RegistryLookupCache}'s pattern for the same reason: real CSV
 * inventories repeat the same product/version across many rows (see that class's javadoc for the
 * measured duplication rate), and {@link NvdVulnerabilitySource} queries a fully version-qualified
 * CPE — unlike the registry cache, there is no coarser reusable key here (NVD resolves version
 * applicability server-side against the exact CPE we send), so this is keyed on the complete
 * {@code cpeName} string as-is, no re-derivation logic needed.
 *
 * <p>Only a successful {@link SourceResult} (including a genuine empty-findings one — "NVD checked
 * and this exact CPE has no CVEs" is a real, reusable answer) is cached. A {@link
 * SourceResult#failure()} is never cached: that means the call itself didn't complete (network
 * error, rate limit, ...), so caching it would durably mask a transient failure as "checked, found
 * nothing" for every later duplicate of the same CPE.
 *
 * <p>Bounded and time-limited the same way as {@code RegistryLookupCache}: entries expire after
 * {@link #TTL_MILLIS} and the map is cleared wholesale (not LRU-evicted) if it ever exceeds {@link
 * #MAX_ENTRIES} — this is a pure optimization, so the worst case of a dropped entry is one extra
 * NVD request.
 */
@Component
@Slf4j
public class NvdResponseCache {

    private static final long TTL_MILLIS = 6 * 60 * 60 * 1000L;
    private static final int MAX_ENTRIES = 100_000;

    private record Entry(List<VulnFinding> findings, long expiresAtMillis) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    /**
     * Returns the cached {@link SourceResult} for this exact {@code cpeName}, or invokes {@code
     * lookup} and (only on success) stores it.
     *
     * <p>Deliberately not {@code computeIfAbsent} — same rationale as {@code
     * RegistryLookupCache#get}: {@code lookup} performs a rate-limited network call taking seconds,
     * and {@code computeIfAbsent} would hold a bin lock on the map for that whole time. Two
     * concurrent lookups of the same CPE can therefore both call NVD — harmless and rare, and much
     * cheaper than serializing the map.
     */
    public SourceResult get(String cpeName, Supplier<SourceResult> lookup) {
        long now = System.currentTimeMillis();

        Entry cached = entries.get(cpeName);
        if (cached != null && cached.expiresAtMillis() > now) {
            hits.incrementAndGet();
            return SourceResult.success(cached.findings());
        }

        misses.incrementAndGet();
        SourceResult result = lookup.get();
        if (result.succeeded()) {
            if (entries.size() >= MAX_ENTRIES) {
                log.info("NVD response cache reached {} entries — clearing", MAX_ENTRIES);
                entries.clear();
            }
            entries.put(cpeName, new Entry(List.copyOf(result.findings()), now + TTL_MILLIS));
        }
        return result;
    }

    /** Hit/miss counters, for reporting how much NVD traffic was actually avoided. */
    public String stats() {
        long hit = hits.get();
        long miss = misses.get();
        long total = hit + miss;
        return "nvdResponseCache hits=" + hit + " misses=" + miss + " entries=" + entries.size()
                + (total > 0 ? " hitRate=" + (100 * hit / total) + "%" : "");
    }
}
