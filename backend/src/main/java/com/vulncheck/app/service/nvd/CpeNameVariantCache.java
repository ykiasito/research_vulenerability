package com.vulncheck.app.service.nvd;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Process-wide memo of "what did the short-form/long-form name-variant search (acronym
 * contraction, initialism expansion, vendor-prefix strip) find for this (vendor, productName)",
 * mirroring {@link com.vulncheck.app.service.registry.RegistryLookupCache}'s own precedent and
 * rationale: this project's CSVs repeat the same product name across many version-duplicate rows
 * (see that class's javadoc for the measured repeat rate), and the variant search this backs is
 * deliberately more expensive than the plain literal lookup (an extra dictionary round trip or
 * two, capped but real) precisely because it only ever runs when the cheap literal search already
 * failed — the exact case most likely to recur unchanged across duplicate rows in the same job.
 *
 * <p>Only caches the *result* of the variant search, not the cheap literal pg_trgm search itself
 * (that one is already fast and unconditionally re-run per {@code identify()} call regardless).
 */
@Component
@Slf4j
public class CpeNameVariantCache {

    private static final long TTL_MILLIS = 6 * 60 * 60 * 1000L;
    /**
     * Lowered from 100,000 (senior review, 2026-08-25): each entry can cache up to {@code
     * CPE_CANDIDATE_POOL} (40) {@link CpeDictionaryEntry} rows, each carrying full {@code title}/
     * {@code cpe_string} strings — 100,000 entries was a worst-case ~1GB heap. This search only
     * ever runs as a last resort after both the literal dictionary search and the live NVD fallback
     * have already failed, so it's a much smaller working set than {@link
     * com.vulncheck.app.service.registry.RegistryLookupCache}'s own limit; 10,000 entries is still
     * generous headroom for a single job's worth of distinct unresolved product names while keeping
     * the worst case in the tens-of-MB range.
     */
    private static final int MAX_ENTRIES = 10_000;

    private record Entry(List<CpeDictionaryEntry> value, long expiresAtMillis) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();

    /**
     * Deliberately not {@code computeIfAbsent} — same reasoning as {@code RegistryLookupCache#get}:
     * the supplier does real (if local-only) database work, and {@code computeIfAbsent} would hold
     * a bin lock on the map for that whole time. Two concurrent lookups of the same key can
     * therefore both compute — harmless and rare.
     */
    public List<CpeDictionaryEntry> get(String vendor, String productName, Supplier<List<CpeDictionaryEntry>> compute) {
        // A plain space can appear in real vendor/product text, so it cannot safely separate the
        // two fields here: vendor "a b" + product "c" would collide with vendor "a" + product
        // "b c". A NUL character cannot appear in real input, so it is used instead as an
        // explicit escaped char literal (not a raw control byte embedded in this source file).
        String key = (vendor == null ? "" : vendor) + '\0' + productName;
        long now = System.currentTimeMillis();

        Entry cached = entries.get(key);
        if (cached != null && cached.expiresAtMillis() > now) {
            return cached.value();
        }

        List<CpeDictionaryEntry> value = compute.get();
        if (entries.size() >= MAX_ENTRIES) {
            log.info("CPE name-variant cache reached {} entries — clearing", MAX_ENTRIES);
            entries.clear();
        }
        entries.put(key, new Entry(value, now + TTL_MILLIS));
        return value;
    }
}
