package com.vulncheck.app.service.registry;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Process-wide memo of "what did this registry say about this package", so a name that appears
 * more than once never costs more than one lookup per registry.
 *
 * <p>Closed-mode B3 turned every registry lookup into a local {@code registry_package_mirror} DB
 * read instead of a rate-limited public-registry HTTP call, but that didn't remove the case for
 * this cache — its value was never really about hiding network latency, it was about not repeating
 * work for duplicate-heavy input. Measured across the real test corpora (jobs 30 and 31,
 * 2026-08-25): <b>1,350 items covered only 443 distinct product names</b> — two thirds of every
 * lookup was a repeat of one already answered. Software inventories are like this by nature; the
 * same runtime, framework or utility is installed on many hosts, and each host is its own CSV row.
 * With up to a ten-way registry fan-out per item (see {@code RegistryRoutingPolicy}), skipping the
 * repeat still saves real per-item DB round trips at job scale, even though each individual one is
 * now cheap rather than a multi-second network call.
 *
 * <p><b>Keyed by (ecosystem, productName) only — deliberately not version.</b> The cache used to
 * include the version in its key, which measured 2026-08-25 data showed was nearly useless: those
 * same 1,350 items had ~1,349 distinct (name, version) pairs, a ~0.07% hit rate on that key shape,
 * because two hosts running the same product are rarely on the exact same version. Package
 * *existence* is not version-specific — only whether one particular version is confirmed to exist
 * is — so the key drops version entirely and {@link #get} re-derives the version-specific answer
 * from the cached entry's own {@link RegistryMatch#versions()} instead of re-querying. When that
 * list isn't available (see {@code versions}'s own javadoc for which lookups don't have one),
 * {@link #get} falls back to only reusing a hit for the exact version it was originally answered
 * for, same as the old key shape — never wrong, just not improved for those.
 *
 * <p><b>Negative results are cached too</b>, and unlike positive results this is always safe
 * regardless of version — a registry genuinely not having a package at all doesn't depend on which
 * version was asked. With a ten-way fan-out most lookups are misses, so caching only the hits would
 * leave the bulk of the traffic untouched.
 *
 * <p>Bounded and time-limited because this lives for the life of the process: entries expire after
 * {@link #TTL_MILLIS} (registry contents do change — a version published mid-job should not be
 * masked indefinitely) and the map is cleared wholesale if it ever exceeds {@link #MAX_ENTRIES}.
 * A full clear rather than an LRU eviction is deliberate: this is a pure optimization where the
 * worst case of dropping a still-useful entry is one extra request, so paying for LRU bookkeeping
 * on every read would cost more than it saves.
 */
@Component
@Slf4j
public class RegistryLookupCache {

    private static final long TTL_MILLIS = 6 * 60 * 60 * 1000L;
    private static final int MAX_ENTRIES = 100_000;

    // Matches every PackageRegistryLookup implementation that populates RegistryMatch#versions —
    // see NpmRegistryClient et al. Re-derived answers reuse these same two constants rather than
    // whatever confidence the cached entry's own (possibly different) version happened to get.
    private static final BigDecimal VERSION_CONFIRMED_CONFIDENCE = new BigDecimal("0.95");
    private static final BigDecimal VERSION_UNCONFIRMED_CONFIDENCE = new BigDecimal("0.5");

    private record Entry(Optional<RegistryMatch> value, String queriedVersion, long expiresAtMillis) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicLong hits = new AtomicLong();
    private final AtomicLong misses = new AtomicLong();

    /**
     * Returns the cached answer for this (ecosystem, productName) at this version, or computes and
     * stores it.
     *
     * <p>Deliberately not {@code computeIfAbsent}: the supplier performs a database read (against
     * the shared HikariCP connection pool), and {@code computeIfAbsent} would hold a bin lock on
     * the map for that whole round trip, blocking unrelated keys that happen to hash to the same
     * bin. Two concurrent lookups of the same key can therefore both issue a query — harmless and
     * rare, and much cheaper than serializing the map.
     */
    public Optional<RegistryMatch> get(String ecosystem, String productName, String version,
            Supplier<Optional<RegistryMatch>> lookup) {
        String key = ecosystem + " " + productName;
        long now = System.currentTimeMillis();

        Entry cached = entries.get(key);
        if (cached != null && cached.expiresAtMillis() > now) {
            Optional<RegistryMatch> reused = reuseForVersion(cached, version);
            if (reused != null) {
                hits.incrementAndGet();
                return reused;
            }
            // A positive match was cached, but for a different version than requested, and this
            // entry didn't capture a version list to safely re-derive from — fall through to a
            // fresh lookup rather than risk stale version-specific fields (falls into the miss
            // path below, same as if there had been no entry at all).
        }

        misses.incrementAndGet();
        Optional<RegistryMatch> value = lookup.get();
        if (entries.size() >= MAX_ENTRIES) {
            log.info("Registry lookup cache reached {} entries — clearing", MAX_ENTRIES);
            entries.clear();
        }
        entries.put(key, new Entry(value, version, now + TTL_MILLIS));
        return value;
    }

    /**
     * @return the reusable answer for {@code requestedVersion}, or {@code null} if this cache
     *         entry cannot safely answer for that version (caller must treat that as a miss). A
     *         cached negative result ({@code Optional.empty()}) is always reusable — package
     *         non-existence isn't version-specific.
     */
    private Optional<RegistryMatch> reuseForVersion(Entry cached, String requestedVersion) {
        if (cached.value().isEmpty()) {
            return Optional.empty();
        }
        RegistryMatch match = cached.value().get();
        if (!match.versions().isEmpty()) {
            boolean exists = versionListContains(match.ecosystem(), match.versions(), requestedVersion);
            String purl = match.purl().substring(0, match.purl().lastIndexOf('@') + 1) + requestedVersion;
            BigDecimal confidence = exists ? VERSION_CONFIRMED_CONFIDENCE : VERSION_UNCONFIRMED_CONFIDENCE;
            return Optional.of(new RegistryMatch(match.ecosystem(), match.packageName(), purl, confidence, exists, match.versions()));
        }
        return cached.queriedVersion().equals(requestedVersion) ? cached.value() : null;
    }

    /**
     * Mirrors each {@code PackageRegistryLookup} client's own version-match semantics — most
     * compare exact/case-sensitive, but {@code NuGetRegistryClient} confirms a version with
     * {@code equalsIgnoreCase} (NuGet package/version identifiers are
     * case-insensitive there). A fresh NuGet lookup would confirm "1.0.0-Beta" against a published
     * "1.0.0-beta"; without this, a re-derived cache-hit answer for the exact same input would
     * disagree — {@code exists=false} where a fresh call says {@code true} — silently under-
     * confirming a version purely because this entry happened to come from cache.
     */
    private boolean versionListContains(String ecosystem, List<String> versions, String requestedVersion) {
        if ("nuget".equals(ecosystem)) {
            return versions.stream().anyMatch(v -> v.equalsIgnoreCase(requestedVersion));
        }
        return versions.contains(requestedVersion);
    }

    /** Hit/miss counters, for reporting how much registry traffic was actually avoided. */
    public String stats() {
        long hit = hits.get();
        long miss = misses.get();
        long total = hit + miss;
        return "registryLookupCache hits=" + hit + " misses=" + miss + " entries=" + entries.size()
                + (total > 0 ? " hitRate=" + (100 * hit / total) + "%" : "");
    }
}
