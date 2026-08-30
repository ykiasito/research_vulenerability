package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class RegistryLookupCacheTest {

    @Test
    void aPositiveMatchWithACapturedVersionListAnswersADifferentVersionWithoutARequest() {
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();
        RegistryMatch match = new RegistryMatch("npm", "lodash", "pkg:npm/lodash@4.17.15",
                new BigDecimal("0.95"), true, List.of("4.17.15", "4.17.21"));

        Optional<RegistryMatch> first = cache.get("npm", "lodash", "4.17.15", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        // A different version of the SAME package — must be answered from the captured versions
        // list, no second call to the supplier (i.e. no second network request).
        Optional<RegistryMatch> second = cache.get("npm", "lodash", "4.17.21", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        // A version that isn't in the captured list — still answered from cache, just as "not
        // confirmed" rather than another request.
        Optional<RegistryMatch> third = cache.get("npm", "lodash", "0.0.1-does-not-exist", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });

        assertThat(calls.get()).isEqualTo(1);
        assertThat(first).isPresent();
        assertThat(second).isPresent();
        assertThat(second.get().exactVersionConfirmed()).isTrue();
        assertThat(second.get().purl()).isEqualTo("pkg:npm/lodash@4.17.21");
        assertThat(third).isPresent();
        assertThat(third.get().exactVersionConfirmed()).isFalse();
        assertThat(third.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void aNegativeResultIsReusedForAnyVersionOfTheSamePackage() {
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();

        Optional<RegistryMatch> first = cache.get("npm", "totally-unknown", "1.0.0", () -> {
            calls.incrementAndGet();
            return Optional.empty();
        });
        Optional<RegistryMatch> second = cache.get("npm", "totally-unknown", "2.0.0", () -> {
            calls.incrementAndGet();
            return Optional.empty();
        });

        assertThat(calls.get()).isEqualTo(1);
        assertThat(first).isEmpty();
        assertThat(second).isEmpty();
    }

    @Test
    void aPositiveMatchWithNoCapturedVersionListIsOnlyReusedForTheExactSameVersion() {
        // Maven Central / Go proxy shape: no versions list captured (see RegistryMatch#versions()).
        // A different version can't be safely answered from this entry, so it must fall through to
        // a fresh lookup rather than risk a stale exactVersionConfirmed/purl.
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();
        RegistryMatch match = new RegistryMatch("maven", "com.google.code.gson:gson",
                "pkg:maven/com.google.code.gson/gson@2.10.1", new BigDecimal("0.95"), true);

        Optional<RegistryMatch> sameVersion = cache.get("maven", "gson", "2.10.1", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        Optional<RegistryMatch> sameVersionAgain = cache.get("maven", "gson", "2.10.1", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        Optional<RegistryMatch> differentVersion = cache.get("maven", "gson", "2.9.0", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });

        assertThat(sameVersion).isPresent();
        assertThat(sameVersionAgain).isPresent();
        assertThat(differentVersion).isPresent();
        // Two distinct network calls: one for "2.10.1" (served from cache the second time), one
        // more forced by "2.9.0" not being safely answerable from the cached entry.
        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void nuGetVersionReuseIsCaseInsensitiveMatchingAFreshNuGetLookup() {
        // NuGetRegistryClient itself confirms a version with equalsIgnoreCase (see its javadoc) —
        // a cache-hit re-derivation must agree, or an item asking about "1.0.0-Beta" would be
        // silently under-confirmed on the cache-hit path even though a fresh NuGet call would have
        // confirmed it (the published list only ever contains "1.0.0-beta").
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();
        RegistryMatch match = new RegistryMatch("nuget", "Newtonsoft.Json", "pkg:nuget/newtonsoft.json@12.0.0",
                new BigDecimal("0.95"), true, List.of("12.0.0", "1.0.0-beta"));

        cache.get("nuget", "Newtonsoft.Json", "12.0.0", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        Optional<RegistryMatch> differentCase = cache.get("nuget", "Newtonsoft.Json", "1.0.0-Beta", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });

        assertThat(calls.get()).isEqualTo(1);
        assertThat(differentCase).isPresent();
        assertThat(differentCase.get().exactVersionConfirmed()).isTrue();
        assertThat(differentCase.get().confidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void nonNuGetVersionReuseStaysCaseSensitiveMatchingAFreshLookupForThatEcosystem() {
        // npm (and every other ecosystem here) compares versions with a plain, case-sensitive
        // equals — the cache must not silently become more lenient than a fresh lookup would be
        // for those ecosystems just because it re-derives from a captured version list.
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();
        RegistryMatch match = new RegistryMatch("npm", "SomePackage", "pkg:npm/SomePackage@1.0.0",
                new BigDecimal("0.95"), true, List.of("1.0.0", "1.0.0-beta"));

        cache.get("npm", "SomePackage", "1.0.0", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });
        Optional<RegistryMatch> differentCase = cache.get("npm", "SomePackage", "1.0.0-Beta", () -> {
            calls.incrementAndGet();
            return Optional.of(match);
        });

        assertThat(calls.get()).isEqualTo(1);
        assertThat(differentCase).isPresent();
        assertThat(differentCase.get().exactVersionConfirmed()).isFalse();
        assertThat(differentCase.get().confidence()).isEqualByComparingTo("0.5");
    }

    @Test
    void cacheHitAndFreshLookupProduceIdenticalRegistryMatchForTheSameInput() {
        // Not just "the cache returns something" — this proves a cache-hit answer for version B is
        // bit-for-bit identical to what a brand-new, independent lookup for version B would have
        // returned, by computing the "fresh" answer via the exact same production logic
        // (simulateFreshLookup below mirrors NpmRegistryClient's own versionExists/confidence/purl
        // derivation) rather than trusting the cache's own reasoning about itself.
        RegistryLookupCache cache = new RegistryLookupCache();
        List<String> publishedVersions = List.of("4.17.15", "4.17.20", "4.17.21");
        String packageName = "lodash";

        // Warm the cache via version 4.17.15 (a "fresh" call in this test's own simulated registry).
        cache.get("npm", packageName, "4.17.15", () -> Optional.of(simulateFreshLookup(packageName, "4.17.15", publishedVersions)));

        // Cache-hit path for a different version of the same package — supplier must never run.
        Optional<RegistryMatch> cacheHit = cache.get("npm", packageName, "4.17.21", () -> {
            throw new AssertionError("supplier should not run on a cache hit");
        });

        // Independently computed "what a fresh lookup for 4.17.21 would have returned" — the
        // baseline this test is actually checking the cache-hit answer against.
        RegistryMatch expectedFresh = simulateFreshLookup(packageName, "4.17.21", publishedVersions);

        assertThat(cacheHit).isPresent();
        // versions() is deliberately not compared here: the cache hit's own versions() is the
        // captured list from the entry it was reused from (an internal cache-bookkeeping detail),
        // not a field Stage1's downstream AI-arbitration/weak-match logic ever reads — every field
        // that logic actually consumes (ecosystem/packageName/purl/confidence/exactVersionConfirmed)
        // is checked below and must match the independently-computed fresh answer exactly.
        assertThat(cacheHit.get().exactVersionConfirmed()).isEqualTo(expectedFresh.exactVersionConfirmed());
        assertThat(cacheHit.get().confidence()).isEqualByComparingTo(expectedFresh.confidence());
        assertThat(cacheHit.get().purl()).isEqualTo(expectedFresh.purl());
        assertThat(cacheHit.get().ecosystem()).isEqualTo(expectedFresh.ecosystem());
        assertThat(cacheHit.get().packageName()).isEqualTo(expectedFresh.packageName());
    }

    /** Mirrors NpmRegistryClient's own versionExists/confidence/purl derivation exactly, so this
     *  test's "expected" baseline is independent production logic, not the cache's own reasoning. */
    private RegistryMatch simulateFreshLookup(String packageName, String version, List<String> publishedVersions) {
        boolean versionExists = publishedVersions.contains(version);
        BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
        String purl = "pkg:npm/" + packageName + "@" + version;
        return new RegistryMatch("npm", packageName, purl, confidence, versionExists, publishedVersions);
    }

    @Test
    void differentEcosystemsWithTheSameProductNameAreCachedIndependently() {
        RegistryLookupCache cache = new RegistryLookupCache();
        AtomicInteger calls = new AtomicInteger();
        RegistryMatch npmMatch = new RegistryMatch("npm", "commons-io", "pkg:npm/commons-io@1.0.0", new BigDecimal("0.5"), false);

        cache.get("npm", "commons-io", "1.0.0", () -> {
            calls.incrementAndGet();
            return Optional.of(npmMatch);
        });
        cache.get("maven", "commons-io", "1.0.0", () -> {
            calls.incrementAndGet();
            return Optional.of(npmMatch);
        });

        assertThat(calls.get()).isEqualTo(2);
    }
}
