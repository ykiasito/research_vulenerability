package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Stage1 Tier1 lookup against the Maven Central search API, matching on artifactId (and, when
 * possible, exact version). https://search.maven.org/classic/#api
 *
 * <p>Two-step by design, not one exact-first-then-fallback query: querying the {@code gav} core
 * directly with {@code a:"X" AND v:"Y"} sorts by timestamp, not relevance, and was observed live
 * to rank an obscure republished/wrapper artifact above the real, canonical one (e.g. "gson" at a
 * specific version returned {@code dev.galasa:gson} instead of the real
 * {@code com.google.code.gson:gson}) — a confident-looking but wrong match.
 *
 * <p>Step 1 uses the default relevance-ranked core (no {@code core} param, top
 * {@value #CANDIDATE_GROUP_LIMIT} results) to find candidate groupIds for the artifactId, then
 * re-sorts them by {@code versionCount} (highest first, all from that one response — no extra
 * call) before checking any version. This matters because relevance order alone isn't enough to
 * pick the real package: a wrapper/republish can legitimately publish under the *exact same
 * version numbers* as the real upstream (confirmed live: {@code dev.galasa:gson} republishes real
 * gson releases verbatim, so "first candidate whose version matches" would pick it if it simply
 * ranked above the real one) — but a long-running canonical project accumulates far more releases
 * over time than an opportunistic wrapper (real gson: versionCount 44; dev.galasa's wrapper: 3),
 * so versionCount is a much better proxy for "the real package" than relevance/timestamp is.
 * Step 2 then checks each candidate's exact version, in that versionCount order, and uses the
 * first one that confirms it — this also transparently handles a project migrating groupId over
 * time (observed live: Jackson's newer {@code tools.jackson.core} now outranks the classic
 * {@code com.fasterxml.jackson.core} by relevance, but an older version like 2.15.2 only exists
 * under the classic groupId, which also happens to have the far higher versionCount). Ahead of
 * versionCount, candidates where {@code groupId} literally equals {@code artifactId} sort first —
 * the classic pre-2010s Apache/OSS convention (commons-io:commons-io, junit:junit, log4j:log4j)
 * and a near-certain signal of the canonical package on its own, needed because versionCount alone
 * isn't reliable against a prolific wrapper vendor republishing many libraries at once (confirmed
 * live: the same {@code com.guicedee.services} group republishes commons-io, hibernate-core, and
 * others, each with a suspiciously high versionCount). If no candidate confirms the version, falls
 * back to the first candidate in this sort order, unconfirmed.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class MavenCentralRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "maven";
    /**
     * Observed live: for a heavily-squatted artifactId like "commons-io", Maven's default
     * relevance sort ranks the real {@code commons-io:commons-io} 26th of 27 matches — a limit of
     * 5 (or even 20) misses it from the candidate pool entirely, so this is never even a matter of
     * picking wrong, just never seeing the right one. 30 is a pragmatic balance: still one Solr
     * response, still fast, and comfortably covers realistic squatting counts observed so far —
     * not a guarantee against an even more adversarial case, just a meaningfully wider net.
     */
    private static final int CANDIDATE_GROUP_LIMIT = 30;

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    /**
     * Circuit-breaker for the version-check loop below, not a per-request timeout (that's already
     * handled by {@code externalApiRestClient}'s own connect/read timeouts). Measured live
     * 2026-08-24: a generic single-English-word product name (e.g. "echo", "time") can return the
     * full {@value #CANDIDATE_GROUP_LIMIT}-candidate pool, and with none of them confirming the
     * given version, the sequential loop checked every candidate — each with up to {@value
     * #MAX_ATTEMPTS} retried attempts — taking up to ~120-180s for a single registry within a
     * single item (dwarfing a 100-items/1h throughput target on its own). The short-circuit-on-
     * first-confirm behavior stays exactly as before (the common case — a real, correct candidate
     * near the front of the sorted list — is unaffected and still costs only 1-2 calls); this only
     * bounds the pathological worst case where nothing confirms.
     */
    private static final long CANDIDATE_LOOP_BUDGET_MILLIS = 20_000;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        // A full Maven coordinate ("groupId:artifactId", e.g. "com.google.guava:guava") is already
        // unambiguous — searching the relevance-ranked `a:` core with the combined form as if it
        // were a bare artifactId returns zero results (confirmed live against search.maven.org:
        // `a:"com.google.guava:guava"` -> numFound 0, but splitting into `g:"com.google.guava" AND
        // a:"guava"` finds all 150 versions). Skip findCandidateArtifacts entirely in this case and
        // go straight to the version-scoped gav check.
        int lastColon = productName == null ? -1 : productName.lastIndexOf(':');
        if (lastColon > 0 && lastColon < productName.length() - 1) {
            return lookupByCoordinate(productName.substring(0, lastColon), productName.substring(lastColon + 1), version);
        }

        List<CanonicalArtifact> candidates = findCandidateArtifacts(productName);
        if (candidates.isEmpty()) {
            return Optional.empty();
        }

        long deadline = System.currentTimeMillis() + CANDIDATE_LOOP_BUDGET_MILLIS;
        for (CanonicalArtifact candidate : candidates) {
            if (System.currentTimeMillis() > deadline) {
                log.debug("Maven Central version-check loop for productName={} exceeded its time budget "
                        + "after checking some of {} candidates — falling back to the top candidate unconfirmed",
                        productName, candidates.size());
                break;
            }
            if (versionExists(candidate, version)) {
                return Optional.of(toMatch(candidate, version, true));
            }
        }
        return Optional.of(toMatch(candidates.get(0), version, false));
    }

    /** Handles the already-unambiguous {@code groupId:artifactId} coordinate form — see {@link
     *  #lookup}'s javadoc comment above for why this bypasses {@link #findCandidateArtifacts}
     *  entirely. Same return-type convention as {@link #lookup}: a confirmed match on success, an
     *  unconfirmed one on failure — never empty, since the coordinate itself is not in question. */
    private Optional<RegistryMatch> lookupByCoordinate(String groupId, String artifactId, String version) {
        CanonicalArtifact artifact = new CanonicalArtifact(groupId, artifactId, 0);
        boolean versionConfirmed = versionExists(artifact, version);
        return Optional.of(toMatch(artifact, version, versionConfirmed));
    }

    private RegistryMatch toMatch(CanonicalArtifact artifact, String version, boolean versionConfirmed) {
        String packageName = artifact.groupId() + ":" + artifact.artifactId();
        String purl = "pkg:maven/" + artifact.groupId() + "/" + artifact.artifactId() + "@" + version;
        BigDecimal confidence = versionConfirmed ? new BigDecimal("0.95") : new BigDecimal("0.5");
        return new RegistryMatch(ECOSYSTEM, packageName, purl, confidence, versionConfirmed);
    }

    private List<CanonicalArtifact> findCandidateArtifacts(String productName) {
        try {
            JsonNode body = solrSearchWithRetry("a:\"" + productName + "\"", null, CANDIDATE_GROUP_LIMIT);
            if (body == null) {
                return List.of();
            }
            JsonNode docs = body.path("response").path("docs");
            if (!docs.isArray()) {
                return List.of();
            }

            Map<String, CanonicalArtifact> byKey = new LinkedHashMap<>();
            for (JsonNode doc : docs) {
                String groupId = doc.path("g").asText();
                String artifactId = doc.path("a").asText();
                int versionCount = doc.path("versionCount").asInt(0);
                if (!groupId.isBlank() && !artifactId.isBlank()) {
                    byKey.put(groupId + ":" + artifactId, new CanonicalArtifact(groupId, artifactId, versionCount));
                }
            }

            List<CanonicalArtifact> candidates = new ArrayList<>(byKey.values());
            // groupId == artifactId is the classic pre-2010s Apache/OSS convention (commons-io,
            // commons-lang, junit, log4j, ...) and a near-certain signal of the real canonical
            // package when present — checked ahead of versionCount because versionCount alone
            // isn't reliable against a prolific wrapper vendor republishing many libraries at once
            // (confirmed live: com.guicedee.services:commons-io has versionCount 446 vs. the real
            // commons-io:commons-io's 35 — versionCount order alone would still pick the wrapper).
            candidates.sort(Comparator
                    .comparing((CanonicalArtifact a) -> a.groupId().equals(a.artifactId()) ? 1 : 0)
                    .thenComparingInt(CanonicalArtifact::versionCount)
                    .reversed());
            return candidates;
        } catch (Exception e) {
            log.debug("Maven Central candidate search failed for productName={}", productName, e);
            return List.of();
        }
    }

    /** Scoped to one already-known groupId:artifactId — unlike the unscoped {@code gav} query,
     *  there's no cross-package ambiguity left to sort incorrectly. */
    private boolean versionExists(CanonicalArtifact artifact, String version) {
        try {
            String query = "g:\"" + artifact.groupId() + "\" AND a:\"" + artifact.artifactId() + "\" AND v:\"" + version + "\"";
            JsonNode body = solrSearchWithRetry(query, "gav", 1);
            return body != null && body.path("response").path("docs").isArray()
                    && !body.path("response").path("docs").isEmpty();
        } catch (Exception e) {
            log.debug("Maven Central version check failed for {}:{}:{}", artifact.groupId(), artifact.artifactId(), version, e);
            return false;
        }
    }

    /**
     * A single {@link #lookup} call can issue up to {@value #CANDIDATE_GROUP_LIMIT} + 1
     * sequential requests to search.maven.org with no pacing between them (unlike NVD, which has
     * a dedicated rate limiter) — confirmed live that Maven Central occasionally stalls or times
     * out under this pattern. Without a retry, a single transient timeout on the version check
     * for the *real* candidate silently falls through to the next (possibly wrong) candidate and
     * is indistinguishable from a genuine "version doesn't exist" — observed live: a transient
     * failure checking {@code org.hibernate:hibernate-core:6.2.13.Final} (which does exist) left
     * the wrapper package {@code com.guicedee.services:hibernate-core} as the unconfirmed result
     * instead. A single retry still wasn't enough in practice — also observed live, on the
     * *candidate search* call itself (not just a per-candidate version check), the whole item came
     * back completely UNIDENTIFIED with no fallback at all. Up to {@value #MAX_ATTEMPTS} total
     * attempts is cheap insurance either way; a hard outage still degrades the same as before
     * (empty candidates / unconfirmed fallback), just after trying harder first.
     */
    private static final int MAX_ATTEMPTS = 3;

    private JsonNode solrSearchWithRetry(String query, String core, int rows) {
        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return solrSearch(query, core, rows);
            } catch (Exception e) {
                lastError = e;
                log.debug("Maven Central request failed (attempt {}/{}): query={}", attempt, MAX_ATTEMPTS, query, e);
                if (attempt < MAX_ATTEMPTS) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        return null;
                    }
                }
            }
        }
        log.debug("Maven Central request failed after {} attempts: query={}", MAX_ATTEMPTS, query, lastError);
        return null;
    }

    private JsonNode solrSearch(String query, String core, int rows) {
        rateLimiter.awaitTurn(ECOSYSTEM);
        return externalApiRestClient.get()
                .uri(uriBuilder -> {
                    var builder = uriBuilder
                            .scheme("https")
                            .host("search.maven.org")
                            .path("/solrsearch/select")
                            .queryParam("q", query)
                            .queryParam("rows", rows)
                            .queryParam("wt", "json");
                    if (core != null) {
                        builder.queryParam("core", core);
                    }
                    return builder.build();
                })
                .retrieve()
                .body(JsonNode.class);
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }

    private record CanonicalArtifact(String groupId, String artifactId, int versionCount) {
    }
}
