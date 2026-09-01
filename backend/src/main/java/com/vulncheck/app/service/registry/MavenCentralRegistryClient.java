package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

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

    /**
     * REVISE (senior review 2026-08-30, PR #8): {@link #lookup}'s candidate loop used to call the
     * OR'd {@link #versionExists} (Solr, then — only if that didn't confirm — the costlier
     * maven-metadata.xml fetch) per candidate. That doubles the per-candidate cost of the loop
     * whenever nothing confirms via Solr, halving how many of the {@value #CANDIDATE_GROUP_LIMIT}
     * candidates fit in {@value #CANDIDATE_LOOP_BUDGET_MILLIS} compared to before the
     * maven-metadata.xml fallback existed. {@link #lookup} now runs two explicit passes instead:
     * every candidate against {@link #solrVersionExists} alone first (unchanged cost/depth from
     * before the fallback existed), then — only if none of them confirmed — the maven-metadata.xml
     * fallback against just the top few. This constant is that second pass's cap: the fallback only
     * exists to cover Solr's index lag for a genuinely real, recently-published version (see {@link
     * #versionExists}'s javadoc), which is already near the front of the versionCount-sorted
     * candidate list by definition — a stale squatter/wrapper package far down the list isn't the
     * one that just published a brand-new version. 3 is a pragmatic small number to bound the
     * doubled cost to a handful of candidates rather than the whole pool.
     */
    private static final int METADATA_FALLBACK_CANDIDATE_LIMIT = 3;

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
        // Pass 1: every candidate against Solr alone — same per-candidate cost and search depth as
        // before the maven-metadata.xml fallback existed. See METADATA_FALLBACK_CANDIDATE_LIMIT's
        // javadoc for why the costlier fallback below is deliberately NOT applied here to every
        // candidate.
        for (CanonicalArtifact candidate : candidates) {
            if (System.currentTimeMillis() > deadline) {
                log.debug("Maven Central version-check loop for productName={} exceeded its time budget "
                        + "after checking some of {} candidates — falling back to the top candidate unconfirmed",
                        productName, candidates.size());
                break;
            }
            if (solrVersionExists(candidate, version)) {
                return Optional.of(toMatch(candidate, version, true));
            }
        }

        // Pass 2: none of the candidates confirmed via Solr — only now consult the
        // maven-metadata.xml fallback (see #versionExists's javadoc for why it exists), and only
        // for the top METADATA_FALLBACK_CANDIDATE_LIMIT candidates, to avoid doubling the
        // per-candidate cost across the whole candidate pool.
        int metadataFallbackLimit = Math.min(METADATA_FALLBACK_CANDIDATE_LIMIT, candidates.size());
        for (int i = 0; i < metadataFallbackLimit; i++) {
            if (System.currentTimeMillis() > deadline) {
                log.debug("Maven Central maven-metadata.xml fallback pass for productName={} exceeded its "
                        + "time budget — falling back to the top candidate unconfirmed", productName);
                break;
            }
            CanonicalArtifact candidate = candidates.get(i);
            if (metadataXmlHasVersion(candidate, version)) {
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
            JsonNode body = solrSearchWithRetry("a:\"" + escapeLuceneQueryValue(productName) + "\"", null, CANDIDATE_GROUP_LIMIT);
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

    /**
     * Scoped to one already-known groupId:artifactId — unlike the unscoped {@code gav} query,
     * there's no cross-package ambiguity left to sort incorrectly.
     *
     * <p>Confirms via the Solr {@code gav} core first, then — only if that didn't confirm — falls
     * back to the canonical {@code maven-metadata.xml} for the same groupId:artifactId (see {@link
     * #metadataXmlHasVersion}), OR'ing the two together: either source confirming the version is
     * enough. Observed live (golden-300 job191, 2026-08-30): search.maven.org's Solr index can lag
     * behind the real, authoritative {@code maven-metadata.xml} for a newly-published version (e.g.
     * {@code org.springframework:spring-core:7.1.0-M1}, {@code com.zaxxer:HikariCP:7.1.0}),
     * leaving an actually-real version reported as unconfirmed and confidence stuck at 0.5. The
     * short-circuiting {@code ||} keeps the common case (Solr already confirms) at exactly one
     * extra HTTP call, same as before this fix — {@code maven-metadata.xml} is only ever fetched
     * when Solr didn't confirm.
     *
     * <p>This method itself is only used by {@link #lookupByCoordinate}, which has exactly one
     * candidate to check and so pays this OR's worst case (two calls) rarely enough not to matter.
     * {@link #lookup}'s own multi-candidate loop does <em>not</em> call this method — it implements
     * the same OR logic as two explicit passes across the candidate list instead (Solr for every
     * candidate, then the metadata.xml fallback for only the top {@value
     * #METADATA_FALLBACK_CANDIDATE_LIMIT}), so that the fallback's added cost is bounded to a
     * handful of candidates rather than doubling the cost of the whole candidate pool — see {@link
     * #METADATA_FALLBACK_CANDIDATE_LIMIT}'s javadoc.
     */
    private boolean versionExists(CanonicalArtifact artifact, String version) {
        return solrVersionExists(artifact, version) || metadataXmlHasVersion(artifact, version);
    }

    private boolean solrVersionExists(CanonicalArtifact artifact, String version) {
        try {
            String query = "g:\"" + escapeLuceneQueryValue(artifact.groupId()) + "\" AND a:\""
                    + escapeLuceneQueryValue(artifact.artifactId()) + "\" AND v:\"" + escapeLuceneQueryValue(version) + "\"";
            JsonNode body = solrSearchWithRetry(query, "gav", 1);
            return body != null && body.path("response").path("docs").isArray()
                    && !body.path("response").path("docs").isEmpty();
        } catch (Exception e) {
            log.debug("Maven Central version check failed for {}:{}:{}", artifact.groupId(), artifact.artifactId(), version, e);
            return false;
        }
    }

    /**
     * Fallback existence check against the authoritative {@code maven-metadata.xml} for a
     * groupId:artifactId, used only when {@link #solrVersionExists} did not confirm — see {@link
     * #versionExists}'s javadoc for why this exists and why it's OR'd rather than replacing Solr.
     */
    private boolean metadataXmlHasVersion(CanonicalArtifact artifact, String version) {
        byte[] body = fetchMetadataXmlWithRetry(artifact.groupId(), artifact.artifactId());
        if (body == null) {
            return false;
        }
        return parseMetadataVersions(body).stream().anyMatch(v -> v.equals(version));
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

    /**
     * Escapes Lucene/Solr query syntax characters in {@code value} before it's embedded into a
     * quoted {@code q} clause (e.g. {@code a:"..."}) — mirrors {@code
     * org.apache.lucene.queryparser.classic.QueryParser#escape}. Without this, a CSV-supplied
     * {@code productName}/groupId/artifactId/version containing a literal {@code "} could close
     * the quoted phrase early and append arbitrary Solr query syntax of its own choosing.
     * Confirmed live against search.maven.org: an unescaped {@code productName} reaching {@link
     * #findCandidateArtifacts}'s default-core {@code a:"..."} query can be broadened this way into
     * matching artifacts that have nothing to do with the real product — a crafted product name
     * pulled back 13 unrelated candidate artifacts in one live test — so the wrong package is what
     * ends up sorted to the front and returned as the identified match. (A similar-looking attempt
     * to spoof {@link #versionExists}'s {@code gav}-core confirmation query — forging a nonexistent
     * version into a confidence-0.95 "confirmed" result via an injected {@code v:} clause — did
     * not reproduce live: search.maven.org returned HTTP 400 for an injected {@code OR v:*} and
     * {@code numFound: 0} for an injected OR'd literal version.) CSV input is untrusted, so every
     * value reaching a {@code q} parameter here goes through this first, not just the ones that
     * look adversarial today, and not just the ones with a live-confirmed exploit.
     */
    private static String escapeLuceneQueryValue(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '\\' || c == '+' || c == '-' || c == '!' || c == '(' || c == ')' || c == ':'
                    || c == '^' || c == '[' || c == ']' || c == '"' || c == '{' || c == '}' || c == '~'
                    || c == '*' || c == '?' || c == '|' || c == '&' || c == '/') {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }

    /** Hard cap on how much of a {@code maven-metadata.xml} response is read into memory —
     *  defense in depth. A real {@code maven-metadata.xml}, even for a package with hundreds of
     *  releases (e.g. commons-io), is a tiny fraction of this. */
    private static final int MAX_METADATA_RESPONSE_BYTES = 512 * 1024;

    /**
     * Same retry-on-transient-failure policy as {@link #solrSearchWithRetry} (5xx / timeout /
     * {@link IOException}) — see that method's javadoc for why a bare single attempt wasn't enough
     * against Maven Central in practice.
     *
     * <p>REVISE (senior review 2026-08-30, PR #8): a 404 is deliberately excluded from that policy.
     * It's {@link #fetchMetadataXml}'s confirmed, deterministic answer that the coordinate/version
     * doesn't exist — not a transient failure — so {@link #fetchMetadataXml} returns {@code null}
     * directly instead of throwing for any 4xx, and this loop's first attempt simply returns that
     * {@code null} without retrying. Retrying a definitive "not found" up to {@value #MAX_ATTEMPTS}
     * times used to cost 3 wasted requests plus {@code 3x} the shared rate limiter's pacing delay
     * (see {@link ExternalRegistryRateLimiter}, which gates every Maven lookup in the process, not
     * just this one item's) for zero benefit.
     *
     * <p>REVISE (senior review 2026-08-30): a response exceeding {@link #MAX_METADATA_RESPONSE_BYTES}
     * is excluded from the retry policy for the same reason — it's a deterministic rejection of
     * that specific response, not a transient failure, so retrying it wastes the same 3 requests
     * and pacing delay for zero benefit. {@link #fetchMetadataXml} likewise returns {@code null}
     * directly for it instead of letting the underlying {@link ResponseTooLargeException} reach
     * this loop's generic {@code catch (Exception e)} below.
     */
    private byte[] fetchMetadataXmlWithRetry(String groupId, String artifactId) {
        Exception lastError = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            try {
                return fetchMetadataXml(groupId, artifactId);
            } catch (Exception e) {
                lastError = e;
                log.debug("Maven Central maven-metadata.xml request failed (attempt {}/{}): {}:{}",
                        attempt, MAX_ATTEMPTS, groupId, artifactId, e);
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
        log.debug("Maven Central maven-metadata.xml request failed after {} attempts: {}:{}",
                MAX_ATTEMPTS, groupId, artifactId, lastError);
        return null;
    }

    /**
     * groupId/artifactId path segments are restricted to this character set — a defensive check
     * against path traversal, since {@link #fetchMetadataXml} builds a {@code /maven2/...} URL path
     * directly from these values with no framework-level normalization/rejection in between.
     * {@link #lookup}'s own candidate search always supplies these from Maven Central's own {@code
     * g}/{@code a} response fields, but {@link #lookupByCoordinate} takes them straight from a
     * {@code ':'}-split CSV {@code product_name} column with no upstream validation at all — a
     * value like {@code groupId="../../../etc"} would otherwise walk the resulting path outside
     * {@code /maven2/} (repo1.maven.org itself would very likely reject or 404 such a request, but
     * this is defense in depth, not a bet on that).
     */
    private static final Pattern VALID_COORDINATE_SEGMENT = Pattern.compile("[A-Za-z0-9._-]+");

    private static boolean isValidCoordinateSegment(String value) {
        return value != null && !value.isBlank() && !value.contains("..") && VALID_COORDINATE_SEGMENT.matcher(value).matches();
    }

    /** Builds the path directly via the {@code UriBuilder} function form (as {@link #solrSearch}
     *  already does) rather than a {@code {var}} URI template — a template variable containing a
     *  {@code /} (groupId converted to a path, e.g. "com/google/guava") would otherwise get
     *  percent-encoded to {@code %2F} and break the real repository path. */
    private byte[] fetchMetadataXml(String groupId, String artifactId) {
        if (!isValidCoordinateSegment(groupId) || !isValidCoordinateSegment(artifactId)) {
            log.debug("Refusing maven-metadata.xml lookup for invalid coordinate groupId={} artifactId={}",
                    groupId, artifactId);
            return null;
        }
        rateLimiter.awaitTurn(ECOSYSTEM);
        String groupPath = groupId.replace('.', '/');
        return externalApiRestClient.get()
                .uri(uriBuilder -> uriBuilder
                        .scheme("https")
                        .host("repo1.maven.org")
                        .path("/maven2/" + groupPath + "/" + artifactId + "/maven-metadata.xml")
                        .build())
                .exchange((request, response) -> {
                    // REVISE (senior review 2026-08-30, PR #8): a 404 (or any other 4xx) is a
                    // confirmed, deterministic answer — this coordinate/version genuinely doesn't
                    // exist — not a transient failure, so it must not be retried the way a 5xx is.
                    // Returning null here (rather than throwing) makes that the case: see
                    // fetchMetadataXmlWithRetry's javadoc.
                    if (response.getStatusCode().is4xxClientError()) {
                        log.debug("maven-metadata.xml not found for {}:{} status={}", groupId, artifactId,
                                response.getStatusCode());
                        return null;
                    }
                    if (!response.getStatusCode().is2xxSuccessful()) {
                        throw new IllegalStateException(
                                "maven-metadata.xml request returned " + response.getStatusCode());
                    }
                    // A response exceeding the byte cap is likewise a confirmed, deterministic
                    // answer -- not a transient failure -- so it must not be retried either: see
                    // ResponseTooLargeException's and fetchMetadataXmlWithRetry's javadoc.
                    try {
                        return readBounded(response.getBody(), MAX_METADATA_RESPONSE_BYTES);
                    } catch (ResponseTooLargeException e) {
                        log.debug("maven-metadata.xml response exceeded size cap for {}:{}: {}",
                                groupId, artifactId, e.getMessage());
                        return null;
                    }
                });
    }

    /** Parses every {@code <version>} text under {@code <metadata><versioning><versions>} — the
     *  authoritative, always-up-to-date list of published versions for this groupId:artifactId
     *  (unlike the Solr index this fallback exists to cover for — see {@link #versionExists}). */
    private List<String> parseMetadataVersions(byte[] body) {
        try {
            DocumentBuilder builder = newHardenedDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body));
            Element versioning = firstElement(doc.getDocumentElement(), "versioning");
            Element versionsElement = versioning == null ? null : firstElement(versioning, "versions");
            if (versionsElement == null) {
                return List.of();
            }
            NodeList versionNodes = versionsElement.getElementsByTagName("version");
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < versionNodes.getLength(); i++) {
                String text = versionNodes.item(i).getTextContent();
                if (text != null && !text.isBlank()) {
                    versions.add(text.trim());
                }
            }
            return versions;
        } catch (Exception e) {
            log.debug("maven-metadata.xml parse failed", e);
            return List.of();
        }
    }

    /** Returns the first {@code <tagName>} element under {@code parent} (searching all
     *  descendants via {@link Element#getElementsByTagName}, acceptable here since
     *  maven-metadata.xml's structure is flat and controlled), or {@code null} if absent. */
    private static Element firstElement(Element parent, String tagName) {
        if (parent == null) {
            return null;
        }
        NodeList nodes = parent.getElementsByTagName(tagName);
        return nodes.getLength() > 0 ? (Element) nodes.item(0) : null;
    }

    /** XXE-hardened {@link DocumentBuilder} (DOCTYPE declarations disallowed outright, external
     *  general/parameter entity resolution disabled). A fresh instance is built per call since
     *  {@code DocumentBuilderFactory}/{@code DocumentBuilder} are not documented as thread-safe,
     *  and this runs under a concurrent item-processing executor. */
    private DocumentBuilder newHardenedDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder();
    }

    /**
     * REVISE (senior review 2026-08-30): thrown by {@link #readBounded} when a response exceeds
     * its byte cap. This is deliberately unchecked and distinct from the genuine {@link
     * IOException}s the same read loop can still throw (e.g. a real connection drop mid-read) —
     * exceeding the cap is a confirmed, content-based rejection, not a transient I/O failure, so
     * {@link #fetchMetadataXml} catches this one specifically and returns {@code null} the same
     * way it already does for a 404 (see {@link #fetchMetadataXmlWithRetry}'s javadoc for why a
     * deterministic "no" must not be retried), while a genuine {@link IOException} still falls
     * through to that retry loop unchanged.
     */
    private static final class ResponseTooLargeException extends RuntimeException {
        ResponseTooLargeException(String message) {
            super(message);
        }
    }

    /** Reads {@code in} fully into memory, failing fast if it would exceed {@code maxBytes} —
     *  defense in depth against an unexpectedly large response. */
    private static byte[] readBounded(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new ResponseTooLargeException("maven-metadata.xml response exceeded " + maxBytes + " byte cap");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }

    private record CanonicalArtifact(String groupId, String artifactId, int versionCount) {
    }
}
