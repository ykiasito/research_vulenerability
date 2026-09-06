package com.vulncheck.app.service.cveorg;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Mirrors CVE.org's CVE List V5 (https://github.com/CVEProject/cvelistV5) into the local
 * {@code cve_org_records}/{@code cve_org_affected_products} tables, which {@link
 * com.vulncheck.app.service.vuln.CveOrgVulnerabilitySource} then queries locally (no live API call
 * per item — that's the whole point of pre-syncing this source, unlike NVD's live-lookup fallback).
 *
 * <p>The project distributes data as hourly GitHub Releases, each carrying two assets: a full
 * "baseline" snapshot (zip containing one nested zip of ~380k individual CVE JSON files, ~1.1GB
 * download / ~3.2GB uncompressed as of 2026-08) and a "delta" zip containing only records added or
 * updated since that day's midnight baseline (~tens of records typically, a few tens of KB). Both
 * are upserted through the exact same {@link #upsertCveJson} path — a delta record is just a
 * complete CVE JSON like any other, not a partial diff, so re-applying it (or re-running a whole
 * day's delta twice) is naturally idempotent.
 *
 * <p>{@link #syncBaseline()} is deliberately never called automatically (no {@code @Scheduled} on
 * it) — given its size, it's meant to be triggered once, manually, after deploying to a properly
 * sized server (see {@code AdminController}). {@link #syncDelta()} is small and safe to run
 * routinely; {@link CveOrgScheduledSync} calls it once a day.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CveOrgSyncService {

    private static final String LATEST_RELEASE_API = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest";
    private static final String BASELINE_ASSET_SUFFIX = "_all_CVEs_at_midnight.zip.zip";
    private static final String DELTA_ASSET_INFIX = "_delta_CVEs_at_";

    /** Hosts {@link #download}'s {@code url} (parsed from GitHub's {@code browser_download_url},
     *  not a hardcoded constant) is allowed to connect to (backlog items 359/361). Verified live
     *  2026-09-06 against the real {@code CVEProject/cvelistV5} release assets: {@code
     *  github.com/CVEProject/cvelistV5/releases/download/.../*.zip} redirects exactly once (a
     *  single 302) to {@code release-assets.githubusercontent.com/github-production-release-asset/
     *  ...&sig=...&jwt=...} before the terminal 2xx — cross-checked against {@code GET
     *  https://api.github.com/meta}'s {@code domains.actions} list. {@code
     *  objects.githubusercontent.com}/{@code github-releases.githubusercontent.com} are kept as
     *  historical/failover asset hosts, not the currently-observed one. Deliberately NOT a
     *  wildcard like {@code *.githubusercontent.com} — that would also admit unrelated hosts such
     *  as {@code camo.}/{@code raw.}/{@code user-images.githubusercontent.com}. Deliberately NOT
     *  {@code objects-origin.githubusercontent.com} either — that's the upload-side host, never
     *  seen on a download response.
     *
     *  <p><b>Do not infer this host set from a sibling's confirmed redirect chain</b> — GitHub's
     *  redirect target is not uniform across content types. {@code GhsaSyncService}'s tarball
     *  download (a different GitHub API, {@code /repos/.../tarball/...}) lands on {@code
     *  codeload.github.com}, a genuinely different path; treating that as evidence for this
     *  release-asset download's host was the mistaken inference in this class's original SSRF fix
     *  (before this host set was corrected against the actual live chain). */
    private static final Set<String> ALLOWED_HOSTS = Set.of(
            "github.com",
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
            "github-releases.githubusercontent.com");
    /** Mirrors {@code GhsaSyncService.MAX_REDIRECTS}'s convention — bounds {@link #download}'s
     *  redirect-following loop so a misbehaving/compromised host can't cause an infinite loop. */
    private static final int MAX_REDIRECTS = 3;
    private static final int DOWNLOAD_CONNECT_TIMEOUT_MILLIS = 10_000;
    /** Finite, not {@code 0}/unbounded (backlog item 362) — {@link URLConnection#setReadTimeout} is
     *  a per-read (socket-idle) timeout, not a whole-download budget, so this doesn't cap how long
     *  a genuinely-streaming multi-GB download can take; it only kills a connection that goes fully
     *  idle for this long, matching {@code cveOrgSyncRestClient}'s own read timeout (see {@code
     *  RestClientConfig#cveOrgSyncRestClient}) for consistency. */
    private static final int DOWNLOAD_READ_TIMEOUT_MILLIS = 30_000;

    private final RestClient cveOrgSyncRestClient;
    private final CveOrgRecordRepository cveOrgRecordRepository;
    private final CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    private final CveOrgSyncStateRepository cveOrgSyncStateRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Full baseline load — ~380k records, ~1.1GB download. Not scheduled; see class javadoc. */
    public int syncBaseline() {
        GitHubRelease release = fetchLatestRelease();
        if (release == null || release.baselineZipUrl() == null) {
            log.error("CVE.org baseline sync aborted: could not resolve the latest release's baseline asset");
            return 0;
        }
        log.info("CVE.org baseline sync starting from release {} ({})", release.tag(), release.baselineZipUrl());

        int upserted = 0;
        try (InputStream outerStream = download(release.baselineZipUrl());
                ZipInputStream outerZip = new ZipInputStream(outerStream)) {
            ZipEntry outerEntry;
            while ((outerEntry = outerZip.getNextEntry()) != null) {
                if (!outerEntry.getName().endsWith(".zip")) {
                    continue;
                }
                // The baseline asset is a zip containing exactly one nested zip (cves.zip) of the
                // individual CVE-*.json files — ZipInputStream reads local file headers
                // sequentially, so nesting one stream inside another works without random access.
                try (ZipInputStream innerZip = new ZipInputStream(outerZip)) {
                    ZipEntry innerEntry;
                    while ((innerEntry = innerZip.getNextEntry()) != null) {
                        if (upsertEntryIfCveJson(innerEntry, innerZip)) {
                            upserted++;
                            if (upserted % 10000 == 0) {
                                log.info("CVE.org baseline sync progress: {} records upserted", upserted);
                            }
                        }
                    }
                }
            }
        } catch (IOException e) {
            log.error("CVE.org baseline sync failed after upserting {} records", upserted, e);
            return upserted;
        }

        markSynced(release.tag(), true);
        log.info("CVE.org baseline sync complete: {} records upserted (release {})", upserted, release.tag());
        return upserted;
    }

    /** Small, safe to run routinely — the day's cumulative changes since midnight. */
    public int syncDelta() {
        GitHubRelease release = fetchLatestRelease();
        if (release == null || release.deltaZipUrl() == null) {
            log.warn("CVE.org delta sync skipped: could not resolve the latest release's delta asset");
            return 0;
        }
        log.info("CVE.org delta sync starting from release {} ({})", release.tag(), release.deltaZipUrl());

        int upserted = 0;
        try (InputStream stream = download(release.deltaZipUrl());
                ZipInputStream zip = new ZipInputStream(stream)) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (upsertEntryIfCveJson(entry, zip)) {
                    upserted++;
                }
            }
        } catch (IOException e) {
            log.error("CVE.org delta sync failed after upserting {} records", upserted, e);
            return upserted;
        }

        markSynced(release.tag(), false);
        log.info("CVE.org delta sync complete: {} records upserted (release {})", upserted, release.tag());
        return upserted;
    }

    private boolean upsertEntryIfCveJson(ZipEntry entry, ZipInputStream zip) throws IOException {
        String name = entry.getName();
        if (entry.isDirectory() || !name.endsWith(".json") || !name.contains("CVE-")) {
            return false;
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(zip.readAllBytes());
        } catch (Exception e) {
            log.debug("Skipping unparseable CVE.org entry {}", name, e);
            return false;
        }
        try {
            upsertCveJson(root);
            return true;
        } catch (Exception e) {
            log.warn("Skipping CVE.org entry {} — failed to upsert", name, e);
            return false;
        }
    }

    private void upsertCveJson(JsonNode root) {
        JsonNode metadata = root.path("cveMetadata");
        String cveId = metadata.path("cveId").asText(null);
        if (cveId == null || cveId.isBlank()) {
            return;
        }

        JsonNode cna = root.path("containers").path("cna");
        String title = cna.path("title").asText(null);
        String description = extractEnglishDescription(cna.path("descriptions"));
        BigDecimal cvssScore = null;
        String cvssSeverity = null;
        for (JsonNode metric : cna.path("metrics")) {
            JsonNode cvss = firstCvssNode(metric);
            if (cvss != null) {
                cvssScore = cvss.has("baseScore") ? BigDecimal.valueOf(cvss.path("baseScore").asDouble()) : null;
                cvssSeverity = cvss.path("baseSeverity").asText(null);
                break;
            }
        }

        cveOrgRecordRepository.upsert(
                cveId,
                title,
                description,
                cvssScore,
                cvssSeverity,
                metadata.path("state").asText(null),
                parseTimestamp(metadata.path("datePublished").asText(null)),
                parseTimestamp(metadata.path("dateUpdated").asText(null)),
                root.toString());

        cveOrgAffectedProductRepository.deleteByCveId(cveId);
        for (JsonNode affected : cna.path("affected")) {
            String vendor = affected.path("vendor").asText(null);
            String product = affected.path("product").asText(null);
            String packageName = affected.path("packageName").asText(null);
            if (isBlank(vendor) && isBlank(product) && isBlank(packageName)) {
                continue;
            }
            cveOrgAffectedProductRepository.insert(cveId, vendor, product, packageName);
        }
    }

    private JsonNode firstCvssNode(JsonNode metric) {
        for (String key : new String[] {"cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"}) {
            if (metric.has(key)) {
                return metric.path(key);
            }
        }
        return null;
    }

    private String extractEnglishDescription(JsonNode descriptions) {
        for (JsonNode d : descriptions) {
            if ("en".equals(d.path("lang").asText())) {
                return d.path("value").asText(null);
            }
        }
        return descriptions.size() > 0 ? descriptions.get(0).path("value").asText(null) : null;
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

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private void markSynced(String releaseTag, boolean baselineLoaded) {
        CveOrgSyncState state = cveOrgSyncStateRepository.findById((short) 1).orElseGet(CveOrgSyncState::new);
        state.setId((short) 1);
        state.setLastReleaseTag(releaseTag);
        state.setLastSyncedAt(OffsetDateTime.now());
        if (baselineLoaded) {
            state.setBaselineLoaded(true);
        }
        cveOrgSyncStateRepository.save(state);
    }

    private GitHubRelease fetchLatestRelease() {
        try {
            JsonNode release = cveOrgSyncRestClient.get()
                    .uri(LATEST_RELEASE_API)
                    .header("Accept", "application/vnd.github+json")
                    .retrieve()
                    .body(JsonNode.class);
            if (release == null) {
                return null;
            }
            String tag = release.path("tag_name").asText(null);
            String baselineUrl = null;
            String deltaUrl = null;
            for (JsonNode asset : release.path("assets")) {
                String name = asset.path("name").asText("");
                String url = asset.path("browser_download_url").asText(null);
                if (name.endsWith(BASELINE_ASSET_SUFFIX)) {
                    baselineUrl = url;
                } else if (name.contains(DELTA_ASSET_INFIX) && name.endsWith(".zip")) {
                    deltaUrl = url;
                }
            }
            return new GitHubRelease(tag, baselineUrl, deltaUrl);
        } catch (Exception e) {
            log.error("Failed to resolve the latest cvelistV5 GitHub release", e);
            return null;
        }
    }

    /** Plain {@link URLConnection} for the actual bytes (via {@link #openConnection}), not the
     *  {@code cveOrgSyncRestClient} bean directly — that client's 30s read timeout is fine for the
     *  quick releases-API call but far too short for a download that can run for minutes
     *  (baseline: well over 1GB). {@code url} is GitHub-supplied (parsed from {@code
     *  browser_download_url}), so it's validated and every redirect hop re-validated before ever
     *  connecting (backlog items 359/361/362) — see {@link #validatedUri}/{@link
     *  #resolveRedirectTarget}/{@link #openConnection}, mirroring {@code
     *  GhsaSyncService#resolveRedirectTarget}/{@code #openStream}'s SSRF-hardening for its
     *  equivalent tarball-body download. Loops (bounded by {@link #MAX_REDIRECTS}, same convention
     *  as {@code GhsaSyncService.MAX_REDIRECTS}) rather than following a single hop, since {@link
     *  #openConnection} itself now fails closed on any further redirect it wasn't told to expect.
     *
     *  <p>Package-private (not {@code private}) so the unit test can call it directly and assert
     *  on the {@link #MAX_REDIRECTS} bound without needing a live network call. */
    InputStream download(String url) throws IOException {
        URI current = validatedUri(url);
        if (current == null) {
            throw new IOException("Rejected non-allowlisted download URL: " + sanitizedForLogging(url));
        }
        // redirectsRemaining counts down exactly like GhsaSyncService.fetchBounded's own
        // redirectsRemaining parameter (3 -> 2 -> 1 -> 0): a chain of up to MAX_REDIRECTS actual
        // redirect hops is tolerated, and only an attempted (MAX_REDIRECTS + 1)th redirect fails.
        // (An earlier version of this loop checked-and-followed a hop in the same iteration, which
        // required the loop's *final* iteration to observe a non-redirect to succeed — one hop
        // stricter than intended; peer review caught the mismatch with the claimed convention.)
        int redirectsRemaining = MAX_REDIRECTS;
        while (true) {
            URI next = resolveRedirectTarget(current);
            if (next.equals(current)) {
                return openConnection(current).getInputStream();
            }
            if (redirectsRemaining <= 0) {
                throw new IOException("CVE.org sync: too many redirects resolving download URL (max " + MAX_REDIRECTS + ")");
            }
            redirectsRemaining--;
            current = next;
        }
    }

    /**
     * Validates {@code url} is {@code https} and its host is one of {@link #ALLOWED_HOSTS} before
     * ever connecting — {@code url} (passed from {@link #download}) ultimately comes from GitHub's
     * parsed {@code browser_download_url}, not a hardcoded constant, so a compromised/spoofed
     * release response could otherwise redirect this sync job at an arbitrary host (or a
     * non-network scheme such as {@code file://}, which would bypass network-level egress controls
     * entirely). Matches the same defense already applied by {@code OsvSyncService}, {@code
     * GhsaSyncService}, and both CSAF sync services (backlog items 359/361).
     *
     * <p>Package-private (not {@code private}) so the unit test can call it directly, matching
     * {@code RestClientConfig#simpleRequestFactory}'s established convention for this kind of seam.
     */
    URI validatedUri(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            // Deliberately a fixed message, not the raw (unparseable, so not even confirmed to be a
            // URL at all) input — see sanitizedForLogging's javadoc on why this class redacts more
            // aggressively than the sibling sync services.
            log.warn("CVE.org sync: rejecting an unparseable download URL");
            return null;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || !ALLOWED_HOSTS.contains(uri.getHost())) {
            log.warn("CVE.org sync: rejecting fetch of {} — not https or not an allowlisted host", sanitizedForLogging(uri));
            return null;
        }
        return uri;
    }

    /**
     * Re-resolves {@code uri}'s single 3xx redirect hop (if any) through {@link
     * #cveOrgSyncRestClient} — the same no-auto-redirect bean used for the releases-API call — so
     * the redirect target's host can be validated against {@link #ALLOWED_HOSTS} before ever being
     * followed (backlog item 361). {@link #download} calls this in a bounded loop (see {@link
     * #MAX_REDIRECTS}) rather than assuming a single hop, since a target itself may 3xx again.
     * GitHub's {@code github.com/.../releases/download/...} endpoint is verified (2026-09-06,
     * live, against {@code CVEProject/cvelistV5}) to redirect exactly once in practice to its
     * signed asset CDN — see {@link #ALLOWED_HOSTS}'s javadoc for the full chain and an explicit
     * warning against inferring this host set from {@code GhsaSyncService}'s differently-shaped
     * tarball-endpoint redirect. On a non-redirect response the original (already-validated) {@code
     * uri} is returned as-is — a real connection problem surfaces at {@link #openConnection}'s own
     * attempt, not here.
     *
     * <p>Package-private (not {@code private}) so the unit test can call it directly against a
     * {@code MockRestServiceServer}-backed client.
     */
    URI resolveRedirectTarget(URI uri) throws IOException {
        try {
            return cveOrgSyncRestClient.get().uri(uri).exchange((request, response) -> {
                if (!response.getStatusCode().is3xxRedirection()) {
                    return uri;
                }
                String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                if (location == null) {
                    throw new IllegalStateException(
                            "CVE.org sync: redirect response had no Location header for " + sanitizedForLogging(uri));
                }
                URI target = uri.resolve(location);
                URI validatedTarget = validatedUri(target.toString());
                if (validatedTarget == null) {
                    // target (not sanitizedForLogging(target)) is deliberately never embedded here —
                    // this service's redirect target carries request-signing credentials (sig=/jwt=
                    // query parameters), unlike OsvSyncService/GhsaSyncService's redirect targets.
                    throw new IllegalStateException(
                            "CVE.org sync: rejected non-allowlisted redirect target " + sanitizedForLogging(target));
                }
                return validatedTarget;
            });
        } catch (IllegalStateException e) {
            // e's own message was already built through sanitizedForLogging above, so it's safe to
            // chain as cause.
            throw new IOException(e.getMessage(), e);
        } catch (Exception e) {
            // Deliberately does NOT chain e as this exception's cause, and does NOT embed
            // e.getMessage() — unlike the IllegalStateException branch above, e here is whatever
            // cveOrgSyncRestClient's transport threw (typically Spring's ResourceAccessException on
            // a connect timeout/reset/TLS failure), and that exception's own message embeds the
            // full, un-sanitized request URI ("I/O error on GET request for \"<uri>\": ..."). On a
            // second+ redirect hop, uri here already carries a previously-resolved sig=/jwt=
            // credential (see sanitizedForLogging's javadoc) — chaining e as cause would let
            // syncBaseline/syncDelta's log.error("...", e) print that credential into the log via
            // the "Caused by:" line, defeating the whole point of sanitizing this method's own
            // message. Only e's class name is safe to surface.
            throw new IOException("CVE.org sync: transport error (" + e.getClass().getSimpleName()
                    + ") resolving redirect for " + sanitizedForLogging(uri));
        }
    }

    /**
     * Builds the raw {@link URLConnection} for the (already validated + redirect-resolved)
     * download URL, with a finite connect/read timeout (backlog item 362) instead of the previous
     * unbounded ({@code setReadTimeout(0)}) one — see {@link #DOWNLOAD_READ_TIMEOUT_MILLIS}'s
     * javadoc for why a finite value doesn't cap a genuinely-streaming multi-GB download. Also
     * disables {@link HttpURLConnection}'s own automatic redirect-following and, for an
     * {@code HttpURLConnection}, fails closed with an {@link IOException} if the response is a 3xx
     * — every hop this service intends to follow already went through {@link
     * #resolveRedirectTarget}'s allowlist check in {@link #download}'s loop, so an extra redirect
     * surfacing here means either a race (the target started redirecting again between resolution
     * and this connection attempt) or an inconsistency between the two requests; either way, this
     * must not silently follow it unchecked.
     *
     * <p>Also rejects any other non-2xx response (backlog item 362 follow-up, senior review,
     * 2026-09-06, third round) — {@code uri} here is the final, signed download URL (carrying
     * {@code sig=}/{@code jwt=} query-string credentials), and letting the caller's own {@link
     * URLConnection#getInputStream()} run on a 4xx/5xx (e.g. an expired signature returning 403)
     * would throw the JDK's plain {@code java.io.IOException("Server returned HTTP response code:
     * <code> for URL: <uri>")} — a message that embeds the FULL, un-sanitized URL. That raw
     * exception would propagate straight out of {@link #download} into {@code
     * syncBaseline}/{@code syncDelta}'s {@code log.error("...", e)}, leaking the credential the
     * exact same way the redirect and transport-error cases already had to be fixed against.
     * Throwing here first, with an already-sanitized message, means {@code getInputStream()} is
     * never reached on a non-2xx response.
     *
     * <p>Package-private so the unit test can assert the concrete timeout values and redirect
     * behavior directly, same convention as {@code RestClientConfig#noRedirectRequestFactory}'s own
     * test.
     */
    URLConnection openConnection(URI uri) throws IOException {
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(DOWNLOAD_CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(DOWNLOAD_READ_TIMEOUT_MILLIS);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (cve.org sync)");
        if (connection instanceof HttpURLConnection httpConnection) {
            httpConnection.setInstanceFollowRedirects(false);
            int responseCode = httpConnection.getResponseCode();
            if (responseCode >= 300 && responseCode < 400) {
                throw new IOException("CVE.org sync: unexpected redirect (HTTP " + responseCode + ") opening "
                        + sanitizedForLogging(uri) + " — every hop should already have been validated by "
                        + "resolveRedirectTarget");
            }
            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("CVE.org sync: unexpected HTTP " + responseCode + " opening "
                        + sanitizedForLogging(uri) + " — refusing to read the response body, since "
                        + "HttpURLConnection#getInputStream() would otherwise throw its own exception "
                        + "embedding the full request URL (including this URL's signed query string)");
            }
        }
        return connection;
    }

    /**
     * Redacts everything except scheme+host+path for logging/exception messages — this service's
     * redirect target carries request-signing credentials ({@code sig=}/{@code jwt=} query
     * parameters, see {@link #ALLOWED_HOSTS}'s javadoc), which must never be logged or embedded in
     * an exception message. This is stricter than {@code OsvSyncService}/{@code GhsaSyncService},
     * whose redirect targets don't carry such credentials, so their equivalent log/exception
     * messages can embed the full URL.
     */
    private static String sanitizedForLogging(URI uri) {
        return uri.getScheme() + "://" + uri.getAuthority() + uri.getPath();
    }

    /** {@link #sanitizedForLogging(URI)} for a raw, not-yet-parsed URL string — falls back to a
     *  fixed placeholder if {@code url} isn't even a parseable URI. */
    private static String sanitizedForLogging(String url) {
        try {
            return sanitizedForLogging(URI.create(url));
        } catch (IllegalArgumentException e) {
            return "(unparseable URL)";
        }
    }

    private record GitHubRelease(String tag, String baselineZipUrl, String deltaZipUrl) {
    }
}
