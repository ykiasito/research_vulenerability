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
    private static final Set<String> DEFAULT_ALLOWED_HOSTS = Set.of(
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
    /**
     * The real production check (backlog items 359/361): {@code https} scheme + host in {@link
     * #DEFAULT_ALLOWED_HOSTS}. Has an inline initializer, so — same technique as {@link
     * #objectMapper} just above — it's excluded from the {@code @RequiredArgsConstructor}-generated
     * constructor and can never be different in production, regardless of how this bean is wired.
     *
     * <p>Package-private-overridable-via-reflection only, for exactly one reason: {@link #download}
     * now drives its entire redirect-following loop through raw {@link HttpURLConnection}s (no
     * {@code RestClient}/{@code MockRestServiceServer} anywhere in the picture — see {@link
     * #download}'s own javadoc for why), so a real local {@code
     * com.sun.net.httpserver.HttpServer} is the only way {@code CveOrgSyncServiceTest} can exercise
     * the full loop end-to-end, and that test server can only ever be reached at {@code
     * http://localhost:<port>} — never at a real allowlisted GitHub hostname over {@code https}.
     * {@code CveOrgSyncServiceTest} uses {@code ReflectionTestUtils.setField} to relax this
     * predicate (e.g. to "host is localhost, any scheme") only inside the test process.
     */
    private final java.util.function.Predicate<URI> urlAllowed = uri ->
            "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null && DEFAULT_ALLOWED_HOSTS.contains(uri.getHost());

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

    /** Drives the actual download connection through a bounded redirect-following loop (backlog
     *  items 359/361/362). {@code url} is GitHub-supplied (parsed from {@code
     *  browser_download_url}), so it's validated and every redirect hop re-validated before ever
     *  connecting — see {@link #validatedUri}/{@link #openConnection}, mirroring {@code
     *  GhsaSyncService}'s equivalent tarball-body download SSRF-hardening.
     *
     *  <p><b>One HTTP request per hop — the terminal request IS the download</b> (senior review,
     *  2026-09-06, fourth round: a REAL regression this class had between the second and third
     *  review rounds). An earlier version resolved each redirect through a separate {@code
     *  resolveRedirectTarget} call (a {@code RestClient.exchange()}, which Spring closes via {@code
     *  SimpleClientHttpResponse.close()} — draining the ENTIRE response body to EOF even though
     *  nothing read it), and only THEN opened a second, brand-new connection via {@link
     *  #openConnection} to actually fetch the bytes. For the terminal (non-redirect) hop, that
     *  meant every byte of the CVE.org baseline (well over 1GB, see the class javadoc) was
     *  downloaded and silently discarded once, then downloaded again for real — doubling egress
     *  and download time with no test catching it, since {@code MockRestServiceServer} bodies were
     *  empty in this class's own tests. This loop instead opens exactly one connection per hop and
     *  reads its response code directly; only a genuine 3xx causes a second connection (to the
     *  redirect target), and the terminal hop's connection is the one whose body is actually
     *  streamed out.
     *
     *  <p>{@code redirectsRemaining} counts down exactly like {@code
     *  GhsaSyncService.fetchBounded}'s own {@code redirectsRemaining} parameter (3 -> 2 -> 1 -> 0):
     *  a chain of up to {@link #MAX_REDIRECTS} actual redirect hops is tolerated, and only an
     *  attempted ({@link #MAX_REDIRECTS} + 1)th redirect fails closed.
     *
     *  <p>Package-private (not {@code private}) so the unit test can call it directly and assert
     *  on the {@link #MAX_REDIRECTS} bound (and the single-request-per-hop property) without
     *  needing a live network call. */
    InputStream download(String url) throws IOException {
        URI current = validatedUri(url);
        if (current == null) {
            throw new IOException("Rejected non-allowlisted download URL: " + sanitizedForLogging(url));
        }
        int redirectsRemaining = MAX_REDIRECTS;
        while (true) {
            HttpURLConnection connection = openConnection(current);
            int responseCode = responseCodeOf(connection, current);
            if (responseCode >= 200 && responseCode < 300) {
                return connection.getInputStream();
            }
            if (responseCode >= 300 && responseCode < 400) {
                String location = connection.getHeaderField(HttpHeaders.LOCATION);
                connection.disconnect();
                if (location == null) {
                    throw new IOException(
                            "CVE.org sync: redirect response had no Location header for " + sanitizedForLogging(current));
                }
                if (redirectsRemaining <= 0) {
                    throw new IOException("CVE.org sync: too many redirects resolving download URL (max " + MAX_REDIRECTS + ")");
                }
                URI target = current.resolve(location);
                URI next = validatedUri(target.toString());
                if (next == null) {
                    // target (not sanitizedForLogging(target)) is deliberately never embedded here —
                    // this service's redirect target carries request-signing credentials (sig=/jwt=
                    // query parameters), unlike OsvSyncService/GhsaSyncService's redirect targets.
                    throw new IOException(
                            "CVE.org sync: rejected non-allowlisted redirect target " + sanitizedForLogging(target));
                }
                redirectsRemaining--;
                current = next;
                continue;
            }
            connection.disconnect();
            throw new IOException("CVE.org sync: unexpected HTTP " + responseCode + " opening "
                    + sanitizedForLogging(current) + " — refusing to read the response body, since "
                    + "HttpURLConnection#getInputStream() would otherwise throw its own exception "
                    + "embedding the full request URL (including this URL's signed query string)");
        }
    }

    /**
     * Wraps {@link HttpURLConnection#getResponseCode()} so a transport-level failure (connect
     * timeout, connection reset, TLS error) never leaks {@code uri} — which, on a second+ redirect
     * hop, already carries a previously-resolved {@code sig=}/{@code jwt=} credential — through an
     * unsanitized cause. Same rationale (and same fix shape: surface only {@code
     * e.getClass().getSimpleName()}, never chain {@code e} as cause or embed {@code e.getMessage()})
     * as this class's now-deleted {@code resolveRedirectTarget}'s own catch-all used, so this
     * doesn't silently reintroduce that already-fixed leak on the new code path.
     *
     * <p>Package-private (not {@code private}) so the unit test can call it directly against a
     * fake {@link HttpURLConnection} whose {@code getResponseCode()} is stubbed to throw — forcing
     * a genuine transport-level failure deterministically (without needing a flaky real-socket
     * trick) is otherwise impractical against a real {@code com.sun.net.httpserver.HttpServer}.
     */
    int responseCodeOf(HttpURLConnection connection, URI uri) throws IOException {
        try {
            return connection.getResponseCode();
        } catch (IOException e) {
            throw new IOException("CVE.org sync: transport error (" + e.getClass().getSimpleName()
                    + ") connecting to " + sanitizedForLogging(uri));
        }
    }

    /**
     * Validates {@code url} is {@code https} and its host is one of {@link #DEFAULT_ALLOWED_HOSTS}
     * (via {@link #urlAllowed}) before ever connecting — {@code url} (passed from {@link
     * #download}) ultimately comes from GitHub's parsed {@code browser_download_url}, not a
     * hardcoded constant, so a compromised/spoofed release response could otherwise redirect this
     * sync job at an arbitrary host (or a non-network scheme such as {@code file://}, which would
     * bypass network-level egress controls entirely). Matches the same defense already applied by
     * {@code OsvSyncService}, {@code GhsaSyncService}, and both CSAF sync services (backlog items
     * 359/361).
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
        if (!urlAllowed.test(uri)) {
            log.warn("CVE.org sync: rejecting fetch of {} — not https or not an allowlisted host", sanitizedForLogging(uri));
            return null;
        }
        return uri;
    }

    /**
     * Opens the raw {@link HttpURLConnection} for {@code uri} with a finite connect/read timeout
     * (backlog item 362) instead of an unbounded ({@code setReadTimeout(0)}) one — see {@link
     * #DOWNLOAD_READ_TIMEOUT_MILLIS}'s javadoc for why a finite value doesn't cap a
     * genuinely-streaming multi-GB download — and with {@link HttpURLConnection}'s own automatic
     * redirect-following disabled, since {@link #download}'s own loop is what decides whether to
     * follow a redirect (after re-validating its target against {@link #DEFAULT_ALLOWED_HOSTS}),
     * not this connection itself.
     *
     * <p>Deliberately does NOT inspect the response code or throw on a 3xx/non-2xx status — that
     * used to happen here (through the second and third senior-review rounds), but {@link
     * #download}'s loop needs the {@code Location} header off a 3xx response before deciding
     * whether to follow it, which a throw-inside-this-method approach would discard. Response-code
     * interpretation is entirely {@link #download}'s responsibility now (senior review, 2026-09-06,
     * fourth round, alongside deleting the now-unused {@code resolveRedirectTarget} — see {@link
     * #download}'s own javadoc for why that method existed and why removing it fixes a genuine
     * double-download regression).
     *
     * <p>Package-private so the unit test can assert the concrete timeout values and redirect
     * behavior directly, same convention as {@code RestClientConfig#noRedirectRequestFactory}'s own
     * test.
     */
    HttpURLConnection openConnection(URI uri) throws IOException {
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(DOWNLOAD_CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(DOWNLOAD_READ_TIMEOUT_MILLIS);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (cve.org sync)");
        if (!(connection instanceof HttpURLConnection httpConnection)) {
            // Should be unreachable in practice — validatedUri only ever admits https URIs, whose
            // URLConnection is always an HttpsURLConnection (an HttpURLConnection subtype) — but
            // kept as a defensive, sanitized failure rather than a ClassCastException.
            throw new IOException("CVE.org sync: expected an HTTP(S) connection opening " + sanitizedForLogging(uri));
        }
        httpConnection.setInstanceFollowRedirects(false);
        return httpConnection;
    }

    /**
     * Redacts everything except scheme+host+path for logging/exception messages — this service's
     * redirect target carries request-signing credentials ({@code sig=}/{@code jwt=} query
     * parameters, see {@link #DEFAULT_ALLOWED_HOSTS}'s javadoc), which must never be logged or
     * embedded in an exception message. This is stricter than {@code OsvSyncService}/{@code
     * GhsaSyncService}, whose redirect targets don't carry such credentials, so their equivalent
     * log/exception messages can embed the full URL.
     *
     * <p>Uses {@link URI#getHost()} (not {@link URI#getAuthority()}) and {@link URI#getRawPath()}
     * (not {@link URI#getPath()}) — {@code getAuthority()} would also echo any embedded userinfo
     * ({@code user:pass@host}), and {@code getPath()}/{@code getAuthority()} are both DECODED
     * accessors, so a maliciously-crafted redirect {@code Location} containing (for example) {@code
     * %0A} would become a literal newline in this sanitized message, enabling CRLF log injection —
     * this repo already fixed the same bug class elsewhere (backlog items 223/270/271); {@link
     * URI#getRawPath()} keeps percent-encoding un-decoded, which is safe for logs (senior review,
     * 2026-09-06, fourth round).
     */
    private static String sanitizedForLogging(URI uri) {
        return uri.getScheme() + "://" + uri.getHost() + uri.getRawPath();
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
