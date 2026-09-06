package com.vulncheck.app.service.cveorg;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import com.vulncheck.app.service.LogSanitizer;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URLConnection;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Set;
import java.util.function.Predicate;
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

    /** Backlog item 416 (SSRF hardening): hosts {@link #download}'s {@code url} — parsed from
     *  GitHub's {@code browser_download_url}, not a hardcoded constant — is allowed to connect to,
     *  matching the allowlist discipline {@code OsvSyncService}/{@code GhsaSyncService}/both CSAF
     *  sync services already apply to their own outbound fetches. {@code github.com} covers the
     *  asset URL as first resolved from the releases API response; the three
     *  {@code *.githubusercontent.com} hosts cover the redirect this project's release assets
     *  actually land on (GitHub serves large release assets from a separate storage CDN rather than
     *  {@code github.com} itself) — kept as a small set of known asset-CDN hostnames rather than a
     *  {@code *.githubusercontent.com} wildcard, which would also admit unrelated hosts such as
     *  {@code raw.}/{@code camo.githubusercontent.com}. */
    private static final Set<String> DEFAULT_ALLOWED_HOSTS = Set.of(
            "github.com",
            "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
            "github-releases.githubusercontent.com");
    /** Bounds {@link #download}'s manual redirect-following loop so a misbehaving or compromised
     *  host can never cause it to loop forever — same 3-hop budget {@code
     *  GhsaSyncService}'s own bounded fetch uses. */
    private static final int MAX_REDIRECTS = 3;
    private static final int DOWNLOAD_CONNECT_TIMEOUT_MILLIS = 10_000;
    /** Finite, not {@code 0}/unbounded (backlog item 398) — {@link URLConnection#setReadTimeout} is
     *  a per-read (socket-idle) timeout, not a whole-download budget, so this doesn't cap how long a
     *  genuinely-streaming multi-GB baseline download can take; it only kills a connection that goes
     *  fully idle for this long. Without a finite value, a peer that keeps the connection open but
     *  stops sending bytes would hang this thread forever, without ever reaching {@link
     *  #recordSyncFailure}. 30s is the same value used by the sibling sync services (backlog items
     *  378/381 for {@code GhsaSyncService}/{@code OsvSyncService}). */
    private static final int DOWNLOAD_READ_TIMEOUT_MILLIS = 30_000;

    private final RestClient cveOrgSyncRestClient;
    private final CveOrgRecordRepository cveOrgRecordRepository;
    private final CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    private final CveOrgSyncStateRepository cveOrgSyncStateRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();
    /** The real scheme/host check (backlog item 416): {@code https} plus a host in {@link
     *  #DEFAULT_ALLOWED_HOSTS}. An inline-initialized field (same technique as {@link #objectMapper}
     *  above), so it's excluded from the {@code @RequiredArgsConstructor}-generated constructor and
     *  can never differ in production. Package-private and overridable via reflection purely so
     *  {@code CveOrgSyncServiceTest} can point {@link #download}'s redirect-following loop at a local
     *  {@code com.sun.net.httpserver.HttpServer} (reachable only at {@code http://localhost:<port>})
     *  without ever loosening this predicate in production. */
    private final Predicate<URI> urlAllowed = uri ->
            "https".equalsIgnoreCase(uri.getScheme()) && uri.getHost() != null && DEFAULT_ALLOWED_HOSTS.contains(uri.getHost());

    /** Full baseline load — ~380k records, ~1.1GB download. Not scheduled; see class javadoc. */
    public int syncBaseline() {
        GitHubRelease release = fetchLatestRelease();
        if (release == null || release.baselineZipUrl() == null) {
            String message = "Could not resolve the latest cvelistV5 release's baseline asset";
            log.error("CVE.org baseline sync aborted: {}", message);
            recordSyncFailure(message);
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
            // Closed-mode backlog item 379: record the failure (rather than silently returning) so
            // /admin/cve-org has a signal a continuously-failing baseline sync used to leave
            // nowhere — deliberately e.getClass().getSimpleName(), not e.getMessage(), since a
            // download IOException could in principle still be wrapping part of the request URL.
            recordSyncFailure("baseline sync failed after upserting " + upserted + " records ("
                    + e.getClass().getSimpleName() + ")");
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
            String message = "Could not resolve the latest cvelistV5 release's delta asset";
            log.warn("CVE.org delta sync skipped: {}", message);
            recordSyncFailure(message);
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
            // See syncBaseline's matching catch block for why this is e.getClass().getSimpleName(),
            // not e.getMessage() (closed-mode backlog item 379).
            recordSyncFailure("delta sync failed after upserting " + upserted + " records ("
                    + e.getClass().getSimpleName() + ")");
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
        CveOrgSyncState state = loadState();
        state.setLastReleaseTag(releaseTag);
        state.setLastSyncedAt(OffsetDateTime.now());
        state.setLastSyncError(null);
        if (baselineLoaded) {
            state.setBaselineLoaded(true);
        }
        cveOrgSyncStateRepository.save(state);
    }

    /** Closed-mode backlog item 379: records a failed sync attempt (baseline or delta) so the
     *  failure is visible on /admin/cve-org instead of vanishing into the log alone. Deliberately
     *  still advances {@code last_synced_at} to "now" — matching {@code
     *  GhsaSyncService#failSync}'s convention — so this state's last_synced_at means "the last time
     *  a sync was attempted", not "the last time one succeeded"; {@code last_sync_error} being
     *  non-null is what actually distinguishes the two. Never touches {@code baseline_loaded}/
     *  {@code last_release_tag} — a failed attempt must not make a previously-completed baseline
     *  look un-loaded, nor overwrite a known-good release tag with nothing. */
    private void recordSyncFailure(String message) {
        CveOrgSyncState state = loadState();
        state.setLastSyncedAt(OffsetDateTime.now());
        state.setLastSyncError(message);
        cveOrgSyncStateRepository.save(state);
    }

    private CveOrgSyncState loadState() {
        CveOrgSyncState state = cveOrgSyncStateRepository.findById((short) 1).orElseGet(CveOrgSyncState::new);
        state.setId((short) 1);
        return state;
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

    /** Backlog item 416: drives the download through a bounded, manually-followed redirect loop
     *  instead of handing {@code url} straight to {@link URLConnection#openConnection()} with
     *  automatic redirect-following left on. {@code url} is GitHub-supplied (parsed from {@code
     *  browser_download_url}), not a hardcoded constant, so both it and every redirect hop it leads
     *  to are validated against {@link #DEFAULT_ALLOWED_HOSTS} (via {@link #validatedUri}) before
     *  ever connecting — mirroring the allowlist discipline the sibling sync services already apply.
     *  Exactly one HTTP connection is opened per hop; only the terminal (non-redirect) response's
     *  body is ever read, so a redirect never causes a byte of the asset to be downloaded twice.
     *
     *  <p>Package-private so {@code CveOrgSyncServiceTest} can exercise the loop end-to-end against a
     *  local {@code com.sun.net.httpserver.HttpServer}. */
    InputStream download(String url) throws IOException {
        URI current = validatedUri(url);
        if (current == null) {
            throw new IOException("CVE.org sync: rejected non-allowlisted download URL " + sanitizedForLogging(url));
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
                    throw new IOException(
                            "CVE.org sync: rejected non-allowlisted redirect target " + sanitizedForLogging(target));
                }
                redirectsRemaining--;
                current = next;
                continue;
            }
            connection.disconnect();
            throw new IOException("CVE.org sync: unexpected HTTP " + responseCode + " opening " + sanitizedForLogging(current));
        }
    }

    /** Wraps {@link HttpURLConnection#getResponseCode()} so a transport-level failure (connect
     *  timeout, connection reset, TLS error) can never leak {@code uri} — which, past the first hop,
     *  may already carry a redirect-signed query string — through an unsanitized cause or message.
     *  Package-private purely so the unit test can force a deterministic transport failure via a
     *  stubbed {@link HttpURLConnection}. */
    int responseCodeOf(HttpURLConnection connection, URI uri) throws IOException {
        try {
            return connection.getResponseCode();
        } catch (IOException e) {
            throw new IOException("CVE.org sync: transport error (" + e.getClass().getSimpleName()
                    + ") connecting to " + sanitizedForLogging(uri));
        }
    }

    /** Validates {@code url} is {@code https} and its host is one of {@link #DEFAULT_ALLOWED_HOSTS}
     *  before ever connecting (backlog item 416) — {@code url} ultimately comes from GitHub's parsed
     *  {@code browser_download_url}, not a hardcoded constant, so a compromised/spoofed release
     *  response could otherwise redirect this sync job at an arbitrary host. Package-private so the
     *  unit test can call it directly. */
    URI validatedUri(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            log.warn("CVE.org sync: rejecting an unparseable download URL");
            return null;
        }
        if (!urlAllowed.test(uri)) {
            log.warn("CVE.org sync: rejecting fetch of {} — not https or not an allowlisted host", sanitizedForLogging(uri));
            return null;
        }
        return uri;
    }

    /** Opens the raw {@link HttpURLConnection} for {@code uri} with the same finite connect/read
     *  timeouts the previous plain-{@link URLConnection} version used, plus {@link
     *  HttpURLConnection}'s own automatic redirect-following disabled — {@link #download}'s loop is
     *  what decides whether to follow a redirect (after re-validating its target), not this
     *  connection itself. Deliberately does not inspect the response code — {@link #download} needs
     *  the {@code Location} header off a 3xx response before deciding whether to follow it, so
     *  response-code interpretation stays entirely {@link #download}'s responsibility. Package-private
     *  so the unit test can assert the concrete timeout/redirect-following values directly. */
    HttpURLConnection openConnection(URI uri) throws IOException {
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(DOWNLOAD_CONNECT_TIMEOUT_MILLIS);
        connection.setReadTimeout(DOWNLOAD_READ_TIMEOUT_MILLIS);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (cve.org sync)");
        if (!(connection instanceof HttpURLConnection httpConnection)) {
            // Unreachable in practice — validatedUri only ever admits https URIs, whose
            // URLConnection is always an HttpsURLConnection (an HttpURLConnection subtype) — but kept
            // as a defensive, sanitized failure rather than a raw ClassCastException.
            throw new IOException("CVE.org sync: expected an HTTP(S) connection opening " + sanitizedForLogging(uri));
        }
        httpConnection.setInstanceFollowRedirects(false);
        return httpConnection;
    }

    /** Redacts everything except scheme/host/path before a URL reaches a log line or exception
     *  message (backlog item 416) — this service's redirect target carries request-signing
     *  credentials ({@code sig=}/{@code jwt=} query parameters on the asset-CDN hosts in {@link
     *  #DEFAULT_ALLOWED_HOSTS}), which must never be logged verbatim. Uses {@link URI#getRawPath()}
     *  (not the decoding {@link URI#getPath()}) so a maliciously crafted redirect {@code Location}
     *  can't smuggle a decoded control character into the sanitized result; {@link
     *  LogSanitizer#sanitize} is applied on top as this codebase's standard defense against exactly
     *  that class of log-injection risk for any other externally-derived log value. */
    private static String sanitizedForLogging(URI uri) {
        return LogSanitizer.sanitize(uri.getScheme() + "://" + uri.getHost() + uri.getRawPath());
    }

    /** {@link #sanitizedForLogging(URI)} for a raw, not-yet-parsed URL string — falls back to a fixed
     *  placeholder if {@code url} isn't even a parseable URI. */
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
