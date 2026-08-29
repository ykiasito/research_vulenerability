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
import java.net.URI;
import java.net.URLConnection;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    private final RestClient externalApiRestClient;
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
            JsonNode release = externalApiRestClient.get()
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

    /** Plain {@link URLConnection}, not the shared {@code externalApiRestClient} bean — that
     *  client's 10s read timeout (fine for quick API calls) is far too short for a download that
     *  can run for minutes (baseline: well over 1GB). */
    private InputStream download(String url) throws IOException {
        URLConnection connection = URI.create(url).toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(0);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (cve.org sync)");
        return connection.getInputStream();
    }

    private record GitHubRelease(String tag, String baselineZipUrl, String deltaZipUrl) {
    }
}
