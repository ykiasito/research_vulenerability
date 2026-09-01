package com.vulncheck.app.service.csaf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.CsafAdvisoryId;
import com.vulncheck.app.entity.CsafSyncState;
import com.vulncheck.app.repository.CsafAdvisoryRepository;
import com.vulncheck.app.repository.CsafProductRepository;
import com.vulncheck.app.repository.CsafProductStatusRepository;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService.SyncResult;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Real Red Hat document shapes (same trimmed-but-verbatim RHSA-2003:315/RHEA-2014:1175 fixtures as
 * {@code CsafDocumentUpsertServiceTest}) exercised through {@link RedHatCsafSyncService}'s baseline
 * (in-memory {@code .tar.zst} archive — {@code MockRestServiceServer} CAN intercept this, unlike
 * {@code GhsaSyncService}'s raw {@link java.net.URLConnection} tarball body, since {@link
 * RedHatCsafSyncService} downloads the whole bounded-size archive through the ordinary {@code
 * RestClient} path) and delta ({@code changes.csv}/{@code deletions.csv}, both mocked) paths — see
 * the go/no-go review items 5-8 this class's production code implements.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class RedHatCsafSyncServiceTest {

    @Autowired
    private CsafAdvisoryRepository csafAdvisoryRepository;
    @Autowired
    private CsafProductRepository csafProductRepository;
    @Autowired
    private CsafProductStatusRepository csafProductStatusRepository;
    @Autowired
    private CsafSyncStateRepository csafSyncStateRepository;

    private static final String ADVISORIES_DIR_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/";
    private static final String ARCHIVE_LATEST_URL = ADVISORIES_DIR_URL + "archive_latest.txt";
    private static final String CHANGES_CSV_URL = ADVISORIES_DIR_URL + "changes.csv";
    private static final String DELETIONS_CSV_URL = ADVISORIES_DIR_URL + "deletions.csv";

    // Trimmed, verbatim-per-field real document — same RHSA-2003:315 (quagga) fixture as
    // CsafProductTreeWalkerTest, minus product_tree.relationships[] (not needed for this class's own
    // tests, which exercise sync-service behavior, not walker behavior already covered elsewhere).
    private static final String RHSA_2003_315 = """
            {
              "document": {
                "title": "Red Hat Security Advisory: quagga security update",
                "tracking": { "id": "RHSA-2003:315", "status": "final", "version": "3",
                  "initial_release_date": "2003-11-12T14:16:00+00:00", "current_release_date": "2026-06-25T10:31:54+00:00" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [
                { "branches": [
                    { "branches": [
                        { "category": "product_version", "name": "quagga-0:0.96.2-8.3E.x86_64",
                          "product": { "name": "quagga-0:0.96.2-8.3E.x86_64", "product_id": "quagga-0:0.96.2-8.3E.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=x86_64" } } }
                      ], "category": "architecture", "name": "x86_64" }
                  ], "category": "vendor", "name": "Red Hat" } ] },
              "vulnerabilities": [
                { "cve": "CVE-2003-0858", "product_status": { "fixed": ["quagga-0:0.96.2-8.3E.x86_64"] } }
              ]
            }
            """;

    // Small, self-contained, real-shaped second document for multi-entry archive tests.
    private static final String RHSA_2026_9999 = """
            {
              "document": {
                "title": "Red Hat Security Advisory: test-only second archive entry",
                "tracking": { "id": "RHSA-2026:9999", "status": "final", "version": "1",
                  "initial_release_date": "2026-01-01T00:00:00+00:00", "current_release_date": "2026-01-01T00:00:00+00:00" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [
                { "branches": [
                    { "branches": [
                        { "category": "product_version", "name": "widget-0:1.0-1.el9.x86_64",
                          "product": { "name": "widget-0:1.0-1.el9.x86_64", "product_id": "widget-0:1.0-1.el9.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/widget@1.0-1.el9?arch=x86_64" } } }
                      ], "category": "architecture", "name": "x86_64" }
                  ], "category": "vendor", "name": "Red Hat" } ] },
              "vulnerabilities": [
                { "cve": "CVE-2026-00099", "product_status": { "fixed": ["widget-0:1.0-1.el9.x86_64"] } }
              ]
            }
            """;

    private record Harness(RedHatCsafSyncService service, MockRestServiceServer server) {
    }

    private Harness harness() {
        return harness(RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_ENTRY_COUNT,
                RedHatCsafSyncService.MAX_DOCUMENT_BYTES, RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES);
    }

    private Harness harness(int maxArchiveEntryCount, long maxPerEntryDecompressedBytes, long maxArchiveTotalDecompressedBytes) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CsafDocumentUpsertService upsertService = new CsafDocumentUpsertService(
                csafAdvisoryRepository, csafProductRepository, csafProductStatusRepository, new CsafProductTreeWalker());
        RedHatCsafSyncService service = new RedHatCsafSyncService(builder.build(), ExternalRegistryRateLimiter.disabledForTesting(),
                upsertService, csafAdvisoryRepository, csafSyncStateRepository,
                maxArchiveEntryCount, maxPerEntryDecompressedBytes, maxArchiveTotalDecompressedBytes);
        return new Harness(service, server);
    }

    /** Builds an in-memory {@code .tar.zst} — real zstd compression via {@code zstd-jni}, the same
     *  codec the production {@link RedHatCsafSyncService} decompresses with. */
    private byte[] buildTarZst(Map<String, String> pathToJson) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (ZstdCompressorOutputStream zstd = new ZstdCompressorOutputStream(bytes);
                    TarArchiveOutputStream tar = new TarArchiveOutputStream(zstd)) {
                for (Map.Entry<String, String> entry : pathToJson.entrySet()) {
                    byte[] content = entry.getValue().getBytes(StandardCharsets.UTF_8);
                    TarArchiveEntry tarEntry = new TarArchiveEntry(entry.getKey());
                    tarEntry.setSize(content.length);
                    tar.putArchiveEntry(tarEntry);
                    tar.write(content);
                    tar.closeArchiveEntry();
                }
                tar.finish();
            }
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private String sha256HexOf(byte[] data) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
            return java.util.HexFormat.of().formatHex(digest) + "  archive.tar.zst";
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ------------------------------------------------------------------ baseline ----------------

    @Test
    void baselineSyncStreamDecompressesTheArchiveVerifiesItsHashAndUpsertsEveryJsonEntry() {
        Harness h = harness();
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("2003/rhsa-2003_315.json", RHSA_2003_315);
        entries.put("2026/rhsa-2026_9999.json", RHSA_2026_9999);
        byte[] archiveBytes = buildTarZst(entries);
        String archiveSha256 = sha256HexOf(archiveBytes);

        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd"))
                        .headers(headersWithLastModified("Tue, 25 Aug 2026 11:43:13 GMT")));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(archiveSha256, MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(2);
        assertThat(result.failed()).isZero();
        h.server().verify();

        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isPresent();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2026:9999"))).isPresent();
        // purl-derived naming (item 2) took effect for a document synced via the archive path too.
        assertThat(csafProductRepository.findByVendorAndAdvisoryId("redhat", "RHSA-2003:315"))
                .extracting(p -> p.getComponentName()).contains("quagga");

        CsafSyncState state = csafSyncStateRepository.findById("redhat").orElseThrow();
        // Cursor's changes-half is the archive's own Last-Modified header — both halves identical
        // after a baseline (class javadoc).
        assertThat(state.getLastCursor()).isEqualTo("2026-08-25T11:43:13Z|2026-08-25T11:43:13Z");
    }

    @Test
    void baselineSyncSkipsNonJsonArchiveEntries() {
        Harness h = harness();
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("2003/rhsa-2003_315.json", RHSA_2003_315);
        entries.put("README.md", "not json, must be skipped without counting as a failure");
        byte[] archiveBytes = buildTarZst(entries);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(sha256HexOf(archiveBytes), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(1);
        assertThat(result.failed()).isZero();
    }

    @Test
    void baselineSyncAbortsWithoutUpsertingAnythingWhenTheArchiveFailsSha256Verification() {
        Harness h = harness();
        byte[] archiveBytes = buildTarZst(Map.of("2003/rhsa-2003_315.json", RHSA_2003_315));

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                // Deliberately wrong digest — simulates a corrupted/tampered download.
                .andRespond(withSuccess("0".repeat(64) + "  archive.tar.zst", MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isZero();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("redhat")).isEmpty();
    }

    // --- item 5: decompression-bomb protection — three independent bounds, each tested with a small
    // fast fixture via the test-only constructor rather than a 50,000-entry/12GB real-scale archive. --

    @Test
    void baselineSyncAbortsWhenArchiveEntryCountExceedsTheBound() {
        Harness h = harness(1, RedHatCsafSyncService.MAX_DOCUMENT_BYTES, RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES);
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("2003/rhsa-2003_315.json", RHSA_2003_315);
        entries.put("2026/rhsa-2026_9999.json", RHSA_2026_9999); // 2nd entry exceeds the maxArchiveEntryCount=1 bound
        byte[] archiveBytes = buildTarZst(entries);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(sha256HexOf(archiveBytes), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        // The first (already-verified, real) document is real work and is NOT rolled back — see
        // class javadoc — but the run as a whole aborted and the sync state was never written.
        assertThat(result.upserted()).isEqualTo(1);
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isPresent();
        assertThat(csafSyncStateRepository.findById("redhat")).isEmpty();
    }

    @Test
    void baselineSyncAbortsWhenASingleEntryExceedsThePerEntryDecompressionBound() {
        // A tiny bound (1 byte) forces even our small real fixture to trip it — proves the per-entry
        // decompression-bomb check works without needing a genuinely 64MB+ fixture.
        Harness h = harness(RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_ENTRY_COUNT, 1L,
                RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES);
        byte[] archiveBytes = buildTarZst(Map.of("2003/rhsa-2003_315.json", RHSA_2003_315));

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(sha256HexOf(archiveBytes), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isZero();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("redhat")).isEmpty();
    }

    @Test
    void baselineSyncAbortsWhenCumulativeDecompressedSizeExceedsTheTotalBound() {
        Harness h = harness(RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_ENTRY_COUNT, RedHatCsafSyncService.MAX_DOCUMENT_BYTES,
                RHSA_2003_315.getBytes(StandardCharsets.UTF_8).length); // exactly 1 doc's worth — the 2nd trips it
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("2003/rhsa-2003_315.json", RHSA_2003_315);
        entries.put("2026/rhsa-2026_9999.json", RHSA_2026_9999);
        byte[] archiveBytes = buildTarZst(entries);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(sha256HexOf(archiveBytes), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(1);
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isPresent();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2026:9999"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("redhat")).isEmpty();
    }

    // -------------------------------------------------------------------- delta -----------------

    @Test
    void deltaSyncProcessesChangesCsvAscendingByTimestampVerifiesHashAndAdvancesOnlyTheChangesCursor() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(CHANGES_CSV_URL))
                // Deliberately descending order in the raw CSV (real changes.csv is newest-first) —
                // the sync service must sort ascending itself (plan §7), not trust file order.
                .andRespond(withSuccess(
                        "\"2026/rhsa-2026_9999.json\",\"2026-01-01T00:00:00+00:00\"\n"
                                + "\"2003/rhsa-2003_315.json\",\"2003-11-12T14:16:00+00:00\"\n",
                        MediaType.valueOf("text/csv")));
        // Ascending: RHSA-2003:315 (2003) fetched before RHSA-2026:9999 (2026).
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2003/rhsa-2003_315.json"))
                .andRespond(withSuccess(RHSA_2003_315, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2003/rhsa-2003_315.json.sha256"))
                .andRespond(withSuccess(sha256HexOf(RHSA_2003_315.getBytes(StandardCharsets.UTF_8)).replace("archive.tar.zst", "rhsa-2003_315.json"), MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json"))
                .andRespond(withSuccess(RHSA_2026_9999, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json.sha256"))
                .andRespond(withSuccess(sha256HexOf(RHSA_2026_9999.getBytes(StandardCharsets.UTF_8)).replace("archive.tar.zst", "rhsa-2026_9999.json"), MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(DELETIONS_CSV_URL))
                .andRespond(withSuccess("", MediaType.valueOf("text/csv")));

        SyncResult result = h.service().syncDelta();

        assertThat(result.upserted()).isEqualTo(2);
        assertThat(result.failed()).isZero();
        h.server().verify();

        CsafSyncState state = csafSyncStateRepository.findById("redhat").orElseThrow();
        assertThat(state.getLastCursor()).isEqualTo("2026-01-01T00:00Z|");
    }

    @Test
    void deltaSyncOnlyProcessesEntriesNewerThanTheEncodedChangesCursor() {
        Harness h = harness();
        CsafSyncState state = new CsafSyncState("redhat");
        // Already caught up through RHSA-2003:315's timestamp — only RHSA-2026:9999 is eligible.
        state.setLastCursor("2003-11-12T14:16:00Z|");
        csafSyncStateRepository.save(state);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(CHANGES_CSV_URL))
                .andRespond(withSuccess(
                        "\"2003/rhsa-2003_315.json\",\"2003-11-12T14:16:00+00:00\"\n"
                                + "\"2026/rhsa-2026_9999.json\",\"2026-01-01T00:00:00+00:00\"\n",
                        MediaType.valueOf("text/csv")));
        // No expectation for rhsa-2003_315.json — it must NOT be re-fetched, it's not newer than the cursor.
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json"))
                .andRespond(withSuccess(RHSA_2026_9999, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json.sha256"))
                .andRespond(withSuccess(sha256HexOf(RHSA_2026_9999.getBytes(StandardCharsets.UTF_8)).replace("archive.tar.zst", "rhsa-2026_9999.json"), MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(DELETIONS_CSV_URL))
                .andRespond(withSuccess("", MediaType.valueOf("text/csv")));

        SyncResult result = h.service().syncDelta();

        assertThat(result.upserted()).isEqualTo(1);
        h.server().verify();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2026:9999"))).isPresent();
    }

    @Test
    void deltaSyncProcessesDeletionsCsvAndCascadesToProductsAndStatuses() {
        Harness h = harness();
        // Seed the mirror the way baseline/a previous delta would have.
        CsafDocumentUpsertService upsertService = new CsafDocumentUpsertService(
                csafAdvisoryRepository, csafProductRepository, csafProductStatusRepository, new CsafProductTreeWalker());
        upsertService.upsertCsafDocument("redhat", parse(RHSA_2003_315));
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isPresent();

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(CHANGES_CSV_URL))
                .andRespond(withSuccess("", MediaType.valueOf("text/csv")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(DELETIONS_CSV_URL))
                .andRespond(withSuccess("\"2003/rhsa-2003_315.json\",\"2026-01-01T00:00:00+00:00\"\n", MediaType.valueOf("text/csv")));

        SyncResult result = h.service().syncDelta();

        h.server().verify();
        // Cascades to csaf_products/csaf_product_status via V17's ON DELETE CASCADE.
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafProductRepository.findByVendorAndAdvisoryId("redhat", "RHSA-2003:315")).isEmpty();

        CsafSyncState state = csafSyncStateRepository.findById("redhat").orElseThrow();
        assertThat(state.getLastCursor()).isEqualTo("|2026-01-01T00:00Z");
    }

    // --- REVISE item 4 (senior review 2026-08-27): per-run cap must not cut a tied-timestamp group ---

    @Test
    void capWithTiedTimestampExtensionIncludesEveryEntrySharingTheBoundaryTimestamp() {
        Harness h = harness();
        java.time.OffsetDateTime t0 = java.time.OffsetDateTime.parse("2026-01-01T00:00:00Z");
        java.time.OffsetDateTime t1 = java.time.OffsetDateTime.parse("2026-01-02T00:00:00Z");
        java.time.OffsetDateTime t2 = java.time.OffsetDateTime.parse("2026-01-03T00:00:00Z");
        // cap=2 falls squarely in the middle of the t1 tied-timestamp group (b, c, d all share t1).
        java.util.List<RedHatCsafSyncService.ChangeEntry> entries = java.util.List.of(
                new RedHatCsafSyncService.ChangeEntry("2026/a.json", t0),
                new RedHatCsafSyncService.ChangeEntry("2026/b.json", t1),
                new RedHatCsafSyncService.ChangeEntry("2026/c.json", t1),
                new RedHatCsafSyncService.ChangeEntry("2026/d.json", t1),
                new RedHatCsafSyncService.ChangeEntry("2026/e.json", t2));

        java.util.List<RedHatCsafSyncService.ChangeEntry> result = h.service().capWithTiedTimestampExtension(entries, 2);

        // a, b, c, d all kept (every entry at or before the t1 boundary timestamp); e (a later,
        // distinct timestamp) is correctly excluded — the cap is a soft floor, not a hard ceiling.
        assertThat(result).extracting(RedHatCsafSyncService.ChangeEntry::path)
                .containsExactly("2026/a.json", "2026/b.json", "2026/c.json", "2026/d.json");
    }

    @Test
    void capWithTiedTimestampExtensionIsANoOpWhenNoTruncationIsNeeded() {
        Harness h = harness();
        java.time.OffsetDateTime t0 = java.time.OffsetDateTime.parse("2026-01-01T00:00:00Z");
        java.util.List<RedHatCsafSyncService.ChangeEntry> entries = java.util.List.of(
                new RedHatCsafSyncService.ChangeEntry("2026/a.json", t0));

        assertThat(h.service().capWithTiedTimestampExtension(entries, 5)).isEqualTo(entries);
    }

    // --- REVISE item 6 (senior review 2026-08-27): decompression-bomb bound must also cover non-.json
    // archive entries, not just .json ones ------------------------------------------------------------

    @Test
    void baselineSyncAbortsWhenALargeNonJsonArchiveEntryExceedsThePerEntryDecompressionBound() {
        // A tiny per-entry bound forces even a small non-.json fixture to trip it — proves the hole
        // (a non-.json entry used to advance the tar stream WITHOUT ever being read/bounded) is closed.
        Harness h = harness(RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_ENTRY_COUNT, 1L,
                RedHatCsafSyncService.DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES);
        Map<String, String> entries = new LinkedHashMap<>();
        entries.put("README.md", "this non-.json entry is well over the 1-byte per-entry bound");
        entries.put("2003/rhsa-2003_315.json", RHSA_2003_315);
        byte[] archiveBytes = buildTarZst(entries);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ARCHIVE_LATEST_URL))
                .andRespond(withSuccess("csaf_advisories_2026-08-25.tar.zst", MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst"))
                .andRespond(withSuccess(archiveBytes, MediaType.valueOf("application/zstd")));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "csaf_advisories_2026-08-25.tar.zst.sha256"))
                .andRespond(withSuccess(sha256HexOf(archiveBytes), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        // Aborted on the FIRST entry (the oversized non-.json one) — the real .json entry after it is
        // never even reached.
        assertThat(result.upserted()).isZero();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("redhat")).isEmpty();
    }

    // --- REVISE item 10 (senior review 2026-08-27): a legacy pipe-less plain-ISO cursor value must
    // degrade gracefully to (iso, null) rather than fail to parse -------------------------------------

    @Test
    void aLegacyPlainIsoCursorWithNoPipeDegradesGracefullyToAChangesCursorWithNoDeletionsCursor() {
        Harness h = harness();
        CsafSyncState state = new CsafSyncState("redhat");
        // Pre-dual-cursor-encoding format: a bare ISO timestamp, no "|" at all.
        state.setLastCursor("2003-11-12T14:16:00Z");
        csafSyncStateRepository.save(state);

        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(CHANGES_CSV_URL))
                .andRespond(withSuccess(
                        "\"2003/rhsa-2003_315.json\",\"2003-11-12T14:16:00+00:00\"\n"
                                + "\"2026/rhsa-2026_9999.json\",\"2026-01-01T00:00:00+00:00\"\n",
                        MediaType.valueOf("text/csv")));
        // Only the entry strictly after the legacy cursor's changes-half is eligible.
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json"))
                .andRespond(withSuccess(RHSA_2026_9999, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(ADVISORIES_DIR_URL + "2026/rhsa-2026_9999.json.sha256"))
                .andRespond(withSuccess(sha256HexOf(RHSA_2026_9999.getBytes(StandardCharsets.UTF_8)).replace("archive.tar.zst", "rhsa-2026_9999.json"), MediaType.TEXT_PLAIN));
        // A legacy cursor has no deletions-half at all (null) — every deletions.csv row (there are
        // none here) would be eligible; this deliberately proves the changes-half alone parsed
        // correctly rather than the whole decode silently failing.
        h.server().expect(method(HttpMethod.GET)).andExpect(requestTo(DELETIONS_CSV_URL))
                .andRespond(withSuccess("", MediaType.valueOf("text/csv")));

        SyncResult result = h.service().syncDelta();

        assertThat(result.upserted()).isEqualTo(1);
        h.server().verify();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2003:315"))).isEmpty();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("redhat", "RHSA-2026:9999"))).isPresent();
    }

    @Test
    void aSecondSyncWhileOneIsAlreadyRunningIsSkippedRatherThanRunningConcurrently() throws Exception {
        java.util.concurrent.CountDownLatch firstCallStarted = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch releaseFirstCall = new java.util.concurrent.CountDownLatch(1);
        RestClient.Builder blockingBuilder = RestClient.builder()
                .requestInterceptor((request, body, execution) -> {
                    firstCallStarted.countDown();
                    try {
                        releaseFirstCall.await(5, java.util.concurrent.TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    throw new java.io.IOException("intentionally failing after the block, for test cleanup only");
                });
        CsafDocumentUpsertService upsertService = new CsafDocumentUpsertService(
                csafAdvisoryRepository, csafProductRepository, csafProductStatusRepository, new CsafProductTreeWalker());
        // Mocked, not the @Autowired repository: this run happens on a second thread, and
        // @DataJpaTest's rollback is bound to the JUnit test thread's transaction only — writes
        // made by a different thread would actually commit to the real database. The concurrency
        // guard under test lives on the service instance (an AtomicBoolean), not in the
        // repository, so mocking it doesn't weaken what this test verifies.
        CsafSyncStateRepository mockSyncStateRepository = org.mockito.Mockito.mock(CsafSyncStateRepository.class);
        RedHatCsafSyncService blockingService = new RedHatCsafSyncService(blockingBuilder.build(),
                ExternalRegistryRateLimiter.disabledForTesting(), upsertService, csafAdvisoryRepository, mockSyncStateRepository);

        Thread firstRun = new Thread(blockingService::syncBaseline);
        firstRun.start();
        assertThat(firstCallStarted.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

        SyncResult second = blockingService.syncDelta();
        assertThat(second.alreadyRunning()).isTrue();

        releaseFirstCall.countDown();
        firstRun.join(5_000);
    }

    private HttpHeaders headersWithLastModified(String rfc1123Date) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.LAST_MODIFIED, rfc1123Date);
        return headers;
    }

    private com.fasterxml.jackson.databind.JsonNode parse(String json) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().readTree(json);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
