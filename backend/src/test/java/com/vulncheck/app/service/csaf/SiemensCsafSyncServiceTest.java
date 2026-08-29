package com.vulncheck.app.service.csaf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.CsafAdvisoryId;
import com.vulncheck.app.entity.CsafSyncState;
import com.vulncheck.app.repository.CsafAdvisoryRepository;
import com.vulncheck.app.repository.CsafProductRepository;
import com.vulncheck.app.repository.CsafProductStatusRepository;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService.SyncResult;
import com.vulncheck.app.service.registry.ExternalRegistryRateLimiter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Real Siemens ROLIE feed shape (provider-metadata.json, {@code ssa-feed-tlp-white.json} entries,
 * per-document {@code .sha512} hash sidecar) captured live 2026-08-27 — see {@link
 * CsafDocumentUpsertServiceTest} for the same two real captured advisories (SSA-779699, SSA-620799)
 * used as this test's per-document fixtures. Uses {@code @DataJpaTest} against the real Postgres
 * instance (same rationale as {@code VulnerabilityRepositoryTest}) since the mid-sync-failure test
 * needs to observe {@code csaf_sync_state}'s actual persisted cursor.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class SiemensCsafSyncServiceTest {

    @Autowired
    private CsafAdvisoryRepository csafAdvisoryRepository;
    @Autowired
    private CsafProductRepository csafProductRepository;
    @Autowired
    private CsafProductStatusRepository csafProductStatusRepository;
    @Autowired
    private CsafSyncStateRepository csafSyncStateRepository;

    private static final String PROVIDER_METADATA = """
            {
              "canonical_url": "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
              "distributions": [
                { "rolie": { "feeds": [
                  { "summary": "All TLP:WHITE advisories of Siemens AG.", "tlp_label": "WHITE",
                    "url": "https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json" }
                ] } }
              ],
              "publisher": { "name": "Siemens ProductCERT", "category": "vendor", "namespace": "https://www.siemens.com" },
              "role": "csaf_trusted_provider"
            }
            """;

    private static final String SSA_779699 = """
            {
              "document": {
                "title": "SSA-779699: Two Incorrect Authorization Vulnerabilities in Mendix",
                "tracking": { "id": "SSA-779699", "status": "final", "version": "1",
                  "initial_release_date": "2021-11-09T00:00:00Z", "current_release_date": "2021-11-09T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "name": "Siemens", "category": "vendor", "branches": [
                { "name": "Mendix Applications using Mendix 8", "category": "product_name", "branches": [
                  { "name": "< V8.18.13", "category": "product_version_range",
                    "product": { "product_id": "1", "name": "Mendix Applications using Mendix 8" } } ] }
              ] } ] },
              "vulnerabilities": [
                { "cve": "CVE-2021-42025", "product_status": { "known_affected": ["1"] } }
              ]
            }
            """;

    private static final String SSA_620799 = """
            {
              "document": {
                "title": "SSA-620799: Denial of Service Vulnerability During BLE Pairing in SENTRON Powercenter 1000/1100",
                "tracking": { "id": "SSA-620799", "status": "final", "version": "2",
                  "initial_release_date": "2024-12-10T00:00:00Z", "current_release_date": "2025-06-10T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "branches": [
                { "branches": [ { "category": "product_version_range", "name": "vers:all/*",
                    "product": { "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)", "product_id": "1" } } ],
                  "category": "product_name", "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)" } ],
                "category": "vendor", "name": "Siemens" } ] },
              "vulnerabilities": [
                { "cve": "CVE-2024-6657", "product_status": { "known_not_affected": ["1"] } }
              ]
            }
            """;

    private static final String SSA_999999 = """
            {
              "document": {
                "title": "SSA-999999: Test-only third document for the cursor regression test",
                "tracking": { "id": "SSA-999999", "status": "final", "version": "1",
                  "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "name": "Siemens", "category": "vendor", "branches": [
                { "name": "Widget Gadget", "category": "product_name", "branches": [
                  { "name": "vers:all/*", "category": "product_version_range",
                    "product": { "product_id": "1", "name": "Widget Gadget" } } ] }
              ] } ] },
              "vulnerabilities": [
                { "cve": "CVE-2026-00001", "product_status": { "known_affected": ["1"] } }
              ]
            }
            """;

    private static String updatedFor(String id) {
        return switch (id) {
            case "SSA-779699" -> "2021-11-09T00:00:00Z";
            case "SSA-620799" -> "2025-06-10T00:00:00Z";
            case "SSA-999999" -> "2026-01-01T00:00:00Z";
            default -> throw new IllegalArgumentException("no fixture timestamp registered for " + id);
        };
    }

    private static String feedJson(String... entryIds) {
        StringBuilder entries = new StringBuilder();
        for (String id : entryIds) {
            String updated = updatedFor(id);
            String lower = id.toLowerCase(java.util.Locale.ROOT);
            if (!entries.isEmpty()) {
                entries.append(",");
            }
            entries.append("""
                    {
                      "id": "%s",
                      "link": [
                        { "rel": "self", "href": "https://cert-portal.siemens.com/productcert/csaf/%s.json" },
                        { "rel": "hash", "href": "https://cert-portal.siemens.com/productcert/csaf/%s.json.sha512" }
                      ],
                      "published": "%s",
                      "updated": "%s",
                      "content": { "type": "application/json", "src": "https://cert-portal.siemens.com/productcert/csaf/%s.json" }
                    }
                    """.formatted(id, lower, lower, updated, updated, lower));
        }
        return "{ \"feed\": { \"id\": \"ssa-feed\", \"entry\": [" + entries + "] } }";
    }

    /** Same shape as {@link #feedJson} but with no {@code link[rel=hash]} entry at all — for the
     *  item-4 regression test. */
    private static String feedJsonEntryWithNoHashLink(String id) {
        String updated = updatedFor(id);
        String lower = id.toLowerCase(java.util.Locale.ROOT);
        String entry = """
                {
                  "id": "%s",
                  "link": [
                    { "rel": "self", "href": "https://cert-portal.siemens.com/productcert/csaf/%s.json" }
                  ],
                  "published": "%s",
                  "updated": "%s",
                  "content": { "type": "application/json", "src": "https://cert-portal.siemens.com/productcert/csaf/%s.json" }
                }
                """.formatted(id, lower, updated, updated, lower);
        return "{ \"feed\": { \"id\": \"ssa-feed\", \"entry\": [" + entry + "] } }";
    }

    private static String sha512Hex(String content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-512").digest(content.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private record Harness(SiemensCsafSyncService service, MockRestServiceServer server) {
    }

    private Harness harness() {
        RestClient.Builder restClientBuilder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(restClientBuilder).build();
        CsafDocumentUpsertService upsertService = new CsafDocumentUpsertService(
                csafAdvisoryRepository, csafProductRepository, csafProductStatusRepository, new CsafProductTreeWalker());
        SiemensCsafSyncService syncService = new SiemensCsafSyncService(
                restClientBuilder.build(), ExternalRegistryRateLimiter.disabledForTesting(), upsertService, csafSyncStateRepository);
        return new Harness(syncService, server);
    }

    @Test
    void baselineSyncUpsertsEveryEntryInAscendingUpdatedOrderAndAdvancesTheCursor() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"))
                .andRespond(withSuccess(PROVIDER_METADATA, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"))
                .andRespond(withSuccess(feedJson("SSA-779699", "SSA-620799"), MediaType.APPLICATION_JSON));
        // Ascending by `updated` — SSA-779699 (2021) before SSA-620799 (2025).
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json"))
                .andRespond(withSuccess(SSA_779699, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json.sha512"))
                .andRespond(withSuccess(sha512Hex(SSA_779699), MediaType.TEXT_PLAIN));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-620799.json"))
                .andRespond(withSuccess(SSA_620799, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-620799.json.sha512"))
                .andRespond(withSuccess(sha512Hex(SSA_620799), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(2);
        assertThat(result.failed()).isZero();
        h.server().verify();

        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-779699"))).isPresent();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-620799"))).isPresent();

        CsafSyncState state = csafSyncStateRepository.findById("siemens").orElseThrow();
        assertThat(state.getLastCursor()).isEqualTo("2025-06-10T00:00Z");
    }

    // REVISE item 2 (senior review 2026-08-27): the original 2-entry version of this test put the
    // failure on the LAST entry, so "cursor stopped at the failure" and "cursor advanced to the last
    // success" were indistinguishable — it would have passed even with the cursor-pollution bug this
    // now actually exercises. Restructured to 3 entries with the failure on the MIDDLE one and a
    // valid entry after it, asserting both that processing continues past the failure (entry #3 is
    // upserted) and that the cursor does NOT advance past the failure (stops at entry #1).
    @Test
    void aHashMismatchOnAMiddleDocumentIsSkippedButProcessingContinuesAndTheCursorStopsAtTheFailure() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"))
                .andRespond(withSuccess(PROVIDER_METADATA, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"))
                .andRespond(withSuccess(feedJson("SSA-779699", "SSA-620799", "SSA-999999"), MediaType.APPLICATION_JSON));
        // Entry #1 (oldest `updated`) — succeeds.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json"))
                .andRespond(withSuccess(SSA_779699, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json.sha512"))
                .andRespond(withSuccess(sha512Hex(SSA_779699), MediaType.TEXT_PLAIN));
        // Entry #2 — its own bytes are fetched fine, but its hash sidecar deliberately does NOT match
        // (simulates corruption/tampering in transit) — plan §6/§7: skip it, do not upsert.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-620799.json"))
                .andRespond(withSuccess(SSA_620799, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-620799.json.sha512"))
                .andRespond(withSuccess("0".repeat(128), MediaType.TEXT_PLAIN));
        // Entry #3 (newest `updated`) — must still be processed and upserted despite entry #2 having
        // failed (processing continues past a failure, it doesn't abort the run).
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-999999.json"))
                .andRespond(withSuccess(SSA_999999, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-999999.json.sha512"))
                .andRespond(withSuccess(sha512Hex(SSA_999999), MediaType.TEXT_PLAIN));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(2);
        assertThat(result.failed()).isEqualTo(1);
        h.server().verify();

        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-779699"))).isPresent();
        // The corrupted document must never be upserted.
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-620799"))).isEmpty();
        // Regression: the entry AFTER the failure must still have been processed and upserted.
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-999999"))).isPresent();

        CsafSyncState state = csafSyncStateRepository.findById("siemens").orElseThrow();
        // Cursor sits at SSA-779699's own updated timestamp — NOT SSA-999999's (2026-01-01), which
        // would have skipped past the failed SSA-620799 entry on the next delta run.
        assertThat(state.getLastCursor()).isEqualTo("2021-11-09T00:00Z");
    }

    // --- REVISE item 4 (senior review 2026-08-27): a missing hash link must not bypass verification --

    @Test
    void anEntryWithNoHashLinkIsTreatedAsAFailureRatherThanUpsertedUnverified() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"))
                .andRespond(withSuccess(PROVIDER_METADATA, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"))
                .andRespond(withSuccess(feedJsonEntryWithNoHashLink("SSA-779699"), MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json"))
                .andRespond(withSuccess(SSA_779699, MediaType.APPLICATION_JSON));
        // Deliberately no expectation for a .sha512 request — a missing hash link must never trigger one.

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isZero();
        assertThat(result.failed()).isEqualTo(1);
        h.server().verify();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-779699"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("siemens")).isEmpty();
    }

    // --- REVISE item 5 (senior review 2026-08-27): a rate-limited hash sidecar fetch must abort the
    // run, same as a rate-limited document fetch does -----------------------------------------------

    @Test
    void aRateLimitedHashSidecarFetchAbortsTheRunWithoutUpsertingTheOffendingDocumentOrAnyAfterIt() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"))
                .andRespond(withSuccess(PROVIDER_METADATA, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"))
                .andRespond(withSuccess(feedJson("SSA-779699", "SSA-620799"), MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json"))
                .andRespond(withSuccess(SSA_779699, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json.sha512"))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));
        // No expectations for entry #2 at all — the run must abort before ever reaching it.

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isZero();
        h.server().verify();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-779699"))).isEmpty();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-620799"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("siemens")).isEmpty();
    }

    @Test
    void a429ResponseAbortsTheRunWithoutUpsertingTheOffendingDocumentOrAnyAfterIt() {
        Harness h = harness();
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json"))
                .andRespond(withSuccess(PROVIDER_METADATA, MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"))
                .andRespond(withSuccess(feedJson("SSA-779699", "SSA-620799"), MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://cert-portal.siemens.com/productcert/csaf/ssa-779699.json"))
                .andRespond(org.springframework.test.web.client.response.MockRestResponseCreators
                        .withStatus(org.springframework.http.HttpStatus.TOO_MANY_REQUESTS));

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isZero();
        assertThat(csafAdvisoryRepository.findById(new CsafAdvisoryId("siemens", "SSA-779699"))).isEmpty();
        assertThat(csafSyncStateRepository.findById("siemens")).isEmpty();
    }

    // --- REVISE item 4 (senior review 2026-08-27): per-run cap must not cut a tied-timestamp group,
    // same fix as RedHatCsafSyncService's identical helper --------------------------------------------

    @Test
    void capWithTiedTimestampExtensionIncludesEveryEntrySharingTheBoundaryTimestamp() {
        Harness h = harness();
        OffsetDateTime t0 = OffsetDateTime.parse("2026-01-01T00:00:00Z");
        OffsetDateTime t1 = OffsetDateTime.parse("2026-01-02T00:00:00Z");
        OffsetDateTime t2 = OffsetDateTime.parse("2026-01-03T00:00:00Z");
        // cap=2 falls squarely in the middle of the t1 tied-timestamp group (b, c, d all share t1).
        java.util.List<SiemensCsafSyncService.RolieEntry> entries = java.util.List.of(
                new SiemensCsafSyncService.RolieEntry("a", "https://x/a.json", "https://x/a.json.sha512", t0),
                new SiemensCsafSyncService.RolieEntry("b", "https://x/b.json", "https://x/b.json.sha512", t1),
                new SiemensCsafSyncService.RolieEntry("c", "https://x/c.json", "https://x/c.json.sha512", t1),
                new SiemensCsafSyncService.RolieEntry("d", "https://x/d.json", "https://x/d.json.sha512", t1),
                new SiemensCsafSyncService.RolieEntry("e", "https://x/e.json", "https://x/e.json.sha512", t2));

        java.util.List<SiemensCsafSyncService.RolieEntry> result = h.service().capWithTiedTimestampExtension(entries, 2);

        assertThat(result).extracting(SiemensCsafSyncService.RolieEntry::id).containsExactly("a", "b", "c", "d");
    }

    @Test
    void aSecondSyncWhileOneIsAlreadyRunningIsSkippedRatherThanRunningConcurrently() throws Exception {
        // A real concurrency test (plan §5-4's "same-vendor sync already running" guard) rather
        // than a same-thread sequential call — a request interceptor blocks the FIRST sync's very
        // first HTTP call until released, so the SECOND sync (started from another thread while the
        // first is still genuinely in flight) can only see alreadyRunning=true if the guard truly
        // works under concurrency, not just "returns fast when called twice in a row".
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
        SiemensCsafSyncService blockingService = new SiemensCsafSyncService(
                blockingBuilder.build(), ExternalRegistryRateLimiter.disabledForTesting(), upsertService, mockSyncStateRepository);

        Thread firstRun = new Thread(blockingService::syncBaseline);
        firstRun.start();
        assertThat(firstCallStarted.await(5, java.util.concurrent.TimeUnit.SECONDS)).isTrue();

        SyncResult second = blockingService.syncDelta();
        assertThat(second.alreadyRunning()).isTrue();

        releaseFirstCall.countDown();
        firstRun.join(5_000);
    }
}
