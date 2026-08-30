package com.vulncheck.app.service.ghsa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.entity.GhsaSyncFailure;
import com.vulncheck.app.entity.GhsaSyncState;
import com.vulncheck.app.repository.GhsaAdvisoryRepository;
import com.vulncheck.app.repository.GhsaAffectedPackageRepository;
import com.vulncheck.app.repository.GhsaAffectedRangeRepository;
import com.vulncheck.app.repository.GhsaAffectedVersionRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.service.ghsa.GhsaSyncService.SyncResult;
import com.vulncheck.app.service.vuln.GhsaRateLimiter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Real GHSA-reviewed document shapes captured live 2026-08-27 (same fixtures as {@code
 * GhsaDocumentUpsertServiceTest}), exercised through {@link GhsaSyncService}'s baseline (in-memory
 * tarball, since {@code MockRestServiceServer} can't intercept the raw {@link
 * java.net.URLConnection} the production tarball-body download uses — see the seam on {@code
 * tarballStreamOpener}) and delta (REST list + raw.githubusercontent.com fetch, both mocked) paths.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class GhsaSyncServiceTest {

    @Autowired
    private GhsaAdvisoryRepository ghsaAdvisoryRepository;
    @Autowired
    private GhsaAffectedPackageRepository ghsaAffectedPackageRepository;
    @Autowired
    private GhsaAffectedRangeRepository ghsaAffectedRangeRepository;
    @Autowired
    private GhsaAffectedVersionRepository ghsaAffectedVersionRepository;
    @Autowired
    private GhsaSyncStateRepository ghsaSyncStateRepository;
    @Autowired
    private GhsaSyncFailureRepository ghsaSyncFailureRepository;
    @Autowired
    private jakarta.persistence.EntityManager entityManager;

    private static final String TARBALL_URL = "https://api.github.com/repos/github/advisory-database/tarball/main";
    private static final String COMMITS_URL = "https://api.github.com/repos/github/advisory-database/commits/main";
    private static final String CODELOAD_URL = "https://codeload.github.com/github/advisory-database/legacy.tar.gz/refs/heads/main";

    // Real: ImageMagick memory leak (NuGet), real: OpenWISP IPAM (PyPI, no CVE alias) — same fixtures
    // as GhsaDocumentUpsertServiceTest.
    private static final String GHSA_WFX3 = """
            {"id": "GHSA-wfx3-6g53-9fgc", "modified": "2026-08-26T20:48:48Z", "published": "2026-02-25T19:13:32Z",
             "aliases": ["CVE-2026-56368"], "summary": "ImageMagick memory leak",
             "affected": [{"package": {"ecosystem": "NuGet", "name": "Magick.NET-Q16-AnyCPU"},
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "14.10.3"}]}]}],
             "database_specific": {"severity": "MODERATE"}}
            """;
    private static final String GHSA_X287 = """
            {"id": "GHSA-x287-5c68-36wp", "modified": "2026-08-26T14:38:10Z", "published": "2026-08-26T14:38:10Z",
             "aliases": [], "summary": "OpenWISP IPAM broken object-level authorization",
             "affected": [{"package": {"ecosystem": "PyPI", "name": "openwisp-ipam"},
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.1"}]}]}],
             "database_specific": {"severity": "MODERATE"}}
            """;
    private static final String GHSA_VG9F_WITHDRAWN = """
            {"id": "GHSA-vg9f-q4xh-62r4", "modified": "2026-08-25T18:09:14Z", "published": "2026-06-15T03:30:32Z",
             "withdrawn": "2026-08-25T18:09:14Z", "aliases": [], "summary": "Duplicate advisory",
             "affected": [{"package": {"ecosystem": "PyPI", "name": "utcp-gql"},
               "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.1.0"}]}]}],
             "database_specific": {"severity": "MODERATE"}}
            """;

    private record Harness(GhsaSyncService service, MockRestServiceServer server) {
    }

    private Harness harness(int expectedBaselineCount, byte[] tarballBytes) {
        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        GhsaDocumentUpsertService upsertService = new GhsaDocumentUpsertService(
                ghsaAdvisoryRepository, ghsaAffectedPackageRepository, ghsaAffectedRangeRepository, ghsaAffectedVersionRepository);
        java.util.function.Function<String, InputStream> opener =
                tarballBytes != null ? (url -> new ByteArrayInputStream(tarballBytes)) : null;
        GhsaSyncService service = new GhsaSyncService(builder.build(), upsertService, ghsaAdvisoryRepository,
                ghsaSyncStateRepository, ghsaSyncFailureRepository, GhsaRateLimiter.disabledForTesting(),
                expectedBaselineCount, opener);
        return new Harness(service, server);
    }

    private void expectCommitsAndTarballRedirect(MockRestServiceServer server, String shortSha) {
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(COMMITS_URL))
                .andRespond(withSuccess("{\"sha\": \"" + shortSha + "000000000000000000000000000000\"}", MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(TARBALL_URL))
                .andRespond(withStatus(org.springframework.http.HttpStatus.FOUND).header("Location", CODELOAD_URL));
    }

    /** Builds an in-memory {@code .tar.gz} with a single top-level directory (matching git tarball
     *  shape — {@code <reponame>-<shortsha>/advisories/github-reviewed/<YYYY>/<MM>/<id>/<id>.json}),
     *  plus one {@code advisories/unreviewed/} entry and one non-JSON entry that must both be
     *  skipped, verifying that filter without needing a huge fixture. */
    private byte[] buildTarGz(String shortSha, Map<String, String> ghsaIdToJson) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (GzipCompressorOutputStream gzip = new GzipCompressorOutputStream(bytes);
                    TarArchiveOutputStream tar = new TarArchiveOutputStream(gzip)) {
                // GHSA-reviewed paths (e.g. .../advisories/github-reviewed/2026/08/GHSA-xxxx-xxxx-xxxx/
                // GHSA-xxxx-xxxx-xxxx.json) routinely exceed ustar's 100-char name field — GNU long-name
                // extension, same as the real codeload.github.com tarball uses (confirmed live 2026-08-27).
                tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_GNU);
                String topDir = "github-advisory-database-" + shortSha;
                for (Map.Entry<String, String> entry : ghsaIdToJson.entrySet()) {
                    String ghsaId = entry.getKey();
                    String yearMonth = "2026/08";
                    String path = topDir + "/advisories/github-reviewed/" + yearMonth + "/" + ghsaId + "/" + ghsaId + ".json";
                    addEntry(tar, path, entry.getValue());
                }
                addEntry(tar, topDir + "/advisories/unreviewed/2026/08/GHSA-should-be-skipped/GHSA-should-be-skipped.json",
                        "{\"id\": \"GHSA-should-be-skipped\", \"modified\": \"2026-01-01T00:00:00Z\"}");
                addEntry(tar, topDir + "/README.md", "not json, must be skipped");
                tar.finish();
            }
            return bytes.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void addEntry(TarArchiveOutputStream tar, String path, String content) throws Exception {
        byte[] bytes = content.getBytes(StandardCharsets.UTF_8);
        TarArchiveEntry entry = new TarArchiveEntry(path);
        entry.setSize(bytes.length);
        tar.putArchiveEntry(entry);
        tar.write(bytes);
        tar.closeArchiveEntry();
    }

    // ------------------------------------------------------------------ baseline ----------------

    @Test
    void baselineSyncUpsertsEveryDocumentSkipsUnreviewedAndNonJsonAndMarksBaselineLoaded() {
        Map<String, String> docs = new LinkedHashMap<>();
        docs.put("GHSA-wfx3-6g53-9fgc", GHSA_WFX3);
        docs.put("GHSA-x287-5c68-36wp", GHSA_X287);
        docs.put("GHSA-vg9f-q4xh-62r4", GHSA_VG9F_WITHDRAWN);
        byte[] tarball = buildTarGz("abc1234", docs);

        Harness h = harness(3, tarball); // expectedBaselineCount=3 — exactly matches, so 100% >= 90%
        expectCommitsAndTarballRedirect(h.server(), "abc1234");

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(3);
        assertThat(result.failed()).isZero();
        h.server().verify();

        assertThat(ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc")).isPresent();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-x287-5c68-36wp")).isPresent();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-vg9f-q4xh-62r4")).isPresent();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-should-be-skipped")).isEmpty(); // unreviewed — never even parsed

        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElseThrow();
        assertThat(state.isBaselineLoaded()).isTrue();
        assertThat(state.getBaselineCommitSha()).startsWith("abc1234");
        assertThat(state.isSyncInProgress()).isFalse();
        assertThat(state.getLastSyncError()).isNull();
    }

    @Test
    void baselineBelowTheCompletenessThresholdIsNotMarkedLoaded() {
        Map<String, String> docs = new LinkedHashMap<>();
        docs.put("GHSA-wfx3-6g53-9fgc", GHSA_WFX3); // only 1 of an "expected" 10 — 10% << 90%
        byte[] tarball = buildTarGz("def5678", docs);

        Harness h = harness(10, tarball);
        expectCommitsAndTarballRedirect(h.server(), "def5678");

        SyncResult result = h.service().syncBaseline();

        assertThat(result.upserted()).isEqualTo(1);
        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElseThrow();
        assertThat(state.isBaselineLoaded()).isFalse();
        assertThat(state.getLastSyncError()).contains("incomplete");
        // The document itself is still upserted (best-effort) even though the RUN as a whole isn't
        // marked complete — plan §0-1 principle 1 is about the *state flag*, not about discarding
        // otherwise-valid work.
        assertThat(ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc")).isPresent();
    }

    @Test
    void baselinePrunesAdvisoriesNoLongerPresentInTheTarball() {
        // Seed a pre-existing advisory NOT part of this run's tarball, backdated so it's older than
        // the run's own start time (plan §6-3 tombstone pruning).
        GhsaDocumentUpsertService seedService = new GhsaDocumentUpsertService(
                ghsaAdvisoryRepository, ghsaAffectedPackageRepository, ghsaAffectedRangeRepository, ghsaAffectedVersionRepository);
        seedService.upsertGhsaAdvisory(new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(
                Map.of("id", "GHSA-old-removed-000", "modified", "2020-01-01T00:00:00Z",
                        "published", "2020-01-01T00:00:00Z", "aliases", java.util.List.of(),
                        "summary", "no longer in github-reviewed", "affected", java.util.List.of())));
        ghsaAdvisoryRepository.findById("GHSA-old-removed-000").ifPresent(a -> {
            a.setLastSyncedAt(OffsetDateTime.now().minusDays(1));
            // saveAndFlush, not save: doSyncBaseline's tombstone pruning runs a native DELETE query,
            // which Hibernate can't auto-flush-before-query for (it doesn't parse native SQL to know
            // it touches ghsa_advisories) — without an explicit flush here, the pending UPDATE above
            // wouldn't be visible to that DELETE within this same test transaction.
            ghsaAdvisoryRepository.saveAndFlush(a);
            // Clears Hibernate's first-level cache for this managed entity — without this, the
            // later native bulk DELETE (deleteNotSyncedSince) removes the row from Postgres but
            // Hibernate's session cache is never told, so a post-sync findById() would return this
            // now-stale cached instance instead of correctly finding nothing.
            entityManager.clear();
        });

        Map<String, String> docs = new LinkedHashMap<>();
        docs.put("GHSA-wfx3-6g53-9fgc", GHSA_WFX3);
        byte[] tarball = buildTarGz("aaa1111", docs);
        Harness h = harness(1, tarball);
        expectCommitsAndTarballRedirect(h.server(), "aaa1111");

        h.service().syncBaseline();
        entityManager.clear();

        assertThat(ghsaAdvisoryRepository.findById("GHSA-old-removed-000")).isEmpty();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc")).isPresent();
    }

    // Senior review item 1 regression: a document that merely FAILED to parse/upsert this run must
    // not be treated as "genuinely removed from github-reviewed" and pruned — it keeps its old
    // last_synced_at (older than runStartedAt), which would otherwise look exactly like a real
    // tombstone to the prune query, silently deleting a still-published advisory.
    @Test
    void baselineDoesNotPruneAnythingWhenAnExistingAdvisorysDocumentFailsToUpsertThisRun() throws Exception {
        GhsaDocumentUpsertService seedService = new GhsaDocumentUpsertService(
                ghsaAdvisoryRepository, ghsaAffectedPackageRepository, ghsaAffectedRangeRepository, ghsaAffectedVersionRepository);
        seedService.upsertGhsaAdvisory(new com.fasterxml.jackson.databind.ObjectMapper().readTree(GHSA_WFX3));
        ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc").ifPresent(a -> {
            a.setLastSyncedAt(OffsetDateTime.now().minusDays(1));
            // saveAndFlush + entityManager.clear() — see baselinePrunesAdvisoriesNoLongerPresentInTheTarball's
            // own comment for why both are needed around the native bulk DELETE this run may (or, in this
            // test, must NOT) issue.
            ghsaAdvisoryRepository.saveAndFlush(a);
            entityManager.clear();
        });

        Map<String, String> docs = new LinkedHashMap<>();
        // This run's copy of the EXISTING advisory's own document fails to parse — its DB row is
        // therefore never touched (and its last_synced_at stays backdated).
        docs.put("GHSA-wfx3-6g53-9fgc", "{ not valid json");
        // A different, unrelated document that succeeds normally this run.
        docs.put("GHSA-x287-5c68-36wp", GHSA_X287);
        byte[] tarball = buildTarGz("bbb2222", docs);
        Harness h = harness(1, tarball); // expectedBaselineCount=1 — the one success alone clears the 90% gate
        expectCommitsAndTarballRedirect(h.server(), "bbb2222");

        SyncResult result = h.service().syncBaseline();
        entityManager.clear();

        assertThat(result.upserted()).isEqualTo(1);
        assertThat(result.failed()).isEqualTo(1);
        // The critical assertion: NOT pruned, even though its last_synced_at is older than
        // runStartedAt — pruning must not run at all this run, since at least one document failed.
        assertThat(ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc")).isPresent();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-x287-5c68-36wp")).isPresent();
    }

    // -------------------------------------------------------------------- delta -----------------

    private void seedBaselineLoadedState(OffsetDateTime cursor) {
        GhsaSyncState state = new GhsaSyncState();
        state.setId((short) 1);
        state.setBaselineLoaded(true);
        state.setLastCursor(cursor);
        ghsaSyncStateRepository.save(state);
    }

    private String listResponse(String... ghsaIdUpdatedPairsAsJson) {
        return "[" + String.join(",", ghsaIdUpdatedPairsAsJson) + "]";
    }

    private String summaryJson(String ghsaId, String publishedAt, String updatedAt) {
        return "{\"ghsa_id\": \"%s\", \"published_at\": \"%s\", \"updated_at\": \"%s\"}".formatted(ghsaId, publishedAt, updatedAt);
    }

    // REVISE-equivalent (mirrors SiemensCsafSyncServiceTest's own regression, checklist item 2):
    // the failure sits on the MIDDLE entry of three, not the last, so "processing continued past
    // the failure" and "the cursor stopped exactly at the failure" are actually distinguishable.
    @Test
    void aMidBatchFailureIsSkippedButProcessingContinuesAndTheCursorStopsBeforeIt() {
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        Harness h = harness(1, null);

        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(org.hamcrest.Matchers.containsString("api.github.com/advisories")))
                .andRespond(withSuccess(listResponse(
                        summaryJson("GHSA-wfx3-6g53-9fgc", "2026-02-25T19:13:32Z", "2026-02-25T19:13:32Z"),
                        summaryJson("GHSA-x287-5c68-36wp", "2026-08-26T14:38:10Z", "2026-08-26T14:38:10Z"),
                        summaryJson("GHSA-vg9f-q4xh-62r4", "2026-06-15T03:30:32Z", "2026-06-15T03:30:32Z")),
                        MediaType.APPLICATION_JSON));
        // Entry #1 (oldest updated_at) — succeeds.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/02/GHSA-wfx3-6g53-9fgc/GHSA-wfx3-6g53-9fgc.json"))
                .andRespond(withSuccess(GHSA_WFX3, MediaType.APPLICATION_JSON));
        // Entry #2 (middle, by updated_at) — deliberately malformed JSON, must fail.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-vg9f-q4xh-62r4/GHSA-vg9f-q4xh-62r4.json"))
                .andRespond(withSuccess("{ not valid json", MediaType.APPLICATION_JSON));
        // Entry #3 (newest updated_at) — must STILL be processed despite entry #2's failure.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/08/GHSA-x287-5c68-36wp/GHSA-x287-5c68-36wp.json"))
                .andRespond(withSuccess(GHSA_X287, MediaType.APPLICATION_JSON));

        SyncResult result = h.service().syncDelta();

        assertThat(result.upserted()).isEqualTo(2);
        assertThat(result.failed()).isEqualTo(1);
        h.server().verify();

        assertThat(ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc")).isPresent();
        assertThat(ghsaAdvisoryRepository.findById("GHSA-vg9f-q4xh-62r4")).isEmpty(); // never upserted
        // Regression guard: the entry AFTER the failure was still processed.
        assertThat(ghsaAdvisoryRepository.findById("GHSA-x287-5c68-36wp")).isPresent();

        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElseThrow();
        // Cursor sits at entry #1's own updated_at — NOT entry #3's, which would silently skip
        // entry #2 forever on every future run.
        assertThat(state.getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-02-25T19:13:32Z"));
    }

    @Test
    void aGhsaIdFailingThreeConsecutiveDeltaRunsIsDeadLetteredAndTheCursorThenAdvancesPastIt() {
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        Harness h = harness(1, null);

        // The SAME single-entry list response and SAME malformed raw document, three delta runs in a
        // row — since a failure never advances the cursor, each run re-discovers the same advisory.
        for (int i = 0; i < 3; i++) {
            h.server().expect(method(HttpMethod.GET))
                    .andExpect(requestTo(org.hamcrest.Matchers.containsString("api.github.com/advisories")))
                    .andRespond(withSuccess(listResponse(
                            summaryJson("GHSA-vg9f-q4xh-62r4", "2026-06-15T03:30:32Z", "2026-06-15T03:30:32Z")),
                            MediaType.APPLICATION_JSON));
            h.server().expect(method(HttpMethod.GET))
                    .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-vg9f-q4xh-62r4/GHSA-vg9f-q4xh-62r4.json"))
                    .andRespond(withSuccess("{ not valid json", MediaType.APPLICATION_JSON));
        }

        h.service().syncDelta();
        h.service().syncDelta();
        SyncResult third = h.service().syncDelta();

        h.server().verify();
        assertThat(third.failed()).isEqualTo(1);

        GhsaSyncFailure failure = ghsaSyncFailureRepository.findById("GHSA-vg9f-q4xh-62r4").orElseThrow();
        assertThat(failure.getConsecutiveFailures()).isEqualTo(3);
        assertThat(failure.getDeadLetteredAt()).isNotNull();

        // Exempted from the "never advance past a failure" rule once dead-lettered — the cursor is
        // now past this poison-pill entry so it doesn't wedge delta sync forever.
        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElseThrow();
        assertThat(state.getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-06-15T03:30:32Z"));
    }

    @Test
    void aSuccessAfterPriorFailuresClearsTheDeadLetterCounter() {
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        Harness h = harness(1, null);

        // Both delta runs' expectations are registered upfront — MockRestServiceServer's default
        // ordered-expectation mode doesn't allow adding more expectations after requests have
        // already been made against it.
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(org.hamcrest.Matchers.containsString("api.github.com/advisories")))
                .andRespond(withSuccess(listResponse(
                        summaryJson("GHSA-vg9f-q4xh-62r4", "2026-06-15T03:30:32Z", "2026-06-15T03:30:32Z")),
                        MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-vg9f-q4xh-62r4/GHSA-vg9f-q4xh-62r4.json"))
                .andRespond(withSuccess("{ not valid json", MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo(org.hamcrest.Matchers.containsString("api.github.com/advisories")))
                .andRespond(withSuccess(listResponse(
                        summaryJson("GHSA-vg9f-q4xh-62r4", "2026-06-15T03:30:32Z", "2026-06-15T03:30:32Z")),
                        MediaType.APPLICATION_JSON));
        h.server().expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2026/06/GHSA-vg9f-q4xh-62r4/GHSA-vg9f-q4xh-62r4.json"))
                .andRespond(withSuccess(GHSA_VG9F_WITHDRAWN, MediaType.APPLICATION_JSON)); // now succeeds

        h.service().syncDelta(); // 1 failure recorded
        h.service().syncDelta(); // succeeds — should clear the counter

        h.server().verify();
        assertThat(ghsaSyncFailureRepository.findById("GHSA-vg9f-q4xh-62r4")).isEmpty();
    }

    @Test
    void interruptedThreadAbortsDeltaBeforeAnyRequestAndDoesNotAdvanceTheCursor() throws Exception {
        seedBaselineLoadedState(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
        Harness h = harness(1, null); // no expectations registered — any HTTP call fails the test

        Thread.currentThread().interrupt();
        try {
            SyncResult result = h.service().syncDelta();
            assertThat(result.upserted()).isZero();
            assertThat(result.failed()).isZero();
        } finally {
            assertThat(Thread.interrupted()).isTrue(); // clear the flag so it doesn't leak into other tests
        }
        h.server().verify(); // zero expectations set, zero requests made

        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElseThrow();
        assertThat(state.getLastCursor()).isEqualTo(OffsetDateTime.parse("2026-01-01T00:00:00Z"));
    }

    @Test
    void deltaSyncIsANoOpWhenBaselineHasNeverCompleted() {
        Harness h = harness(1, null); // no expectations — must not make any HTTP call

        SyncResult result = h.service().syncDelta();

        assertThat(result.upserted()).isZero();
        assertThat(result.alreadyRunning()).isFalse();
        h.server().verify();
    }

    // ------------------------------------------------------------ concurrency guard --------------

    @Test
    void aSecondSyncWhileOneIsAlreadyRunningIsSkippedRatherThanRunningConcurrently() throws Exception {
        CountDownLatch firstCallStarted = new CountDownLatch(1);
        CountDownLatch releaseFirstCall = new CountDownLatch(1);
        RestClient.Builder blockingBuilder = RestClient.builder()
                .requestInterceptor((request, body, execution) -> {
                    firstCallStarted.countDown();
                    try {
                        releaseFirstCall.await(5, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    }
                    throw new java.io.IOException("intentionally failing after the block, for test cleanup only");
                });
        GhsaDocumentUpsertService upsertService = new GhsaDocumentUpsertService(
                ghsaAdvisoryRepository, ghsaAffectedPackageRepository, ghsaAffectedRangeRepository, ghsaAffectedVersionRepository);
        // Mocked, not the @Autowired repository: this run happens on a second thread, and
        // @DataJpaTest's rollback is bound to the JUnit test thread's transaction only — writes
        // made by a different thread would actually commit to the real database. The concurrency
        // guard under test (GhsaSyncService#running, an AtomicBoolean) lives on the service
        // instance, not in the repository, so mocking it doesn't weaken what this test verifies.
        GhsaSyncStateRepository mockSyncStateRepository = org.mockito.Mockito.mock(GhsaSyncStateRepository.class);
        GhsaSyncService blockingService = new GhsaSyncService(blockingBuilder.build(), upsertService, ghsaAdvisoryRepository,
                mockSyncStateRepository, ghsaSyncFailureRepository, GhsaRateLimiter.disabledForTesting(), 1, null);

        Thread firstRun = new Thread(blockingService::syncBaseline);
        firstRun.start();
        assertThat(firstCallStarted.await(5, TimeUnit.SECONDS)).isTrue();

        SyncResult second = blockingService.syncDelta();
        assertThat(second.alreadyRunning()).isTrue();

        releaseFirstCall.countDown();
        firstRun.join(5_000);
    }
}
