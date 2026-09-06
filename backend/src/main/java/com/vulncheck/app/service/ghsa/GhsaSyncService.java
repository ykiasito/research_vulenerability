package com.vulncheck.app.service.ghsa;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.GhsaSyncFailure;
import com.vulncheck.app.entity.GhsaSyncState;
import com.vulncheck.app.repository.GhsaAdvisoryRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.service.vuln.GhsaRateLimiter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URLConnection;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Syncs GHSA-reviewed advisories (github/advisory-database) into the local mirror — see {@code
 * docs/spec/ghsa-mirror-plan.md} §4 for the design sketch this follows. {@link #syncBaseline()}
 * downloads and walks {@code main}'s git tarball (§4-1); {@link #syncDelta()} uses the REST {@code
 * /advisories} endpoint purely as a change-detection signal, then fetches each changed advisory's
 * canonical OSV-schema JSON from {@code raw.githubusercontent.com} (§4-2/§3-1 decision A). Both
 * paths funnel every document through the exact same {@link GhsaDocumentUpsertService#upsertGhsaAdvisory}.
 *
 * <p><b>§5-3 (senior-reviewed decision): a rate limiter instance separate from the Spring-managed
 * {@link GhsaRateLimiter} bean</b> — sharing that bean with {@code GhsaVulnerabilitySource} (a
 * possible future *repo-scoped* consumer, per that class's own javadoc) would make {@code
 * ResearchJobProcessingService}'s per-job wait-time instrumentation (diffing {@code
 * cumulativeWaitMillis()} before/after a job) misattribute this background sync's sleep time to
 * whichever user job happens to be running concurrently. The public no-arg {@link
 * GhsaRateLimiter#GhsaRateLimiter()} constructor is used directly (not injected as a bean) so this
 * is guaranteed to be a distinct instance.
 *
 * <p><b>§5-2: the baseline tarball download is paced through the same {@link GhsaRateLimiter} as
 * delta's {@code /advisories} calls</b> — confirmed live 2026-08-27 that {@code GET
 * /repos/github/advisory-database/tarball/main} shares {@code api.github.com}'s single 60/hour
 * unauthenticated budget (its own response carries {@code x-ratelimit-remaining}, decremented by the
 * call) before redirecting to {@code codeload.github.com} for the actual archive bytes — {@code
 * raw.githubusercontent.com} and {@code codeload.github.com} both confirmed to NOT carry any
 * {@code x-ratelimit-*} headers at all (separate budget/CDN, not shared with {@code api.github.com}),
 * so neither the tarball body download nor delta's per-document {@code raw.githubusercontent.com}
 * fetches are paced through this limiter.
 *
 * <p><b>§6-3 finding (resolves a previously-"unverified" design question in the plan's favor):</b>
 * whether GHSA's REST list response represents withdrawn advisories at all turned out not to matter
 * for tombstone/withdrawal detection here — decision A means delta ALWAYS fetches the full OSV-
 * schema document for any {@code ghsa_id} the list flags as changed, and a withdrawn advisory's own
 * OSV JSON carries a {@code withdrawn} field the shared parser already reads (confirmed live against
 * a real withdrawn advisory, GHSA-vg9f-q4xh-62r4). So withdrawal is captured on the same cadence as
 * any other content change, through the ordinary per-document path — no separate handling needed.
 * Only a FULL removal from the reviewed set with no further {@code updated}/{@code modified} activity
 * (e.g. moved to unreviewed) would rely on baseline's tombstone pruning (§6-3) instead.
 *
 * <p><b>§5-5 merge-gate table (measured 2026-08-27, mirrored from {@code
 * docs/spec/ghsa-mirror-plan.md} §5-5, which is the authoritative copy — same manual-sync convention
 * as {@code SiemensCsafSyncService}'s own copy):</b>
 *
 * <table border="1">
 * <caption>GHSA (github-reviewed) sync — measured rate/volume</caption>
 * <tr><th>baseline doc count</th><th>pacing</th><th>baseline wall-clock</th><th>delta docs/day</th><th>cron</th><th>worst-case req/hour</th></tr>
 * <tr><td>34,768 (measured — full tarball download + walk, this implementation, 2026-08-27)</td>
 *     <td>{@link GhsaRateLimiter}'s 65s fixed interval applies to exactly ONE {@code api.github.com}
 *     call per baseline run (the tarball redirect resolution — {@code commits/main} adds a second,
 *     also paced); the tar.gz body itself streams unpaced from {@code codeload.github.com}</td>
 *     <td>measured: 123.1 MB compressed tarball, 16.7s download + 12.7s gzip-decompress-and-walk
 *     (unauthenticated, this environment's network — download time is network-dependent, not a
 *     portable constant) = ~30s of I/O before any DB writes; per-document upsert throughput
 *     (repeated INSERTs across 4 tables per advisory) was NOT measured against the full 34,768-
 *     document corpus in this implementation pass (would need a live run against a properly sized
 *     deployment DB) — labeled as an extrapolation gap deliberately, not rounded up to a false
 *     precision, same discipline {@code SiemensCsafSyncService}'s own table applies to its own
 *     unmeasured extrapolation</td>
 *     <td>measured 36 advisories changed in the trailing 24h, 2026-08-27 — consistent with the plan's
 *     §5-1 investigation-time estimate of 14-50/day, comfortably under one 100-per-page REST
 *     response</td>
 *     <td>daily at 04:00 UTC, offset from {@code CveOrgScheduledSync}'s 03:30 UTC and {@code
 *     SiemensCsafScheduledSync}'s 03:45 UTC slots</td>
 *     <td>60 (the fixed-interval ceiling shared with every other {@code api.github.com} call from
 *     this app; actual traffic is 1-7 calls/day outside a baseline run: 1 list page + up to 5
 *     raw.githubusercontent.com fetches which don't count against this budget at all)</td></tr>
 * </table>
 */
@Service
@Slf4j
public class GhsaSyncService {

    private static final String TARBALL_URL = "https://api.github.com/repos/github/advisory-database/tarball/main";
    private static final String COMMITS_MAIN_URL = "https://api.github.com/repos/github/advisory-database/commits/main";
    private static final String ADVISORIES_LIST_URL = "https://api.github.com/advisories";
    private static final String RAW_BASE_URL =
            "https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/";
    private static final Set<String> ALLOWED_HOSTS = Set.of("api.github.com", "raw.githubusercontent.com", "codeload.github.com");

    /** Measured live 2026-08-27 (this implementation, full tarball download+walk — see the class
     *  javadoc's §5-5 table): 34,768 github-reviewed documents. Supersedes the design plan's own
     *  slightly earlier §2-3 investigation figure (~28,529, from a Git Trees API count) — both are
     *  real measurements, just at different points against a continuously-growing corpus; this one
     *  is closer to actual deployment time and is what the 90%-completeness gate below is checked
     *  against. An instance field (not a constant) purely so the completeness-gate test doesn't need
     *  a 34,768-document fixture to exercise both sides of the gate. */
    static final int DEFAULT_EXPECTED_BASELINE_COUNT = 34_768;
    /** Plan §4-1 step 5 — below this fraction of {@link #expectedBaselineCount}, a baseline run is
     *  treated as a failed/partial download, never marked loaded (plan §0-1 principle 1). */
    private static final double COMPLETENESS_THRESHOLD = 0.90;
    /** Plan §5-4 (senior-reviewed: lowered from 20 to 5, to avoid starving {@code
     *  CveOrgScheduledSync} on Spring's default single-thread scheduling pool). */
    static final int MAX_PAGES_PER_DELTA_RUN = 5;
    /** Plan §6-1 "N=3 recommended". */
    static final int DEAD_LETTER_THRESHOLD = 3;

    private static final long MAX_JSON_DOCUMENT_BYTES = 5L * 1024 * 1024;
    private static final int MAX_REDIRECTS = 3;
    /** Finite, not {@code 0}/unbounded (backlog items 378/381) — {@link URLConnection#setReadTimeout}
     *  is a per-read (socket-idle) timeout, not a whole-download budget, so this doesn't cap how long
     *  a genuinely-streaming multi-hundred-MB tarball download can take; it only kills a connection
     *  that goes fully idle for this long, matching {@code CveOrgSyncService}'s own read timeout
     *  (see {@code CveOrgSyncService.DOWNLOAD_READ_TIMEOUT_MILLIS}) for consistency across the three
     *  sibling sync services. */
    private static final int DOWNLOAD_READ_TIMEOUT_MILLIS = 30_000;

    /** Real GHSA-ID shape — {@code GHSA-xxxx-xxxx-xxxx}, lowercase alphanumeric, four chars per
     *  segment. Used to reject a path-derived id (senior review item 3: {@link
     *  #derivedGhsaIdFromPath} trusts the tar entry filename verbatim, with no length/format check)
     *  before it's ever used as a {@code ghsa_sync_failures.ghsa_id} value — that column is {@code
     *  VARCHAR(20)}, and a malformed/unexpected filename could otherwise crash the whole run on a
     *  column-width violation instead of just being logged and skipped. */
    private static final Pattern GHSA_ID_PATTERN = Pattern.compile("^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$");

    private final RestClient ghsaSyncRestClient;
    private final GhsaDocumentUpsertService documentUpsertService;
    private final GhsaAdvisoryRepository ghsaAdvisoryRepository;
    private final GhsaSyncStateRepository ghsaSyncStateRepository;
    private final GhsaSyncFailureRepository ghsaSyncFailureRepository;
    private final GhsaRateLimiter ghsaRateLimiter;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final int expectedBaselineCount;
    /** Opens the tarball body stream given the URL {@link #resolveRedirectTarget} resolved — a seam
     *  purely for tests (real production traffic always goes through {@link #openStream}, a plain
     *  streaming {@link URLConnection} with a finite read timeout — {@code ghsaSyncRestClient}
     *  isn't used for this multi-hundred-MB body because its bounded-JSON-response client isn't
     *  suited to a streaming download this large, see {@link #openStream}'s own comment). {@code
     *  MockRestServiceServer} can't intercept a raw {@link URLConnection}, so the baseline-sync
     *  test supplies an in-memory tarball through this instead of hitting a real host. */
    private final java.util.function.Function<String, InputStream> tarballStreamOpener;

    /** In-process "sync already running" guard — same rationale/scope as {@code
     *  SiemensCsafSyncService#running}: matches this codebase's existing single-instance deployment
     *  assumption, so a manually-triggered baseline and the scheduled delta can never race each
     *  other. {@code ghsa_sync_state.sync_in_progress} is also written (for {@code /admin/ghsa}'s
     *  observability, plan §9-0) but is NOT itself the concurrency gate — a DB flag that gets stuck
     *  true after a crash would permanently wedge future syncs, which this avoids. */
    private final java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean(false);

    @Autowired
    public GhsaSyncService(
            RestClient ghsaSyncRestClient,
            GhsaDocumentUpsertService documentUpsertService,
            GhsaAdvisoryRepository ghsaAdvisoryRepository,
            GhsaSyncStateRepository ghsaSyncStateRepository,
            GhsaSyncFailureRepository ghsaSyncFailureRepository) {
        this(ghsaSyncRestClient, documentUpsertService, ghsaAdvisoryRepository, ghsaSyncStateRepository,
                ghsaSyncFailureRepository, new GhsaRateLimiter(), DEFAULT_EXPECTED_BASELINE_COUNT, null);
    }

    /** Test-only constructor — lets tests inject {@link GhsaRateLimiter#disabledForTesting()}, a
     *  smaller {@code expectedBaselineCount} (so the completeness gate is exercisable without a
     *  34,768-document fixture), and an in-memory {@code tarballStreamOpener}. */
    GhsaSyncService(
            RestClient ghsaSyncRestClient,
            GhsaDocumentUpsertService documentUpsertService,
            GhsaAdvisoryRepository ghsaAdvisoryRepository,
            GhsaSyncStateRepository ghsaSyncStateRepository,
            GhsaSyncFailureRepository ghsaSyncFailureRepository,
            GhsaRateLimiter ghsaRateLimiter,
            int expectedBaselineCount,
            java.util.function.Function<String, InputStream> tarballStreamOpener) {
        this.ghsaSyncRestClient = ghsaSyncRestClient;
        this.documentUpsertService = documentUpsertService;
        this.ghsaAdvisoryRepository = ghsaAdvisoryRepository;
        this.ghsaSyncStateRepository = ghsaSyncStateRepository;
        this.ghsaSyncFailureRepository = ghsaSyncFailureRepository;
        this.ghsaRateLimiter = ghsaRateLimiter;
        this.expectedBaselineCount = expectedBaselineCount;
        this.tarballStreamOpener = tarballStreamOpener != null ? tarballStreamOpener : this::openStreamUnchecked;
    }

    public record SyncResult(int upserted, int failed, boolean alreadyRunning) {
    }

    /** Full re-walk of the tarball, ignoring any existing cursor — manually triggered only (see
     *  {@code AdminController}), never {@code @Scheduled}, mirroring {@code
     *  CveOrgSyncService#syncBaseline}'s precedent. */
    public SyncResult syncBaseline() {
        if (!running.compareAndSet(false, true)) {
            log.warn("GHSA baseline sync skipped: another GHSA sync is already running");
            return new SyncResult(0, 0, true);
        }
        try {
            return doSyncBaseline();
        } finally {
            running.set(false);
        }
    }

    /** Only advisories changed since the last cursor — safe to run routinely. Deliberately a no-op
     *  until a baseline has completed at least once (plan §4-1/§4-2: delta assumes a populated
     *  mirror and a real cursor to filter from). */
    public SyncResult syncDelta() {
        if (!running.compareAndSet(false, true)) {
            log.warn("GHSA delta sync skipped: another GHSA sync is already running");
            return new SyncResult(0, 0, true);
        }
        try {
            return doSyncDelta();
        } finally {
            running.set(false);
        }
    }

    // ------------------------------------------------------------------ baseline ----------------

    private SyncResult doSyncBaseline() {
        // The DB server's own clock, not the app server's OffsetDateTime.now() — see
        // GhsaAdvisoryRepository#currentDatabaseTime's javadoc for why mixing clocks here is a real
        // (measured) correctness bug, not just theoretical.
        OffsetDateTime runStartedAt = ghsaAdvisoryRepository.currentDatabaseTime().atOffset(java.time.ZoneOffset.UTC);
        GhsaSyncState state = loadState();
        state.setSyncInProgress(true);
        ghsaSyncStateRepository.save(state);

        int upserted = 0;
        int failed = 0;
        // Senior review item 2: everything from here down used to be un-guarded — an unchecked
        // exception (e.g. readBounded's IllegalStateException-wrapped IOException, which is NOT an
        // IOException itself and so isn't caught by the narrower catch below) would propagate straight
        // out of this method, past state.setSyncInProgress(true) above, and leave sync_in_progress
        // stuck true forever (wedging every future sync). This outer catch is the last line of
        // cleanup, regardless of what kind of unchecked exception surfaces.
        try {
            String resolvedCommitSha = resolveMainCommitSha();

            if (!paceOrAbort()) {
                return failSync(state, "Interrupted before the baseline tarball request could be made", 0, 0);
            }
            RedirectOutcome redirectOutcome = resolveRedirectTarget(TARBALL_URL);
            if (redirectOutcome.status() != RedirectResolution.OK) {
                return failSync(state, redirectFailureMessage(redirectOutcome), 0, 0);
            }
            String tarballUrl = redirectOutcome.url();

            OffsetDateTime maxUpdatedAt = null;
            String observedShortSha = null;
            try (InputStream raw = tarballStreamOpener.apply(tarballUrl);
                    GzipCompressorInputStream gzip = new GzipCompressorInputStream(raw);
                    TarArchiveInputStream tar = new TarArchiveInputStream(gzip)) {
                TarArchiveEntry entry;
                while ((entry = tar.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        continue;
                    }
                    String name = entry.getName();
                    int firstSlash = name.indexOf('/');
                    if (firstSlash < 0) {
                        continue;
                    }
                    if (observedShortSha == null) {
                        String topDir = name.substring(0, firstSlash);
                        int lastDash = topDir.lastIndexOf('-');
                        if (lastDash >= 0) {
                            observedShortSha = topDir.substring(lastDash + 1);
                        }
                    }
                    String relativePath = name.substring(firstSlash + 1);
                    // advisories/unreviewed/** is skipped entirely (plan §0(d)) — never even parsed.
                    if (!relativePath.startsWith("advisories/github-reviewed/") || !relativePath.endsWith(".json")) {
                        continue;
                    }

                    byte[] bytes = readBounded(tar, MAX_JSON_DOCUMENT_BYTES);
                    String pathDerivedGhsaId = derivedGhsaIdFromPath(relativePath);
                    UpsertOutcome outcome = parseAndUpsert(bytes, pathDerivedGhsaId);
                    if (outcome.ghsaId() != null) {
                        upserted++;
                        clearFailure(outcome.ghsaId());
                        if (outcome.updatedAt() != null && (maxUpdatedAt == null || outcome.updatedAt().isAfter(maxUpdatedAt))) {
                            maxUpdatedAt = outcome.updatedAt();
                        }
                    } else {
                        failed++;
                        recordFailure(pathDerivedGhsaId, outcome.error());
                    }
                    if (upserted > 0 && upserted % 5000 == 0) {
                        log.info("GHSA baseline sync progress: {} upserted, {} failed", upserted, failed);
                    }
                }
            } catch (IOException | java.io.UncheckedIOException e) {
                log.error("GHSA baseline sync failed after upserting {} records", upserted, e);
                return failSync(state, "Tarball read failed: " + e.getMessage(), upserted, failed);
            }

            if (upserted < expectedBaselineCount * COMPLETENESS_THRESHOLD) {
                String message = "Baseline incomplete: only " + upserted + " of an expected ~" + expectedBaselineCount
                        + " (" + Math.round(COMPLETENESS_THRESHOLD * 100) + "% threshold) — not marking baseline_loaded (plan §4-1 step 5)";
                log.error("GHSA baseline sync aborted: {}", message);
                return failSync(state, message, upserted, failed);
            }

            if (observedShortSha != null && resolvedCommitSha != null && !resolvedCommitSha.startsWith(observedShortSha)) {
                log.warn("GHSA baseline sync: tarball's own short SHA ({}) does not prefix-match the resolved "
                        + "main branch commit ({}) — proceeding anyway (plan §6: this is a best-effort cross-check, "
                        + "not a hard integrity gate, since GHSA has no per-document signature)", observedShortSha, resolvedCommitSha);
            }

            // Senior review item 1: a document that FAILED to upsert this run keeps its old
            // last_synced_at (older than runStartedAt) and would otherwise look indistinguishable from
            // a genuinely-removed advisory to the tombstone-prune query below — silently deleting a
            // still-published advisory (plus its packages/ranges/versions via CASCADE) just because it
            // hit a transient parse/upsert error this run. Pruning only runs when this run had zero
            // failures — simpler and strictly safer than trying to enumerate/exclude just the failed
            // ids, per the senior review's own preference.
            int pruned = 0;
            if (failed == 0) {
                pruned = ghsaAdvisoryRepository.deleteNotSyncedSince(runStartedAt);
                log.info("GHSA baseline sync: pruned {} tombstoned advisories no longer in github-reviewed (plan §6-3)", pruned);
            } else {
                log.warn("GHSA baseline sync: skipping tombstone pruning — {} document(s) failed to upsert this run, "
                        + "so an untouched last_synced_at can't be trusted to mean 'genuinely removed from "
                        + "github-reviewed' rather than 'failed to sync this run' (senior review item 1)", failed);
            }

            state.setBaselineLoaded(true);
            state.setBaselineCommitSha(resolvedCommitSha);
            if (maxUpdatedAt != null) {
                state.setLastCursor(maxUpdatedAt);
            }
            state.setSyncInProgress(false);
            state.setLastSyncedAt(OffsetDateTime.now());
            state.setLastSyncError(null);
            ghsaSyncStateRepository.save(state);

            log.info("GHSA baseline sync complete: {} upserted, {} failed, {} pruned, cursor={}", upserted, failed, pruned, maxUpdatedAt);
            return new SyncResult(upserted, failed, false);
        } catch (RuntimeException e) {
            log.error("GHSA baseline sync failed with an unexpected error after upserting {} records", upserted, e);
            return failSync(state, "Unexpected error: " + e.getMessage(), upserted, failed);
        }
    }

    /** @param upserted/{@code failed} the real per-document counts from whatever work THIS run did
     *          manage to complete before hitting the failure/gate — plan §0-1 principle 1 only
     *          requires that the run's overall {@code baseline_loaded}/{@code lastCursor} STATE not
     *          flip to a value implying success; the individual documents that did successfully
     *          upsert are real work, not to be hidden from the caller by collapsing the result to a
     *          false 0/0. Shared cleanup for both {@link #doSyncBaseline} and {@link #doSyncDelta} —
     *          always clears {@code sync_in_progress} and records {@code last_sync_error}, regardless
     *          of which kind of failure got here (senior review item 2). */
    private SyncResult failSync(GhsaSyncState state, String message, int upserted, int failed) {
        state.setSyncInProgress(false);
        state.setLastSyncError(message);
        state.setLastSyncedAt(OffsetDateTime.now());
        ghsaSyncStateRepository.save(state);
        return new SyncResult(upserted, failed, false);
    }

    private String derivedGhsaIdFromPath(String relativePath) {
        // advisories/github-reviewed/<YYYY>/<MM>/<GHSA-ID>/<GHSA-ID>.json
        int lastSlash = relativePath.lastIndexOf('/');
        String fileName = lastSlash >= 0 ? relativePath.substring(lastSlash + 1) : relativePath;
        return fileName.endsWith(".json") ? fileName.substring(0, fileName.length() - ".json".length()) : fileName;
    }

    // -------------------------------------------------------------------- delta -----------------

    private SyncResult doSyncDelta() {
        GhsaSyncState state = loadState();
        if (!state.isBaselineLoaded() || state.getLastCursor() == null) {
            log.warn("GHSA delta sync skipped: baseline has not completed yet");
            return new SyncResult(0, 0, false);
        }
        state.setSyncInProgress(true);
        ghsaSyncStateRepository.save(state);

        OffsetDateTime cursor = state.getLastCursor();
        OffsetDateTime advancedCursor = cursor;
        int upserted = 0;
        int failed = 0;
        boolean sawFailure = false;
        boolean interrupted = false;
        // Senior review item 5: a null fetchAdvisoriesPage result (403/rate-limited/5xx/malformed
        // JSON) used to just `break` with neither sawFailure nor interrupted set — the error-recording
        // logic below would then fall through to the "else" branch and write last_sync_error = null,
        // making /admin/ghsa look like a clean run for a sync that actually aborted having done
        // nothing useful. This flag distinguishes that case so a meaningful error gets recorded.
        boolean listFetchFailed = false;

        // Senior review item 2: see doSyncBaseline's matching try/catch for why this needs to be
        // broad, not just the exceptions the happy path expects — an unchecked exception anywhere
        // below must still clear sync_in_progress, or every future sync stays wedged.
        try {
            String nextUrl = ADVISORIES_LIST_URL + "?type=reviewed&per_page=100&sort=updated&direction=asc"
                    + "&modified=" + java.net.URLEncoder.encode(">=" + cursor, java.nio.charset.StandardCharsets.UTF_8);
            int pagesProcessed = 0;
            while (nextUrl != null && pagesProcessed < MAX_PAGES_PER_DELTA_RUN) {
                if (!paceOrAbort()) {
                    interrupted = true;
                    break;
                }
                PageFetchOutcome page = fetchAdvisoriesPage(nextUrl);
                if (page == null) {
                    log.error("GHSA delta sync: aborting — could not fetch advisories list page {}", nextUrl);
                    listFetchFailed = true;
                    break;
                }
                pagesProcessed++;

                List<AdvisorySummary> entries = new ArrayList<>(page.entries());
                entries.sort(Comparator.comparing(AdvisorySummary::updatedAt)); // ascending — plan §6

                for (AdvisorySummary summary : entries) {
                    UpsertOutcome outcome = fetchAndUpsertOne(summary);
                    if (outcome.ghsaId() != null) {
                        upserted++;
                        clearFailure(outcome.ghsaId());
                        if (!sawFailure) {
                            advancedCursor = summary.updatedAt();
                            persistCursor(state, advancedCursor);
                        }
                    } else {
                        failed++;
                        boolean deadLettered = recordFailureAndCheckDeadLetter(summary.ghsaId(), outcome.error());
                        if (deadLettered) {
                            log.warn("GHSA delta sync: {} dead-lettered after {} consecutive failures — skipping and "
                                            + "advancing the cursor past it (plan §6-1)", summary.ghsaId(), DEAD_LETTER_THRESHOLD);
                            if (!sawFailure) {
                                advancedCursor = summary.updatedAt();
                                persistCursor(state, advancedCursor);
                            }
                        } else if (!sawFailure) {
                            sawFailure = true; // block further cursor advancement this run, but keep processing
                        }
                    }
                }
                nextUrl = page.nextUrl();
            }

            state.setSyncInProgress(false);
            state.setLastSyncedAt(OffsetDateTime.now());
            if (interrupted) {
                state.setLastSyncError("Interrupted mid-run — cursor left at last successfully committed position");
            } else if (listFetchFailed) {
                state.setLastSyncError("advisories list page fetch failed — this run made no further progress "
                        + "past the last successfully committed cursor position");
            } else if (sawFailure) {
                state.setLastSyncError("One or more documents failed this run — cursor stopped before the first failure "
                        + "(retried next run unless dead-lettered)");
            } else {
                state.setLastSyncError(null);
            }
            ghsaSyncStateRepository.save(state);

            log.info("GHSA delta sync complete: {} upserted, {} failed, cursor={}", upserted, failed, advancedCursor);
            return new SyncResult(upserted, failed, false);
        } catch (RuntimeException e) {
            log.error("GHSA delta sync failed with an unexpected error after upserting {} records", upserted, e);
            return failSync(state, "Unexpected error: " + e.getMessage(), upserted, failed);
        }
    }

    private void persistCursor(GhsaSyncState state, OffsetDateTime cursor) {
        state.setLastCursor(cursor);
        ghsaSyncStateRepository.save(state);
    }

    private UpsertOutcome fetchAndUpsertOne(AdvisorySummary summary) {
        String yearMonthPath = "%04d/%02d/".formatted(summary.publishedAt().getYear(), summary.publishedAt().getMonthValue());
        String url = RAW_BASE_URL + yearMonthPath + summary.ghsaId() + "/" + summary.ghsaId() + ".json";
        FetchOutcome fetch = fetchBounded(url, MAX_JSON_DOCUMENT_BYTES, MAX_REDIRECTS);
        if (fetch.status() != FetchStatus.OK) {
            return UpsertOutcome.failure("Failed to fetch " + url + " (" + fetch.status() + ")");
        }
        return parseAndUpsert(fetch.body(), summary.ghsaId());
    }

    private record AdvisorySummary(String ghsaId, OffsetDateTime publishedAt, OffsetDateTime updatedAt) {
    }

    private record PageFetchOutcome(List<AdvisorySummary> entries, String nextUrl) {
    }

    private static final Pattern LINK_NEXT_PATTERN = Pattern.compile("<([^>]+)>;\\s*rel=\"next\"");

    private PageFetchOutcome fetchAdvisoriesPage(String url) {
        // Senior review item 4 (SSRF): `url` here is either the fixed, hardcoded ADVISORIES_LIST_URL
        // (safe by construction) OR a `nextUrl` extracted from a PREVIOUS response's own `Link:
        // rel="next"` header — unlike every other outbound fetch in this class (fetchBounded,
        // resolveRedirectTarget, openStream), this path used to skip validatedUri(...) entirely and
        // hand a server-supplied URL straight to the HTTP client. A malicious/MITM'd response could
        // otherwise redirect this pagination loop to an arbitrary host, a non-https URL, or an
        // internal address. An invalid url is treated as "no next page" — this only ever happens with
        // a nextUrl carried over from the previous page, never the first call of a run.
        URI uri = validatedUri(url);
        if (uri == null) {
            log.warn("GHSA delta sync: rejecting pagination URL {} — not https or not an allowlisted host; "
                    + "stopping pagination for this run rather than following it", url);
            return new PageFetchOutcome(List.of(), null);
        }
        try {
            var response = ghsaSyncRestClient.get().uri(uri)
                    .header("Accept", "application/vnd.github+json")
                    .header("X-GitHub-Api-Version", "2022-11-28")
                    .retrieve()
                    .toEntity(JsonNode.class);
            JsonNode body = response.getBody();
            if (body == null || !body.isArray()) {
                return new PageFetchOutcome(List.of(), null);
            }
            List<AdvisorySummary> entries = new ArrayList<>();
            for (JsonNode advisory : body) {
                String ghsaId = textOrNull(advisory.path("ghsa_id"));
                OffsetDateTime publishedAt = parseTimestamp(textOrNull(advisory.path("published_at")));
                OffsetDateTime updatedAt = parseTimestamp(textOrNull(advisory.path("updated_at")));
                if (ghsaId == null || publishedAt == null || updatedAt == null) {
                    continue;
                }
                entries.add(new AdvisorySummary(ghsaId, publishedAt, updatedAt));
            }
            String linkHeader = response.getHeaders().getFirst(HttpHeaders.LINK);
            String nextUrl = null;
            if (linkHeader != null) {
                Matcher matcher = LINK_NEXT_PATTERN.matcher(linkHeader);
                if (matcher.find()) {
                    nextUrl = matcher.group(1);
                }
            }
            return new PageFetchOutcome(entries, nextUrl);
        } catch (Exception e) {
            log.error("GHSA delta sync: failed to fetch/parse advisories list page {}", url, e);
            return null;
        }
    }

    // ---------------------------------------------------------------- shared parse ---------------

    private record UpsertOutcome(String ghsaId, OffsetDateTime updatedAt, String error) {
        static UpsertOutcome success(String ghsaId, OffsetDateTime updatedAt) {
            return new UpsertOutcome(ghsaId, updatedAt, null);
        }
        static UpsertOutcome failure(String error) {
            return new UpsertOutcome(null, null, error);
        }
    }

    private UpsertOutcome parseAndUpsert(byte[] bytes, String fallbackGhsaIdForLogging) {
        if (bytes == null) {
            return UpsertOutcome.failure("document too large or unreadable");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(bytes);
        } catch (Exception e) {
            log.debug("Skipping unparseable GHSA document {}", fallbackGhsaIdForLogging, e);
            return UpsertOutcome.failure("JSON parse error: " + e.getMessage());
        }
        try {
            String ghsaId = documentUpsertService.upsertGhsaAdvisory(root);
            if (ghsaId == null) {
                return UpsertOutcome.failure("missing required field (id/modified)");
            }
            OffsetDateTime updatedAt = parseTimestamp(textOrNull(root.path("modified")));
            return UpsertOutcome.success(ghsaId, updatedAt);
        } catch (Exception e) {
            log.warn("Skipping GHSA document {} — failed to upsert", fallbackGhsaIdForLogging, e);
            return UpsertOutcome.failure("upsert error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------- dead-letter bookkeeping ---------

    private void clearFailure(String ghsaId) {
        // Senior review item 13: deleteById internally does findById(...).ifPresent(this::delete) — an
        // unnecessary SELECT before every DELETE, on a table that's normally empty. Baseline sync calls
        // this once per successfully-upserted document (~34,768 times/run), so that's ~34,768 wasted
        // SELECTs against ghsa_sync_failures every run. deleteByGhsaId is a direct DELETE.
        ghsaSyncFailureRepository.deleteByGhsaId(ghsaId);
    }

    private void recordFailure(String ghsaId, String error) {
        recordFailureAndCheckDeadLetter(ghsaId, error);
    }

    /** @return true if this failure just pushed {@code ghsaId} to (or past) {@link
     *          #DEAD_LETTER_THRESHOLD} consecutive failures. */
    private boolean recordFailureAndCheckDeadLetter(String ghsaId, String error) {
        if (ghsaId == null) {
            return false;
        }
        // Senior review item 3: derivedGhsaIdFromPath trusts the tar entry filename verbatim, with no
        // length/format validation — a malformed/unexpected filename could be longer than 20 chars and
        // violate ghsa_sync_failures.ghsa_id's VARCHAR(20) width, crashing the whole run right when it's
        // trying to record a failure. Log-only and skip the dead-letter ledger write for anything that
        // doesn't look like a real GHSA id, rather than attempting to persist it.
        if (!GHSA_ID_PATTERN.matcher(ghsaId).matches()) {
            log.warn("GHSA sync: not recording a dead-letter entry for '{}' — doesn't look like a real GHSA id "
                    + "(error: {})", ghsaId, error);
            return false;
        }
        GhsaSyncFailure failure = ghsaSyncFailureRepository.findById(ghsaId).orElseGet(() -> new GhsaSyncFailure(ghsaId));
        failure.setConsecutiveFailures(failure.getConsecutiveFailures() + 1);
        failure.setLastError(error);
        failure.setLastAttemptedAt(OffsetDateTime.now());
        boolean deadLettered = failure.getConsecutiveFailures() >= DEAD_LETTER_THRESHOLD;
        if (deadLettered && failure.getDeadLetteredAt() == null) {
            failure.setDeadLetteredAt(OffsetDateTime.now());
        }
        ghsaSyncFailureRepository.save(failure);
        return deadLettered;
    }

    // --------------------------------------------------------------- GitHub API calls ------------

    private GhsaSyncState loadState() {
        return ghsaSyncStateRepository.findById((short) 1).orElseGet(GhsaSyncState::new);
    }

    private String resolveMainCommitSha() {
        if (!paceOrAbort()) {
            return null;
        }
        FetchOutcome outcome = fetchBounded(COMMITS_MAIN_URL, MAX_JSON_DOCUMENT_BYTES, MAX_REDIRECTS);
        if (outcome.status() != FetchStatus.OK) {
            log.warn("GHSA sync: could not resolve main branch commit SHA ({})", outcome.status());
            return null;
        }
        try {
            return textOrNull(objectMapper.readTree(outcome.body()).path("sha"));
        } catch (Exception e) {
            log.warn("GHSA sync: malformed response resolving main branch commit SHA", e);
            return null;
        }
    }

    private boolean paceOrAbort() {
        ghsaRateLimiter.awaitTurn();
        if (Thread.currentThread().isInterrupted()) {
            log.warn("GHSA sync interrupted during rate-limiter wait — aborting without further progress this run "
                    + "(plan §4-2: GhsaRateLimiter#awaitTurn only catches InterruptedException and returns early, "
                    + "it doesn't itself re-throw, so this check is required after every call)");
            return false;
        }
        return true;
    }

    /** Resolves {@link #TARBALL_URL}'s redirect to its final download URL — a single HEAD-shaped
     *  hop (confirmed live 2026-08-27: {@code api.github.com}'s tarball endpoint always 302s exactly
     *  once, to {@code codeload.github.com}), re-validating the target host against the allowlist
     *  (same SSRF-hardening spirit as {@code SiemensCsafSyncService}). Deliberately reads only the
     *  status/headers, never {@code response.getBody()} — the redirect target is the multi-hundred-
     *  MB tarball itself, which {@link #openStream} downloads separately by streaming, not buffering
     *  a second confirmatory fetch here. If the response is already 2xx (no redirect at all), the
     *  original URL is returned as-is — {@link #openStream}'s own attempt is what would surface a
     *  real fetch problem, not this resolution step. */
    /** Senior review follow-up: {@link #resolveRedirectTarget} used to collapse every one of these
     *  distinct failure modes into a bare {@code null}, so {@code ghsa_sync_state.last_sync_error}
     *  couldn't distinguish "GitHub rate-limited us" from "the redirect Location header was missing"
     *  from "transport error" — all recorded as the same uninformative
     *  "Could not resolve the baseline tarball download URL" string. This return type lets the
     *  caller ({@link #doSyncBaseline}) build an actionable message per failure mode instead. */
    private enum RedirectResolution {
        OK, REJECTED_SCHEME_OR_HOST, MISSING_LOCATION_HEADER, REDIRECT_TARGET_REJECTED, RATE_LIMITED, HTTP_ERROR, TRANSPORT_ERROR
    }

    private record RedirectOutcome(RedirectResolution status, String url, int httpStatus) {
        static RedirectOutcome ok(String url) {
            return new RedirectOutcome(RedirectResolution.OK, url, 0);
        }
        static RedirectOutcome of(RedirectResolution status) {
            return new RedirectOutcome(status, null, 0);
        }
        static RedirectOutcome ofHttp(RedirectResolution status, int httpStatus) {
            return new RedirectOutcome(status, null, httpStatus);
        }
    }

    private RedirectOutcome resolveRedirectTarget(String url) {
        URI uri = validatedUri(url);
        if (uri == null) {
            return RedirectOutcome.of(RedirectResolution.REJECTED_SCHEME_OR_HOST);
        }
        try {
            return ghsaSyncRestClient.get().uri(uri).exchange((request, response) -> {
                HttpStatusCode status = response.getStatusCode();
                if (status.is3xxRedirection()) {
                    String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                    if (location == null) {
                        return RedirectOutcome.of(RedirectResolution.MISSING_LOCATION_HEADER);
                    }
                    URI target = uri.resolve(location);
                    return validatedUri(target.toString()) != null
                            ? RedirectOutcome.ok(target.toString())
                            : RedirectOutcome.of(RedirectResolution.REDIRECT_TARGET_REJECTED);
                }
                if (status.is2xxSuccessful()) {
                    return RedirectOutcome.ok(uri.toString());
                }
                // Senior review item 12(b): fetchBounded already maps 403/429 to a distinct
                // RATE_LIMITED status with an actionable message — this redirect-resolution path used
                // to fall through to the generic "unexpected HTTP" branch below, which reads as a
                // random/unexplained failure rather than the exhausted-budget signal it actually is.
                if (status.value() == 429 || status.value() == 403) {
                    log.error("GHSA sync: rate-limited (HTTP {}) resolving {} — treating as a block signal, not a "
                            + "transient error", status.value(), url);
                    return RedirectOutcome.ofHttp(RedirectResolution.RATE_LIMITED, status.value());
                }
                log.error("GHSA sync: unexpected HTTP {} resolving {}", status.value(), url);
                return RedirectOutcome.ofHttp(RedirectResolution.HTTP_ERROR, status.value());
            });
        } catch (Exception e) {
            log.error("GHSA sync: transport error resolving {}", url, e);
            return RedirectOutcome.of(RedirectResolution.TRANSPORT_ERROR);
        }
    }

    /** Builds the {@code ghsa_sync_state.last_sync_error} message for a non-OK {@link
     *  RedirectOutcome} from {@link #resolveRedirectTarget} — one distinct, actionable message per
     *  failure mode (senior review follow-up), rather than the single generic string this used to
     *  collapse to. */
    private String redirectFailureMessage(RedirectOutcome outcome) {
        return switch (outcome.status()) {
            case REJECTED_SCHEME_OR_HOST ->
                    "Could not resolve the baseline tarball download URL: the request URL was not https or not an allowlisted host";
            case MISSING_LOCATION_HEADER ->
                    "Could not resolve the baseline tarball download URL: GitHub's redirect response had no Location header";
            case REDIRECT_TARGET_REJECTED ->
                    "Could not resolve the baseline tarball download URL: the redirect target was not https or not an allowlisted host";
            case RATE_LIMITED ->
                    "Could not resolve the baseline tarball download URL: rate-limited by GitHub (HTTP " + outcome.httpStatus() + ")";
            case HTTP_ERROR ->
                    "Could not resolve the baseline tarball download URL: unexpected HTTP " + outcome.httpStatus();
            case TRANSPORT_ERROR ->
                    "Could not resolve the baseline tarball download URL: transport error contacting GitHub";
            case OK -> throw new IllegalStateException("redirectFailureMessage called with a successful outcome");
        };
    }

    private InputStream openStream(String url) throws IOException {
        URI uri = validatedUri(url);
        if (uri == null) {
            throw new IOException("Rejected non-allowlisted URL: " + url);
        }
        // Plain URLConnection, not ghsaSyncRestClient — same rationale as CveOrgSyncService#download:
        // this app's bounded-JSON-response clients aren't suited to a multi-hundred-MB streaming
        // body. The read timeout below is finite (backlog items 378/381 — see
        // DOWNLOAD_READ_TIMEOUT_MILLIS's javadoc for why that doesn't cap a streaming download's
        // total size/duration); it used to be 0/unbounded, which risked hanging this sync's sole
        // worker thread forever on a connection that stalls without cleanly closing, a realistic
        // failure mode on a closed network.
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(DOWNLOAD_READ_TIMEOUT_MILLIS);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (ghsa sync)");
        return connection.getInputStream();
    }

    /** {@link #openStream} adapted to {@link java.util.function.Function}'s unchecked signature —
     *  the default {@link #tarballStreamOpener}. */
    private InputStream openStreamUnchecked(String url) {
        try {
            return openStream(url);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    // ---------------------------------------------------------- bounded fetch (JSON only) ---------

    private enum FetchStatus {
        OK, REJECTED_SCHEME_OR_HOST, TOO_MANY_REDIRECTS, TOO_LARGE, RATE_LIMITED, HTTP_ERROR, TRANSPORT_ERROR, INTERRUPTED
    }

    private record FetchOutcome(FetchStatus status, byte[] body) {
        static FetchOutcome ok(byte[] body) {
            return new FetchOutcome(FetchStatus.OK, body);
        }
        static FetchOutcome of(FetchStatus status) {
            return new FetchOutcome(status, null);
        }
    }

    private FetchOutcome fetchBounded(String url, long maxBytes, int redirectsRemaining) {
        URI uri = validatedUri(url);
        if (uri == null) {
            return FetchOutcome.of(FetchStatus.REJECTED_SCHEME_OR_HOST);
        }
        try {
            return ghsaSyncRestClient.get().uri(uri).exchange((request, response) -> {
                HttpStatusCode status = response.getStatusCode();
                if (status.is3xxRedirection()) {
                    String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                    if (location == null) {
                        return FetchOutcome.of(FetchStatus.HTTP_ERROR);
                    }
                    if (redirectsRemaining <= 0) {
                        return FetchOutcome.of(FetchStatus.TOO_MANY_REDIRECTS);
                    }
                    // Senior review item 12(a): every other budget-consuming call in this class paces
                    // through the rate limiter first — a same-host redirect hop was spending an unpaced
                    // budget unit (bounded at MAX_REDIRECTS=3 hops, so low risk, but inconsistent).
                    if (!paceOrAbort()) {
                        return FetchOutcome.of(FetchStatus.INTERRUPTED);
                    }
                    return fetchBounded(uri.resolve(location).toString(), maxBytes, redirectsRemaining - 1);
                }
                if (status.value() == 429 || status.value() == 403) {
                    return FetchOutcome.of(FetchStatus.RATE_LIMITED);
                }
                if (!status.is2xxSuccessful()) {
                    return FetchOutcome.of(FetchStatus.HTTP_ERROR);
                }
                byte[] body = readBounded(response.getBody(), maxBytes);
                return body == null ? FetchOutcome.of(FetchStatus.TOO_LARGE) : FetchOutcome.ok(body);
            });
        } catch (Exception e) {
            log.warn("GHSA sync: transport error fetching {}", url, e);
            return FetchOutcome.of(FetchStatus.TRANSPORT_ERROR);
        }
    }

    private URI validatedUri(String url) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            return null;
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || !ALLOWED_HOSTS.contains(uri.getHost())) {
            log.warn("GHSA sync: rejecting fetch of {} — not https or not an allowlisted host", url);
            return null;
        }
        return uri;
    }

    /** Reads at most {@code maxBytes} — returns null (caller treats as "too large") past that,
     *  rather than trusting a possibly-absent/lying {@code Content-Length}. */
    private byte[] readBounded(InputStream in, long maxBytes) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            long total = 0;
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > maxBytes) {
                    return null;
                }
                buffer.write(chunk, 0, read);
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed reading response body", e);
        }
    }

    private OffsetDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** Senior review item 8: {@code node.asText(default)} correctly returns {@code default} for an
     *  ABSENT field ({@link com.fasterxml.jackson.databind.node.MissingNode}), but for an explicit
     *  JSON {@code null} value ({@link com.fasterxml.jackson.databind.node.NullNode}) it returns the
     *  literal 4-character string {@code "null"} instead — so {@code "ghsa_id": null} in a real
     *  response would persist/compare against the string {@code "null"}, not actually be treated as
     *  missing. This only returns a real value for an actual textual node, {@code null} for anything
     *  else (absent, explicit JSON null, wrong type). */
    private static String textOrNull(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }
}
