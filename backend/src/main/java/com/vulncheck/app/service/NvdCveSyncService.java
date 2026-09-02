package com.vulncheck.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.entity.NvdCveSyncChunk;
import com.vulncheck.app.entity.NvdCveSyncChunkStatus;
import com.vulncheck.app.entity.NvdCveSyncState;
import com.vulncheck.app.repository.NvdCveCpeMatchRepository;
import com.vulncheck.app.repository.NvdCveRecordRepository;
import com.vulncheck.app.repository.NvdCveSyncChunkRepository;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.math.BigDecimal;
import java.net.URI;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Mirrors the NVD CVE API (services.nvd.nist.gov/rest/json/cves/2.0) into {@code nvd_cve_records}/
 * {@code nvd_cve_cpe_match} — closed-mode backlog item 202, design in {@code
 * docs/spec/closed-mode-plan.md} §4-2. A sibling of {@link NvdCpeSyncService}, not an extension of
 * it: the target tables differ, and unlike {@link NvdCpeSyncService#syncAllAndRelease} (which is
 * stateless in-memory pagination that restarts from scratch on any interruption), this sync must
 * survive a process restart or an EC2 scheduled-uptime window closing mid-run — a full backfill is
 * ~3.5-4 hours (§4-2-3), far longer than either of those can be relied on to stay up for.
 *
 * <p><b>Chunked, resumable design</b> (§4-2-4): the full corpus is partitioned into non-overlapping
 * 120-day {@code lastModified} windows (NVD's documented max range for {@code lastModStartDate}/
 * {@code lastModEndDate}), persisted as {@link NvdCveSyncChunk} rows. Each chunk additionally
 * tracks {@code next_start_index}, committed after every single NVD API page (2,000 records) — so a
 * mid-run crash loses at most one page of progress, not a whole (potentially tens-of-thousands-of-
 * record) window. A window whose first page reports more results than {@link #SPLIT_THRESHOLD}
 * gets adaptively split into two half-range child chunks rather than paged through in one very long
 * run (see {@link #splitChunk}) — this recurses naturally, since a freshly-inserted child chunk goes
 * through the exact same first-page split check the next time it's picked up.
 *
 * <p><b>Same executor for backfill and delta</b> (§4-2-4): {@link #runBackfillTickAndRelease}
 * processes the persistent chunk queue seeded once from [1999-01-01, now); {@link
 * #runDeltaTickAndRelease} (only meaningful once the baseline is done — see {@code
 * nvd_cve_sync_state.baseline_completed}) enqueues a single ad hoc chunk covering {@code
 * [last_delta_synced_at - safety margin, now)} and pages it through the identical {@link
 * #processChunkStep} logic. Neither is wired to a scheduler by this class itself — {@code
 * NvdCveBackfillScheduledRunner} drives the backfill side; nothing yet drives the delta side (out
 * of scope for backlog item 202's (2)-(5), which covers mirror infrastructure only, not the A/B
 * verification + cutover that would make delta sync operationally relevant).
 *
 * <p><b>Run budget, counted in attempts</b>: both entry points take a {@link RunBudget} (request
 * count + wall-clock duration) and stop cleanly once either is exhausted, leaving any unfinished
 * chunk {@code IN_PROGRESS}/{@code FAILED} for the next run to resume — see {@link BudgetTracker}.
 * Deliberately counted per fetch *attempt*, not per success: counting only successes would let a
 * single chunk stuck in a 503-retry loop consume unlimited wall-clock time (and rate-limiter slots)
 * within one run, starving every chunk after it in {@code window_start} order.
 *
 * <p><b>Existing-asset reuse</b> (§4-2-5): {@link NvdRateLimiter} and the {@code nvdSyncRestClient}
 * bean are reused unchanged from {@link NvdCpeSyncService}'s own dependencies — not {@code
 * externalApiRestClient} (10s read timeout, too short for a 2,000-record page; also the bean
 * closed-mode denies at its network-egress layer). {@code UserApiKeyService#getAdminNvdApiKey()} is
 * a legitimate optional caller-side optimization, never a precondition — every code path here works
 * unkeyed (see §4-2-2's "NVD unkeyed is not 10x slower" correction).
 *
 * <p><b>Never persist a raw API response or request URL</b> (§4-2-4 security note, required):
 * {@link NvdCveSyncChunk#getLastError} stores only an HTTP status code (when the failure was an
 * HTTP error response) plus the failing exception's simple class name — see {@link
 * #describeError}. Exception messages are deliberately never stored verbatim: several of Spring's
 * own {@code RestClientException} subclasses embed the request URL in {@code getMessage()}, and a
 * future keyed run must not have any path, however indirect, that could end up writing an {@code
 * apiKey}-bearing URL or response body into this column (this repo has an actual incident history
 * of a real credential ending up in a persisted column meant for something else).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NvdCveSyncService {

    private static final String NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    /** NVD's documented maximum for the CVE 2.0 endpoint's {@code resultsPerPage} — confirmed via
     *  live calibration 2026-09-02 (see closed-mode backlog item 202), distinct from the CPE
     *  endpoint's 10,000 (see {@link NvdCpeSyncService#RESULTS_PER_PAGE}). */
    private static final int RESULTS_PER_PAGE = 2000;
    /** NVD's documented maximum span for {@code lastModStartDate}/{@code lastModEndDate}. */
    private static final int WINDOW_DAYS = 120;
    /** A window whose first page reports more results than this gets adaptively split (§4-2-4's
     *  "例20,000" — ~10 pages) rather than paged through in one long run. */
    private static final int SPLIT_THRESHOLD = 20_000;
    /** Floor on how small a window's own split-candidates may get before giving up on splitting
     *  further and just paging through it as-is over however many runs it takes — guards against
     *  runaway recursive splitting for a pathologically dense sub-day period. */
    private static final int MIN_SPLIT_WINDOW_DAYS = 1;
    /** Clock-skew safety margin applied to the delta window's start — re-fetching a small overlap
     *  is harmless (every write here is an upsert/replace), missing a just-modified CVE isn't. */
    private static final Duration DELTA_SAFETY_MARGIN = Duration.ofHours(2);
    private static final OffsetDateTime BACKFILL_START = OffsetDateTime.of(1999, 1, 1, 0, 0, 0, 0, ZoneOffset.UTC);

    private final RestClient nvdSyncRestClient;
    private final NvdRateLimiter nvdRateLimiter;
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository;
    private final NvdCveSyncChunkRepository nvdCveSyncChunkRepository;
    private final NvdCveRecordRepository nvdCveRecordRepository;
    private final NvdCveCpeMatchRepository nvdCveCpeMatchRepository;
    private final NvdCveSyncChunkSplitService nvdCveSyncChunkSplitService;

    /** Result of one run (a bounded tick of either {@link #runBackfillTickAndRelease} or {@link
     *  #runDeltaTickAndRelease}). For the backfill side, {@code completed} means the *entire*
     *  baseline finished as a result of this run (mirrors {@link
     *  NvdCpeSyncService.SyncOutcome#completed}'s "clean finish vs. early abort" distinction, not
     *  "this run made progress without erroring") — a single run essentially never sets this true on
     *  its own for a fresh mirror (§4-2-4 estimates ~4 runs at the default budget). For the delta
     *  side, {@code completed} means the one ad hoc chunk this run enqueued finished. */
    public record SyncOutcome(int upserted, boolean completed) {
    }

    /** Bounds one run: stop once either {@code maxRequests} fetch *attempts* (successful or not —
     *  see the class javadoc) or {@code maxDuration} wall-clock time have been spent, whichever
     *  comes first. */
    public record RunBudget(int maxRequests, Duration maxDuration) {
    }

    /** Single-run guard, shared by every caller (scheduled and admin-triggered) of {@link
     *  #runBackfillTickAndRelease}/{@link #runDeltaTickAndRelease} — same shape as {@link
     *  NvdCpeSyncService}'s {@code fullSyncRunning}: the CAS in {@link #tryBeginRun} is itself the
     *  acquisition, callers must not check-then-call. Shared between backfill and delta since both
     *  drive the same {@link NvdRateLimiter} slots and the same chunk table. */
    private final AtomicBoolean runInProgress = new AtomicBoolean(false);

    public boolean tryBeginRun() {
        return runInProgress.compareAndSet(false, true);
    }

    /** Releases the run guard without ever having run a tick — for callers of {@link
     *  #tryBeginRun} only, and only when they're certain the acquired slot will never reach {@link
     *  #runBackfillTickAndRelease}/{@link #runDeltaTickAndRelease} (e.g. the worker thread itself
     *  failed to start) — see {@code NvdCpeSyncService#releaseFullSyncGuard}'s javadoc for the full
     *  rationale (task-backlog items 81/136/141). */
    public void releaseRunGuard() {
        runInProgress.set(false);
    }

    /** Runs one budgeted backfill tick and unconditionally releases {@link #runInProgress}
     *  afterward (success or exception) — callers must have already won {@link #tryBeginRun}. */
    public SyncOutcome runBackfillTickAndRelease(Optional<String> apiKey, RunBudget budget) {
        try {
            return runBackfillTick(apiKey, budget);
        } finally {
            runInProgress.set(false);
        }
    }

    /** Runs one budgeted delta tick and unconditionally releases {@link #runInProgress} afterward
     *  — same contract as {@link #runBackfillTickAndRelease}. No-ops (returns {@code
     *  SyncOutcome(0, false)}) if the baseline backfill hasn't completed yet — delta sync is only
     *  meaningful against a complete baseline. Not currently invoked by any scheduler (see the
     *  class javadoc); exposed for the executor-reuse this class's design requires. */
    public SyncOutcome runDeltaTickAndRelease(Optional<String> apiKey, RunBudget budget) {
        try {
            return runDeltaTick(apiKey, budget);
        } finally {
            runInProgress.set(false);
        }
    }

    private SyncOutcome runBackfillTick(Optional<String> apiKey, RunBudget runBudget) {
        NvdCveSyncState state = loadState();
        if (state.isBaselineCompleted()) {
            return new SyncOutcome(0, true);
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        if (state.getBaselineStartedAt() == null) {
            state.setBaselineStartedAt(now);
            state.setUpdatedAt(now);
            nvdCveSyncStateRepository.save(state);
        }
        ensureChunksSeeded();

        BudgetTracker budget = new BudgetTracker(runBudget);
        int totalUpserted = 0;
        List<NvdCveSyncChunk> chunks =
                nvdCveSyncChunkRepository.findByStatusNotOrderByWindowStartAsc(NvdCveSyncChunkStatus.COMPLETED);
        outer:
        for (NvdCveSyncChunk chunk : chunks) {
            while (true) {
                if (budget.exhausted()) {
                    break outer;
                }
                ChunkStepOutcome step = processChunkStep(chunk, apiKey, budget);
                totalUpserted += step.upserted();
                if (step.chunkFinished()) {
                    break;
                }
            }
        }

        boolean allDone = nvdCveSyncChunkRepository.countByStatusNot(NvdCveSyncChunkStatus.COMPLETED) == 0;
        if (allDone) {
            state.setBaselineCompleted(true);
            state.setUpdatedAt(OffsetDateTime.now(ZoneOffset.UTC));
            nvdCveSyncStateRepository.save(state);
            log.warn("NVD CVE backfill: baseline complete");
        }
        return new SyncOutcome(totalUpserted, allDone);
    }

    private SyncOutcome runDeltaTick(Optional<String> apiKey, RunBudget runBudget) {
        NvdCveSyncState state = loadState();
        if (!state.isBaselineCompleted()) {
            log.warn("NVD CVE delta sync skipped: baseline backfill has not completed yet");
            return new SyncOutcome(0, false);
        }

        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime cursor = state.getLastDeltaSyncedAt() != null ? state.getLastDeltaSyncedAt() : now.minusDays(1);
        NvdCveSyncChunk chunk = new NvdCveSyncChunk();
        chunk.setWindowStart(cursor.minus(DELTA_SAFETY_MARGIN));
        chunk.setWindowEnd(now);
        chunk.setStatus(NvdCveSyncChunkStatus.PENDING);
        nvdCveSyncChunkRepository.save(chunk);

        BudgetTracker budget = new BudgetTracker(runBudget);
        int totalUpserted = 0;
        boolean chunkFinished = false;
        while (!budget.exhausted()) {
            ChunkStepOutcome step = processChunkStep(chunk, apiKey, budget);
            totalUpserted += step.upserted();
            if (step.chunkFinished()) {
                chunkFinished = true;
                break;
            }
        }

        if (chunkFinished && chunk.getStatus() == NvdCveSyncChunkStatus.COMPLETED) {
            state.setLastDeltaSyncedAt(now);
            state.setUpdatedAt(now);
            nvdCveSyncStateRepository.save(state);
        }
        return new SyncOutcome(totalUpserted, chunkFinished);
    }

    private NvdCveSyncState loadState() {
        return nvdCveSyncStateRepository.findById((short) 1)
                .orElseThrow(() -> new IllegalStateException(
                        "nvd_cve_sync_state row (id=1) is missing -- the V39 migration should have inserted it"));
    }

    /** Seeds the full [1999-01-01, now) chunk queue in 120-day windows, once — a no-op once any
     *  chunk exists (including ones adaptive-split has since added), so this is safe to call at the
     *  top of every backfill tick. ~84 rows for the initial seed; cheap to bulk-insert. */
    private void ensureChunksSeeded() {
        if (nvdCveSyncChunkRepository.count() > 0) {
            return;
        }
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        List<NvdCveSyncChunk> chunks = new ArrayList<>();
        OffsetDateTime cursor = BACKFILL_START;
        while (cursor.isBefore(now)) {
            OffsetDateTime windowEnd = cursor.plusDays(WINDOW_DAYS);
            if (windowEnd.isAfter(now)) {
                windowEnd = now;
            }
            NvdCveSyncChunk chunk = new NvdCveSyncChunk();
            chunk.setWindowStart(cursor);
            chunk.setWindowEnd(windowEnd);
            chunk.setStatus(NvdCveSyncChunkStatus.PENDING);
            chunks.add(chunk);
            cursor = windowEnd;
        }
        nvdCveSyncChunkRepository.saveAll(chunks);
        log.info("NVD CVE backfill: seeded {} date-window chunks covering {}..{}", chunks.size(), BACKFILL_START, now);
    }

    /** Replaces {@code chunk} with two new {@code PENDING} child chunks covering its two date-range
     *  halves, and marks {@code chunk} itself {@code COMPLETED} (its own row needs no further
     *  attention once its children exist — see the class javadoc's "COMPLETED" note). Recurses
     *  naturally: a freshly-inserted child goes through this exact same check the next time it's
     *  picked up, so a still-too-dense half keeps splitting on its own without any extra code here.
     *
     *  <p>The actual writes (both children plus the parent's own {@code COMPLETED} save) happen
     *  inside {@link NvdCveSyncChunkSplitService#splitAndComplete}, a single atomic, idempotent
     *  transaction on a separate bean — see that class's javadoc for why this must not be three
     *  separate non-transactional writes on {@code this} (closed-mode backlog item 202, REVISE
     *  round 1, point 2). {@code observedTotalResults}/{@code upserted} must reflect a page that
     *  has *already* been ingested by the time this is called — see {@link #processChunkStep}'s
     *  call site, which fetches+ingests before ever calling this. */
    private void splitChunk(NvdCveSyncChunk chunk, int observedTotalResults, int upserted, OffsetDateTime now) {
        Duration span = Duration.between(chunk.getWindowStart(), chunk.getWindowEnd());
        OffsetDateTime mid = chunk.getWindowStart().plus(span.dividedBy(2));

        nvdCveSyncChunkSplitService.splitAndComplete(chunk, mid, observedTotalResults, upserted, now);

        log.warn("NVD CVE backfill: window {}..{} exceeded the adaptive-split threshold ({} results > {}) "
                        + "-- split into {}..{} and {}..{}",
                chunk.getWindowStart(), chunk.getWindowEnd(), observedTotalResults, SPLIT_THRESHOLD,
                chunk.getWindowStart(), mid, mid, chunk.getWindowEnd());
    }

    /** Outcome of a single {@link #processChunkStep} call — {@code chunkFinished} is true whenever
     *  the calling loop should stop paging this exact chunk (it completed, failed this attempt, or
     *  was just split), false if the same chunk has more pages to fetch and the run budget allows
     *  continuing immediately. */
    private record ChunkStepOutcome(int upserted, boolean chunkFinished) {
    }

    /**
     * Fetches and ingests exactly one NVD API page for {@code chunk} at its current {@code
     * next_start_index}, then persists the chunk's updated progress. Every call — success or
     * failure — consumes exactly one attempt from {@code budget} (see the class javadoc for why
     * attempts, not successes, are the budget unit) and one {@link NvdRateLimiter} slot.
     */
    private ChunkStepOutcome processChunkStep(NvdCveSyncChunk chunk, Optional<String> apiKey, BudgetTracker budget) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        if (chunk.getStartedAt() == null) {
            chunk.setStartedAt(now);
        }
        chunk.setStatus(NvdCveSyncChunkStatus.IN_PROGRESS);

        nvdRateLimiter.awaitTurn(apiKey.isPresent());
        chunk.setAttemptCount(chunk.getAttemptCount() + 1);
        budget.recordAttempt();

        FetchResult result = fetchPage(chunk.getWindowStart(), chunk.getWindowEnd(), chunk.getNextStartIndex(), apiKey);
        if (result.failed()) {
            chunk.setStatus(NvdCveSyncChunkStatus.FAILED);
            chunk.setLastError(result.error());
            nvdCveSyncChunkRepository.save(chunk);
            return new ChunkStepOutcome(0, true);
        }

        JsonNode body = result.body();
        int totalResults = body.path("totalResults").asInt(0);
        JsonNode vulnerabilities = body.path("vulnerabilities");
        boolean isFirstPage = chunk.getNextStartIndex() == 0;
        long windowDays = Duration.between(chunk.getWindowStart(), chunk.getWindowEnd()).toDays();

        if (isFirstPage && totalResults > SPLIT_THRESHOLD && windowDays > MIN_SPLIT_WINDOW_DAYS) {
            // Ingest *before* splitting (closed-mode backlog item 202, REVISE round 1, point 2):
            // if ingest throws (e.g. a downstream data issue), the chunk is left IN_PROGRESS with
            // no children yet, which is safe to retry -- whereas splitting first and ingesting
            // after could leave two persisted children behind a parent that never got its
            // COMPLETED save, and the next tick's re-split would then hit the children's own
            // UNIQUE (window_start, window_end) constraint instead of surfacing the real failure.
            int upserted = ingest(vulnerabilities);
            splitChunk(chunk, totalResults, upserted, now);
            return new ChunkStepOutcome(upserted, true);
        }

        int upserted = ingest(vulnerabilities);
        int fetched = vulnerabilities.size();
        chunk.setTotalResults(totalResults);
        chunk.setUpsertedCount(chunk.getUpsertedCount() + upserted);
        chunk.setNextStartIndex(chunk.getNextStartIndex() + fetched);
        chunk.setLastError(null);

        boolean finished = fetched == 0 || chunk.getNextStartIndex() >= totalResults;
        if (finished) {
            chunk.setStatus(NvdCveSyncChunkStatus.COMPLETED);
            chunk.setCompletedAt(now);
        }
        nvdCveSyncChunkRepository.save(chunk);
        return new ChunkStepOutcome(upserted, finished);
    }

    /** One fetch outcome: either a parsed JSON body, or a sanitized error description (see {@link
     *  #describeError}) — never both. */
    private record FetchResult(JsonNode body, String error) {
        boolean failed() {
            return body == null;
        }
    }

    private FetchResult fetchPage(OffsetDateTime windowStart, OffsetDateTime windowEnd, int startIndex,
            Optional<String> apiKey) {
        URI uri = UriComponentsBuilder.fromHttpUrl(NVD_CVE_API)
                .queryParam("resultsPerPage", RESULTS_PER_PAGE)
                .queryParam("startIndex", startIndex)
                .queryParam("lastModStartDate", formatNvdTimestamp(windowStart))
                .queryParam("lastModEndDate", formatNvdTimestamp(windowEnd))
                .build()
                .toUri();
        try {
            JsonNode body = nvdSyncRestClient.get()
                    .uri(uri)
                    .headers(headers -> apiKey.ifPresent(key -> headers.set("apiKey", key)))
                    .retrieve()
                    .body(JsonNode.class);
            return new FetchResult(body, null);
        } catch (Exception e) {
            log.warn("NVD CVE API request failed (window {}..{}, startIndex={}): {}", windowStart, windowEnd,
                    startIndex, describeError(e));
            return new FetchResult(null, describeError(e));
        }
    }

    private static String formatNvdTimestamp(OffsetDateTime value) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(value);
    }

    /** Sanitized failure description for {@code nvd_cve_sync_chunk.last_error} — status code (when
     *  the failure was an HTTP error response) plus the exception's simple class name only. Never
     *  {@code e.getMessage()}: several {@code RestClientException} subclasses embed the request URL
     *  in their message, which must never reach this column (see the class javadoc's security
     *  note). */
    private static String describeError(Exception e) {
        StringBuilder sb = new StringBuilder();
        if (e instanceof RestClientResponseException rcre) {
            sb.append(rcre.getStatusCode().value()).append(' ');
        }
        sb.append(e.getClass().getSimpleName());
        return sb.toString();
    }

    /** Parses and upserts every CVE record + its {@code cpeMatch} rows in {@code vulnerabilities}
     *  (one NVD API page). Returns the number of CVE records processed (mirrors {@code
     *  NvdCpeSyncService#sync}'s "rows processed" counter convention, not "rows this predicate
     *  actually wrote").
     *
     *  <p>A CVE whose {@code lastModified} is missing or fails to parse is logged and skipped
     *  entirely (closed-mode backlog item 202, REVISE round 1, point 1) — {@code
     *  nvd_cve_records.last_modified_at} is {@code NOT NULL}, so passing a {@code null} value
     *  through to {@link NvdCveRecordRepository#upsertBatch} would throw {@code
     *  DataIntegrityViolationException} for the *whole page's batch*, which propagates out before
     *  {@link #processChunkStep} ever persists this chunk's advanced {@code next_start_index} —
     *  leaving the chunk permanently re-fetching (and re-failing on) this exact same page, with no
     *  retry cap. Skipping just the offending CVE lets every other record on the page still upsert
     *  and the chunk still advance past it. */
    private int ingest(JsonNode vulnerabilities) {
        List<NvdCveRecordRepository.Row> records = new ArrayList<>();
        List<String> cveIds = new ArrayList<>();
        List<NvdCveCpeMatchRepository.Row> matches = new ArrayList<>();

        for (JsonNode vulnNode : vulnerabilities) {
            JsonNode cve = vulnNode.path("cve");
            String cveId = cve.path("id").asText(null);
            if (cveId == null) {
                continue;
            }
            OffsetDateTime lastModifiedAt = parseNvdTimestamp(cve.path("lastModified").asText(null));
            if (lastModifiedAt == null) {
                log.warn("NVD CVE ingest: skipping {} -- lastModified is missing or unparseable "
                        + "(nvd_cve_records.last_modified_at is NOT NULL)", cveId);
                continue;
            }
            cveIds.add(cveId);
            records.add(new NvdCveRecordRepository.Row(
                    cveId,
                    extractEnglishDescription(cve.path("descriptions")),
                    extractSeverity(cve.path("metrics")),
                    extractScore(cve.path("metrics")),
                    parseNvdTimestamp(cve.path("published").asText(null)),
                    lastModifiedAt));
            collectCpeMatches(cveId, cve.path("configurations"), matches);
        }

        if (records.isEmpty()) {
            return 0;
        }
        nvdCveRecordRepository.upsertBatch(records);
        nvdCveCpeMatchRepository.replaceForCves(cveIds, matches);
        return records.size();
    }

    private void collectCpeMatches(String cveId, JsonNode configurations, List<NvdCveCpeMatchRepository.Row> out) {
        for (JsonNode config : configurations) {
            for (JsonNode node : config.path("nodes")) {
                for (JsonNode cpeMatch : node.path("cpeMatch")) {
                    String criteria = cpeMatch.path("criteria").asText(null);
                    if (criteria == null) {
                        continue;
                    }
                    CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(criteria);
                    if (vendorProduct == null) {
                        continue;
                    }
                    out.add(new NvdCveCpeMatchRepository.Row(
                            cveId,
                            CpeUtils.parsePart(criteria),
                            vendorProduct.vendor(),
                            vendorProduct.product(),
                            criteria,
                            cpeMatch.path("vulnerable").asBoolean(true),
                            cpeMatch.path("versionStartIncluding").asText(null),
                            cpeMatch.path("versionStartExcluding").asText(null),
                            cpeMatch.path("versionEndIncluding").asText(null),
                            cpeMatch.path("versionEndExcluding").asText(null)));
                }
            }
        }
    }

    /** Same v3.1 -> v3.0 -> v2 {@code baseSeverity} fallback chain as {@code
     *  NvdVulnerabilitySource#extractSeverity} — duplicated rather than shared, deliberately: this
     *  class must not take a dependency on the live-query code it may eventually replace (see the
     *  class javadoc's scope note; the A/B verification gate in backlog item 202 is a separate,
     *  later task). */
    private String extractSeverity(JsonNode metrics) {
        JsonNode v31 = metrics.path("cvssMetricV31");
        if (v31.isArray() && !v31.isEmpty()) {
            String severity = v31.get(0).path("cvssData").path("baseSeverity").asText(null);
            if (severity != null) {
                return severity;
            }
        }
        JsonNode v30 = metrics.path("cvssMetricV30");
        if (v30.isArray() && !v30.isEmpty()) {
            String severity = v30.get(0).path("cvssData").path("baseSeverity").asText(null);
            if (severity != null) {
                return severity;
            }
        }
        JsonNode v2 = metrics.path("cvssMetricV2");
        if (v2.isArray() && !v2.isEmpty()) {
            return v2.get(0).path("baseSeverity").asText(null);
        }
        return null;
    }

    private BigDecimal extractScore(JsonNode metrics) {
        JsonNode v31 = metrics.path("cvssMetricV31");
        if (v31.isArray() && !v31.isEmpty() && v31.get(0).path("cvssData").has("baseScore")) {
            return BigDecimal.valueOf(v31.get(0).path("cvssData").path("baseScore").asDouble());
        }
        JsonNode v30 = metrics.path("cvssMetricV30");
        if (v30.isArray() && !v30.isEmpty() && v30.get(0).path("cvssData").has("baseScore")) {
            return BigDecimal.valueOf(v30.get(0).path("cvssData").path("baseScore").asDouble());
        }
        JsonNode v2 = metrics.path("cvssMetricV2");
        if (v2.isArray() && !v2.isEmpty() && v2.get(0).has("baseScore")) {
            return BigDecimal.valueOf(v2.get(0).path("baseScore").asDouble());
        }
        return null;
    }

    private String extractEnglishDescription(JsonNode descriptions) {
        for (JsonNode descriptionNode : descriptions) {
            if ("en".equals(descriptionNode.path("lang").asText())) {
                return descriptionNode.path("value").asText(null);
            }
        }
        return null;
    }

    /** NVD's {@code published}/{@code lastModified} fields are ISO-8601 without a zone/offset
     *  (e.g. {@code "2019-10-03T13:15:10.947"}, implicitly UTC) — same fallback shape as {@code
     *  CveOrgSyncService#parseTimestamp}: try a real offset first in case NVD ever adds one, then
     *  fall back to parsing as a bare local timestamp and assuming UTC. */
    private OffsetDateTime parseNvdTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(value).atOffset(ZoneOffset.UTC);
            } catch (DateTimeException e2) {
                return null;
            }
        }
    }

    /** Tracks one run's remaining budget — see the class javadoc for why attempts (not successes)
     *  are the unit. Package-private for direct unit testing. */
    static final class BudgetTracker {
        private final int maxAttempts;
        private final long deadlineMillis;
        private int attempts;

        BudgetTracker(RunBudget budget) {
            this.maxAttempts = budget.maxRequests();
            this.deadlineMillis = System.currentTimeMillis() + budget.maxDuration().toMillis();
        }

        void recordAttempt() {
            attempts++;
        }

        boolean exhausted() {
            return attempts >= maxAttempts || System.currentTimeMillis() >= deadlineMillis;
        }
    }
}
