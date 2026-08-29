package com.vulncheck.app.service.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.OsvSyncFailure;
import com.vulncheck.app.entity.OsvSyncState;
import com.vulncheck.app.repository.OsvAdvisoryRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.service.vuln.OsvEcosystems;
import com.vulncheck.app.service.vuln.OsvSyncRateLimiter;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Syncs OSV.dev's own non-GHSA-reviewed advisories (PYSEC/GO/RUSTSEC/DRUPAL-CONTRIB/EEF-CVE/OSV-*,
 * restricted to the 10 supported ecosystems) into the local mirror — see {@code
 * docs/spec/osv-mirror-plan.md} §6 for the full design. Direct port of {@code GhsaSyncService}'s
 * structure (baseline/delta split, dead-letter ledger, tombstone pruning, sync_in_progress
 * try/finally, broad {@code catch (RuntimeException e)} cleanup), adapted for OSV's own data shape:
 *
 * <ul>
 *   <li>{@link #syncBaseline()} downloads each of the 10 supported ecosystems' own {@code
 *       {ecosystem}/all.zip} individually (plan §6-1) rather than one combined archive — {@code
 *       GHSA-}/{@code MAL-} prefixed entries are skipped by filename before ever being parsed
 *       (plan §4-1), and the completeness gate is self-calibrating (the union of every non-excluded
 *       filename seen across all 10 zips, not a hardcoded expected count — plan §6-1 step 4).
 *   <li>{@link #syncDelta()} fetches {@code modified_id.csv} in full each run (it is a complete
 *       manifest, not an incremental diff — plan §2-2/§6-2) and advances {@code
 *       osv_sync_state.last_cursor} in whole csv-timestamp groups at a time (plan §6-2 step 7):
 *       a group with any non-dead-lettered failure stops the run entirely, without advancing the
 *       cursor past the last fully-completed group — never mid-group.
 * </ul>
 *
 * <p>Both paths funnel every document through the same {@link OsvDocumentUpsertService#upsertOsvJson}.
 */
@Service
@Slf4j
public class OsvSyncService {

    private static final String BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com/";
    private static final Set<String> ALLOWED_HOSTS = Set.of("osv-vulnerabilities.storage.googleapis.com");

    /** The 10 OSV-native ecosystem strings this app supports — used both as the baseline zip path
     *  segment ({@code {ecosystem}/all.zip}) and as delta's directory allowlist (plan §8-3(a)). */
    private static final List<String> SUPPORTED_OSV_ECOSYSTEMS = List.copyOf(OsvEcosystems.INTERNAL_TO_OSV.values());
    private static final Set<String> ALLOWED_DIRECTORIES = Set.copyOf(SUPPORTED_OSV_ECOSYSTEMS);

    /** Plan §6-1 step 4: below this fraction of the self-calibrated candidate-id union, a baseline
     *  run is treated as failed/partial, never marked loaded (plan §0-1 principle 1). */
    private static final double COMPLETENESS_THRESHOLD = 0.90;
    /** Plan §6-2 step 4 ("initial value of 1,000 recommended"). Package-visible so tests can
     *  exercise the group-atomic boundary logic without a 1,000-row fixture. */
    static final int DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN = 1000;
    /** Same convention as {@code GhsaSyncService.DEAD_LETTER_THRESHOLD}. */
    static final int DEAD_LETTER_THRESHOLD = 3;

    private static final long MAX_JSON_DOCUMENT_BYTES = 5L * 1024 * 1024;
    /** Plan §8-3(c): ~5x the measured real size (48.9MB) as of this writing. */
    private static final long MAX_MODIFIED_CSV_BYTES = 256L * 1024 * 1024;
    private static final int MAX_REDIRECTS = 3;

    /** Plan §8-3(b): loose length/charset validation (OSV ids have no single fixed shape across
     *  sources, unlike GHSA's {@code GHSA-xxxx-xxxx-xxxx}) — {@code {0,39}} after the mandatory
     *  first character caps the total length at 40, matching {@code osv_advisories.osv_id}/{@code
     *  osv_sync_failures.osv_id}'s {@code VARCHAR(40)} width. The {@code ".."} substring check is
     *  applied separately (a regex alone can't reject it while still allowing single dots). */
    private static final Pattern OSV_ID_PATTERN = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$");

    private final RestClient osvSyncRestClient;
    private final OsvDocumentUpsertService documentUpsertService;
    private final OsvAdvisoryRepository osvAdvisoryRepository;
    private final OsvSyncStateRepository osvSyncStateRepository;
    private final OsvSyncFailureRepository osvSyncFailureRepository;
    private final OsvSyncRateLimiter osvSyncRateLimiter;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final int maxDocumentsPerDeltaRun;

    /** One already-open ecosystem zip stream plus the two GCS response headers baseline records
     *  for {@code osv_sync_state.baseline_source_generation}/the initial cursor computation (plan
     *  §6-1 step 5, §9-0 item 6). {@code lastModified}/{@code generation} may be null — a test
     *  double, or a real response missing either header, both degrade gracefully (see {@link
     *  #computeInitialCursor}). */
    record StreamWithHeaders(InputStream stream, String lastModified, String generation) {
    }

    /** Test seam for the 10 per-ecosystem baseline zip downloads — production always goes through
     *  {@link #openZipStreamUnchecked}, a plain streaming {@link URLConnection} (same rationale as
     *  {@code GhsaSyncService#openStream}: a multi-hundred-MB body needs an unbounded read timeout).
     *  {@code MockRestServiceServer} can't intercept a raw {@link URLConnection}. */
    private final Function<String, StreamWithHeaders> zipStreamOpener;
    /** Test seam for the {@code modified_id.csv} download — same rationale as {@link #zipStreamOpener}. */
    private final Function<String, InputStream> csvStreamOpener;

    private final java.util.concurrent.atomic.AtomicBoolean running = new java.util.concurrent.atomic.AtomicBoolean(false);

    @Autowired
    public OsvSyncService(
            RestClient osvSyncRestClient,
            OsvDocumentUpsertService documentUpsertService,
            OsvAdvisoryRepository osvAdvisoryRepository,
            OsvSyncStateRepository osvSyncStateRepository,
            OsvSyncFailureRepository osvSyncFailureRepository) {
        this(osvSyncRestClient, documentUpsertService, osvAdvisoryRepository, osvSyncStateRepository,
                osvSyncFailureRepository, new OsvSyncRateLimiter(), DEFAULT_MAX_DOCUMENTS_PER_DELTA_RUN, null, null);
    }

    /** Test-only constructor — lets tests inject a disabled rate limiter, a small {@code
     *  maxDocumentsPerDeltaRun} (to exercise the group-atomic cutoff without a 1,000-row fixture),
     *  and in-memory stream openers. */
    OsvSyncService(
            RestClient osvSyncRestClient,
            OsvDocumentUpsertService documentUpsertService,
            OsvAdvisoryRepository osvAdvisoryRepository,
            OsvSyncStateRepository osvSyncStateRepository,
            OsvSyncFailureRepository osvSyncFailureRepository,
            OsvSyncRateLimiter osvSyncRateLimiter,
            int maxDocumentsPerDeltaRun,
            Function<String, StreamWithHeaders> zipStreamOpener,
            Function<String, InputStream> csvStreamOpener) {
        this.osvSyncRestClient = osvSyncRestClient;
        this.documentUpsertService = documentUpsertService;
        this.osvAdvisoryRepository = osvAdvisoryRepository;
        this.osvSyncStateRepository = osvSyncStateRepository;
        this.osvSyncFailureRepository = osvSyncFailureRepository;
        this.osvSyncRateLimiter = osvSyncRateLimiter;
        this.maxDocumentsPerDeltaRun = maxDocumentsPerDeltaRun;
        this.zipStreamOpener = zipStreamOpener != null ? zipStreamOpener : this::openZipStreamUnchecked;
        this.csvStreamOpener = csvStreamOpener != null ? csvStreamOpener : this::openCsvStreamUnchecked;
    }

    public record SyncResult(int upserted, int failed, boolean alreadyRunning) {
    }

    /** Full re-walk of all 10 ecosystem zips, ignoring any existing cursor — manually triggered
     *  only, never {@code @Scheduled}, mirroring {@code GhsaSyncService#syncBaseline}'s precedent. */
    public SyncResult syncBaseline() {
        if (!running.compareAndSet(false, true)) {
            log.warn("OSV baseline sync skipped: another OSV sync is already running");
            return new SyncResult(0, 0, true);
        }
        try {
            return doSyncBaseline();
        } finally {
            running.set(false);
        }
    }

    /** Only records changed since the last cursor — safe to run routinely. No-op until a baseline
     *  has completed at least once. */
    public SyncResult syncDelta() {
        if (!running.compareAndSet(false, true)) {
            log.warn("OSV delta sync skipped: another OSV sync is already running");
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
        OffsetDateTime runStartedAt = osvAdvisoryRepository.currentDatabaseTime().atOffset(java.time.ZoneOffset.UTC);
        OsvSyncState state = loadState();
        state.setSyncInProgress(true);
        osvSyncStateRepository.save(state);

        int upserted = 0;
        int failed = 0;
        Set<String> allCandidateIds = new LinkedHashSet<>();
        Set<String> succeededIds = new LinkedHashSet<>();
        OffsetDateTime minLastModified = null;
        StringBuilder generationSummary = new StringBuilder();

        // Broad catch, matching GhsaSyncService#doSyncBaseline's own rationale: an unchecked
        // exception below must still clear sync_in_progress, or every future sync stays wedged.
        try {
            for (String ecosystem : SUPPORTED_OSV_ECOSYSTEMS) {
                if (!paceOrAbort()) {
                    return failSync(state, "Interrupted before ecosystem '" + ecosystem + "'s zip could be requested", upserted, failed);
                }
                String zipUrl = BASE_URL + ecosystem + "/all.zip";
                StreamWithHeaders handle;
                try {
                    handle = zipStreamOpener.apply(zipUrl);
                } catch (RuntimeException e) {
                    // Fetch-level failure for one ecosystem's zip aborts the whole run (matching
                    // GhsaSyncService's own "an IOException reading the archive aborts the baseline
                    // run" discipline) — a partial baseline missing an entire ecosystem's worth of
                    // records must not silently be marked loaded.
                    log.error("OSV baseline sync failed fetching {}'s zip", ecosystem, e);
                    return failSync(state, "Failed to download " + zipUrl + ": " + e.getMessage(), upserted, failed);
                }

                OffsetDateTime lastModified = parseHttpDate(handle.lastModified());
                if (lastModified != null && (minLastModified == null || lastModified.isBefore(minLastModified))) {
                    minLastModified = lastModified;
                }
                if (generationSummary.length() > 0) {
                    generationSummary.append(';');
                }
                generationSummary.append(ecosystem).append('=').append(handle.generation());

                try (ZipInputStream zip = new ZipInputStream(handle.stream())) {
                    ZipEntry entry;
                    while ((entry = zip.getNextEntry()) != null) {
                        if (entry.isDirectory()) {
                            continue;
                        }
                        String name = entry.getName();
                        int lastSlash = name.lastIndexOf('/');
                        String fileName = lastSlash >= 0 ? name.substring(lastSlash + 1) : name;
                        if (!fileName.endsWith(".json")) {
                            continue;
                        }
                        String id = fileName.substring(0, fileName.length() - ".json".length());
                        if (id.startsWith("GHSA-") || id.startsWith("MAL-")) {
                            // Plan §4-1/§6-1 step 3a: excluded before ever being read/parsed —
                            // ghsa_advisories already covers GHSA-*, and MAL-* is malware-detection
                            // noise, not a vulnerability.
                            continue;
                        }
                        if (!isValidOsvId(id)) {
                            // Plan §8-1: WARN + skip, never inserted into osv_advisories OR
                            // osv_sync_failures (a VARCHAR(40)-width safety net, not the URL-
                            // injection concern §8-3(b) exists for — baseline never builds a URL
                            // from this id).
                            log.warn("OSV baseline sync: skipping entry with an implausible id '{}' in {}'s zip", id, ecosystem);
                            allCandidateIds.add(id);
                            failed++;
                            continue;
                        }
                        allCandidateIds.add(id);

                        byte[] bytes = readBounded(zip, MAX_JSON_DOCUMENT_BYTES);
                        UpsertOutcome outcome = parseAndUpsert(bytes, id);
                        if (outcome.osvId() != null) {
                            succeededIds.add(outcome.osvId());
                            upserted++;
                            clearFailure(outcome.osvId());
                        } else {
                            failed++;
                            recordFailure(id, outcome.error());
                        }
                    }
                } catch (IOException | java.io.UncheckedIOException e) {
                    log.error("OSV baseline sync failed reading {}'s zip after upserting {} records so far", ecosystem, upserted, e);
                    return failSync(state, "Reading " + ecosystem + "'s zip failed: " + e.getMessage(), upserted, failed);
                }
            }

            if (allCandidateIds.isEmpty() || succeededIds.size() < allCandidateIds.size() * COMPLETENESS_THRESHOLD) {
                String message = "Baseline incomplete: only " + succeededIds.size() + " of " + allCandidateIds.size()
                        + " candidate records across all 10 ecosystem zips (" + Math.round(COMPLETENESS_THRESHOLD * 100)
                        + "% threshold) — not marking baseline_loaded (plan §6-1 step 4)";
                log.error("OSV baseline sync aborted: {}", message);
                return failSync(state, message, upserted, failed);
            }

            // Senior-review-established discipline (mirrors GhsaSyncService#doSyncBaseline item 1):
            // pruning only runs when this run had zero failures — a document that merely failed to
            // parse/upsert this run keeps its old last_synced_at, which would otherwise look
            // indistinguishable from a genuinely-removed record to the tombstone-prune query below.
            int pruned = 0;
            if (failed == 0) {
                pruned = osvAdvisoryRepository.deleteNotSyncedSince(runStartedAt);
                log.info("OSV baseline sync: pruned {} tombstoned advisories no longer present", pruned);
            } else {
                log.warn("OSV baseline sync: skipping tombstone pruning — {} entr(y/ies) failed to upsert this run", failed);
            }

            state.setBaselineLoaded(true);
            state.setBaselineSourceGeneration(generationSummary.toString());
            state.setLastCursor(computeInitialCursor(minLastModified));
            state.setSyncInProgress(false);
            state.setLastSyncedAt(OffsetDateTime.now());
            state.setLastSyncError(null);
            osvSyncStateRepository.save(state);

            log.info("OSV baseline sync complete: {} upserted, {} failed, {} pruned, cursor={}",
                    upserted, failed, pruned, state.getLastCursor());
            return new SyncResult(upserted, failed, false);
        } catch (RuntimeException e) {
            log.error("OSV baseline sync failed with an unexpected error after upserting {} records", upserted, e);
            return failSync(state, "Unexpected error: " + e.getMessage(), upserted, failed);
        }
    }

    /** Plan §6-1 step 5: the initial cursor is the minimum {@code last-modified} header observed
     *  across the 10 zip fetches, minus 7 days — deliberately conservative (re-processing a week's
     *  worth of already-current records costs ~420 extra GETs at the measured ~60/day change rate,
     *  plan §2-2) rather than risking a record changed between the zip snapshot and baseline
     *  completion being silently missed forever. Falls back to "now minus 7 days" (still
     *  conservative, just anchored to a different clock) if no zip's {@code last-modified} header
     *  was present/parseable — logged, since that means {@link #computeInitialCursor} is degrading
     *  from the plan's intended anchor. */
    private OffsetDateTime computeInitialCursor(OffsetDateTime minLastModified) {
        if (minLastModified != null) {
            return minLastModified.minusDays(7);
        }
        log.warn("OSV baseline sync: no usable last-modified header across any of the 10 ecosystem zips — "
                + "falling back to the DB server's current time minus 7 days for the initial delta cursor");
        return osvAdvisoryRepository.currentDatabaseTime().atOffset(java.time.ZoneOffset.UTC).minusDays(7);
    }

    private SyncResult failSync(OsvSyncState state, String message, int upserted, int failed) {
        state.setSyncInProgress(false);
        state.setLastSyncError(message);
        state.setLastSyncedAt(OffsetDateTime.now());
        osvSyncStateRepository.save(state);
        return new SyncResult(upserted, failed, false);
    }

    // -------------------------------------------------------------------- delta -----------------

    private record CsvRow(OffsetDateTime timestamp, String directory, String id) {
    }

    private SyncResult doSyncDelta() {
        OsvSyncState state = loadState();
        if (!state.isBaselineLoaded() || state.getLastCursor() == null) {
            log.warn("OSV delta sync skipped: baseline has not completed yet");
            return new SyncResult(0, 0, false);
        }
        state.setSyncInProgress(true);
        osvSyncStateRepository.save(state);

        OffsetDateTime cursor = state.getLastCursor();
        int upserted = 0;
        int failed = 0;
        boolean sawFailure = false;
        boolean interrupted = false;
        boolean csvFetchFailed = false;

        try {
            List<CsvRow> candidates;
            try {
                candidates = fetchAndFilterModifiedIdCsv(cursor);
            } catch (IOException | java.io.UncheckedIOException e) {
                log.error("OSV delta sync: failed to fetch/read modified_id.csv", e);
                csvFetchFailed = true;
                candidates = List.of();
            }

            // Plan §6-2 step 3: group by id, keep only the max-timestamp row per id (duplicate
            // directory listings for the same id are confirmed byte-identical regardless of which
            // directory is fetched — plan §4-3).
            Map<String, CsvRow> latestById = new LinkedHashMap<>();
            for (CsvRow row : candidates) {
                CsvRow existing = latestById.get(row.id());
                if (existing == null || row.timestamp().isAfter(existing.timestamp())) {
                    latestById.put(row.id(), row);
                }
            }
            List<CsvRow> sorted = new ArrayList<>(latestById.values());
            sorted.sort(java.util.Comparator.comparing(CsvRow::timestamp));

            // Plan §6-2 step 7: group consecutive rows sharing the exact same csv timestamp — the
            // unit both the MAX_DOCUMENTS_PER_DELTA_RUN cutoff (step 4) and cursor advancement
            // operate on. Never split a group.
            List<List<CsvRow>> groups = groupByTimestamp(sorted);

            OffsetDateTime advancedCursor = cursor;
            int processed = 0;
            groupLoop:
            for (List<CsvRow> group : groups) {
                if (processed >= maxDocumentsPerDeltaRun) {
                    break; // boundary respected only BETWEEN groups — plan §6-2 step 4
                }
                boolean groupHadRealFailure = false;
                for (CsvRow row : group) {
                    if (!paceOrAbort()) {
                        interrupted = true;
                        break groupLoop;
                    }
                    UpsertOutcome outcome = fetchAndUpsertOne(row.directory(), row.id());
                    processed++;
                    if (outcome.osvId() != null) {
                        upserted++;
                        clearFailure(outcome.osvId());
                    } else {
                        failed++;
                        boolean deadLettered = recordFailureAndCheckDeadLetter(row.id(), outcome.error());
                        if (deadLettered) {
                            log.warn("OSV delta sync: {} dead-lettered after {} consecutive failures — treated as "
                                    + "resolved for this group's cursor advancement", row.id(), DEAD_LETTER_THRESHOLD);
                        } else {
                            groupHadRealFailure = true;
                        }
                    }
                }
                if (groupHadRealFailure) {
                    // Plan §6-2 step 7.3: stop the whole run here — do not advance past this group,
                    // and do not attempt any later (newer-timestamp) group this run either.
                    sawFailure = true;
                    break;
                }
                advancedCursor = group.get(0).timestamp();
                persistCursor(state, advancedCursor);
            }

            state.setSyncInProgress(false);
            state.setLastSyncedAt(OffsetDateTime.now());
            if (interrupted) {
                state.setLastSyncError("Interrupted mid-run — cursor left at last successfully committed position");
            } else if (csvFetchFailed) {
                state.setLastSyncError("modified_id.csv fetch/read failed — this run made no progress past the "
                        + "last successfully committed cursor position");
            } else if (sawFailure) {
                state.setLastSyncError("One or more documents failed this run — cursor stopped before the first "
                        + "failed timestamp group (retried next run unless dead-lettered)");
            } else {
                state.setLastSyncError(null);
            }
            osvSyncStateRepository.save(state);

            log.info("OSV delta sync complete: {} upserted, {} failed, cursor={}", upserted, failed, advancedCursor);
            return new SyncResult(upserted, failed, false);
        } catch (RuntimeException e) {
            log.error("OSV delta sync failed with an unexpected error after upserting {} records", upserted, e);
            return failSync(state, "Unexpected error: " + e.getMessage(), upserted, failed);
        }
    }

    private List<List<CsvRow>> groupByTimestamp(List<CsvRow> sorted) {
        List<List<CsvRow>> groups = new ArrayList<>();
        List<CsvRow> current = null;
        OffsetDateTime currentTimestamp = null;
        for (CsvRow row : sorted) {
            if (current == null || !row.timestamp().equals(currentTimestamp)) {
                current = new ArrayList<>();
                groups.add(current);
                currentTimestamp = row.timestamp();
            }
            current.add(row);
        }
        return groups;
    }

    private void persistCursor(OsvSyncState state, OffsetDateTime cursor) {
        state.setLastCursor(cursor);
        osvSyncStateRepository.save(state);
    }

    /** Plan §6-2 steps 1-2/§8-3(a)/(c): streams {@code modified_id.csv} line by line (never fully
     *  buffered — it's a 48.9MB, 948k-line file) with a hard byte cap, and filters to rows that (a)
     *  name one of the 10 supported ecosystem directories exactly, (b) don't start with {@code
     *  GHSA-}/{@code MAL-}, (c) pass §8-3(b)'s id validation, and (d) have a csv-side timestamp
     *  strictly after {@code cursor}. */
    private List<CsvRow> fetchAndFilterModifiedIdCsv(OffsetDateTime cursor) throws IOException {
        String url = BASE_URL + "modified_id.csv";
        InputStream raw;
        try {
            raw = csvStreamOpener.apply(url);
        } catch (RuntimeException e) {
            throw new IOException("Failed to open modified_id.csv stream: " + e.getMessage(), e);
        }
        List<CsvRow> matches = new ArrayList<>();
        try (BufferedReader reader = boundedReader(raw, MAX_MODIFIED_CSV_BYTES)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank()) {
                    continue;
                }
                int firstComma = line.indexOf(',');
                if (firstComma < 0) {
                    continue;
                }
                String timestampText = line.substring(0, firstComma);
                String rest = line.substring(firstComma + 1);
                int slash = rest.indexOf('/');
                if (slash < 0) {
                    continue;
                }
                String directory = rest.substring(0, slash);
                String id = rest.substring(slash + 1);

                if (!ALLOWED_DIRECTORIES.contains(directory)) {
                    // Plan §8-3(a): directory must be an EXACT allowlist match before it's ever used
                    // to build a fetch URL. (Plan §6-2's unverified "directory<->zip membership"
                    // premise and its GIT/known-id-set fallback are not implemented — see the
                    // implementation report for why this was escalated as a residual item rather
                    // than built speculatively.)
                    continue;
                }
                if (id.startsWith("GHSA-") || id.startsWith("MAL-")) {
                    continue;
                }
                if (!isValidOsvId(id) || id.contains("..")) {
                    log.warn("OSV delta sync: skipping modified_id.csv row with an implausible id '{}'", id);
                    continue;
                }
                OffsetDateTime timestamp = parseTimestamp(timestampText);
                if (timestamp == null || !timestamp.isAfter(cursor)) {
                    continue;
                }
                matches.add(new CsvRow(timestamp, directory, id));
            }
        }
        return matches;
    }

    private UpsertOutcome fetchAndUpsertOne(String directory, String id) {
        String url = BASE_URL + directory + "/" + id + ".json";
        FetchOutcome fetch = fetchBounded(url, MAX_JSON_DOCUMENT_BYTES, MAX_REDIRECTS);
        if (fetch.status() != FetchStatus.OK) {
            return UpsertOutcome.failure("Failed to fetch " + url + " (" + fetch.status() + ")");
        }
        return parseAndUpsert(fetch.body(), id);
    }

    // ---------------------------------------------------------------- shared parse ---------------

    private record UpsertOutcome(String osvId, String error) {
        static UpsertOutcome success(String osvId) {
            return new UpsertOutcome(osvId, null);
        }
        static UpsertOutcome failure(String error) {
            return new UpsertOutcome(null, error);
        }
    }

    private UpsertOutcome parseAndUpsert(byte[] bytes, String fallbackIdForLogging) {
        if (bytes == null) {
            return UpsertOutcome.failure("document too large or unreadable");
        }
        JsonNode root;
        try {
            root = objectMapper.readTree(bytes);
        } catch (Exception e) {
            log.debug("Skipping unparseable OSV document {}", fallbackIdForLogging, e);
            return UpsertOutcome.failure("JSON parse error: " + e.getMessage());
        }
        try {
            String osvId = documentUpsertService.upsertOsvJson(root);
            if (osvId == null) {
                return UpsertOutcome.failure("missing required field (id/modified)");
            }
            return UpsertOutcome.success(osvId);
        } catch (Exception e) {
            log.warn("Skipping OSV document {} — failed to upsert", fallbackIdForLogging, e);
            return UpsertOutcome.failure("upsert error: " + e.getMessage());
        }
    }

    // ----------------------------------------------------------- dead-letter bookkeeping ---------

    private void clearFailure(String osvId) {
        osvSyncFailureRepository.deleteByOsvId(osvId);
    }

    private void recordFailure(String osvId, String error) {
        recordFailureAndCheckDeadLetter(osvId, error);
    }

    private boolean recordFailureAndCheckDeadLetter(String osvId, String error) {
        if (osvId == null || !isValidOsvId(osvId)) {
            log.warn("OSV sync: not recording a dead-letter entry for '{}' — doesn't look like a valid id "
                    + "(error: {})", osvId, error);
            return false;
        }
        OsvSyncFailure failure = osvSyncFailureRepository.findById(osvId).orElseGet(() -> new OsvSyncFailure(osvId));
        failure.setConsecutiveFailures(failure.getConsecutiveFailures() + 1);
        failure.setLastError(error);
        failure.setLastAttemptedAt(OffsetDateTime.now());
        boolean deadLettered = failure.getConsecutiveFailures() >= DEAD_LETTER_THRESHOLD;
        if (deadLettered && failure.getDeadLetteredAt() == null) {
            failure.setDeadLetteredAt(OffsetDateTime.now());
        }
        osvSyncFailureRepository.save(failure);
        return deadLettered;
    }

    // --------------------------------------------------------------------- helpers ---------------

    private OsvSyncState loadState() {
        return osvSyncStateRepository.findById((short) 1).orElseGet(OsvSyncState::new);
    }

    private boolean paceOrAbort() {
        osvSyncRateLimiter.awaitTurn();
        if (Thread.currentThread().isInterrupted()) {
            log.warn("OSV sync interrupted during rate-limiter wait — aborting without further progress this run");
            return false;
        }
        return true;
    }

    private static boolean isValidOsvId(String id) {
        return id != null && OSV_ID_PATTERN.matcher(id).matches() && !id.contains("..");
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

    private OffsetDateTime parseHttpDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toOffsetDateTime();
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    // ---------------------------------------------------------- streaming downloads --------------

    private StreamWithHeaders openZipStream(String url) throws IOException {
        URI uri = validatedUri(url);
        if (uri == null) {
            throw new IOException("Rejected non-allowlisted URL: " + url);
        }
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(0); // multi-hundred-MB body, same rationale as GhsaSyncService#openStream
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (osv sync)");
        InputStream stream = connection.getInputStream();
        return new StreamWithHeaders(stream, connection.getHeaderField("last-modified"), connection.getHeaderField("x-goog-generation"));
    }

    private StreamWithHeaders openZipStreamUnchecked(String url) {
        try {
            return openZipStream(url);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    private InputStream openCsvStream(String url) throws IOException {
        URI uri = validatedUri(url);
        if (uri == null) {
            throw new IOException("Rejected non-allowlisted URL: " + url);
        }
        URLConnection connection = uri.toURL().openConnection();
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(0);
        connection.setRequestProperty("User-Agent", "vulncheck-server/0.1 (osv sync)");
        return connection.getInputStream();
    }

    private InputStream openCsvStreamUnchecked(String url) {
        try {
            return openCsvStream(url);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    /** Plan §8-3(c): a hard byte cap on top of line-by-line streaming — {@code modified_id.csv} is
     *  fetched from a source outside this app's control, so a Content-Length lie or an unexpectedly
     *  huge response must not be trusted blindly. */
    private BufferedReader boundedReader(InputStream in, long maxBytes) {
        InputStream counting = new FilterInputStream(in) {
            private long total = 0;

            @Override
            public int read() throws IOException {
                int b = super.read();
                if (b != -1) {
                    total++;
                    checkLimit();
                }
                return b;
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                int n = super.read(b, off, len);
                if (n > 0) {
                    total += n;
                    checkLimit();
                }
                return n;
            }

            private void checkLimit() throws IOException {
                if (total > maxBytes) {
                    throw new IOException("modified_id.csv exceeded the maximum allowed size of " + maxBytes + " bytes");
                }
            }
        };
        return new BufferedReader(new InputStreamReader(counting, StandardCharsets.UTF_8));
    }

    // ---------------------------------------------------------- bounded fetch (JSON only) ---------

    private enum FetchStatus {
        OK, REJECTED_SCHEME_OR_HOST, TOO_MANY_REDIRECTS, TOO_LARGE, HTTP_ERROR, TRANSPORT_ERROR, INTERRUPTED
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
            return osvSyncRestClient.get().uri(uri).exchange((request, response) -> {
                HttpStatusCode status = response.getStatusCode();
                if (status.is3xxRedirection()) {
                    String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                    if (location == null) {
                        return FetchOutcome.of(FetchStatus.HTTP_ERROR);
                    }
                    if (redirectsRemaining <= 0) {
                        return FetchOutcome.of(FetchStatus.TOO_MANY_REDIRECTS);
                    }
                    if (!paceOrAbort()) {
                        return FetchOutcome.of(FetchStatus.INTERRUPTED);
                    }
                    return fetchBounded(uri.resolve(location).toString(), maxBytes, redirectsRemaining - 1);
                }
                if (!status.is2xxSuccessful()) {
                    return FetchOutcome.of(FetchStatus.HTTP_ERROR);
                }
                byte[] body = readBounded(response.getBody(), maxBytes);
                return body == null ? FetchOutcome.of(FetchStatus.TOO_LARGE) : FetchOutcome.ok(body);
            });
        } catch (Exception e) {
            log.warn("OSV sync: transport error fetching {}", url, e);
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
            log.warn("OSV sync: rejecting fetch of {} — not https or not an allowlisted host", url);
            return null;
        }
        return uri;
    }

    /** Reads at most {@code maxBytes} — returns null (caller treats as "too large") past that,
     *  rather than trusting a possibly-absent/lying {@code Content-Length}. Same as {@code
     *  GhsaSyncService#readBounded}. */
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
}
