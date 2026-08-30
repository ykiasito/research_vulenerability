package com.vulncheck.app.service.csaf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.CsafSyncState;
import com.vulncheck.app.repository.CsafAdvisoryRepository;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.service.registry.ExternalRegistryRateLimiter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.zstandard.ZstdCompressorInputStream;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Syncs Red Hat Product Security's CSAF advisories (directory + {@code changes.csv}/{@code
 * deletions.csv} discovery, no authentication) into the local mirror via the shared {@link
 * CsafDocumentUpsertService} — see {@code docs/spec/csaf-vendor-advisory-plan.md} §4-2 for the
 * design sketch this follows, and the Phase 2 go/no-go review for the measured findings baked into
 * this implementation from the start (items 5-8 below; items 2-4 landed in the shared {@code
 * CsafProductTreeWalker}/{@code CsafProductRepositoryImpl}, so both vendors benefit).
 *
 * <p><b>Scope: advisories only (go/no-go review, explicit constraint).</b> Only {@code
 * csaf/v2/advisories/} is synced. {@code csaf/v2/vex/} (confirmed live 2026-08-27: 65,440 documents,
 * ~18.51GB raw, extrapolated ~24.6M product rows) is deliberately NOT implemented here — see the
 * plan's §10 for the reasoning and the required separate user sign-off.
 *
 * <p><b>item 5 — baseline streams the {@code .tar.zst} archive, never per-document GETs:</b>
 * confirmed live 2026-08-27 that {@code https://security.access.redhat.com/data/csaf/v2/advisories/
 * archive_latest.txt} names the current archive (e.g. {@code csaf_advisories_2026-08-25.tar.zst}),
 * itself confirmed real and downloadable (~103.4MB compressed, containing all ~28,000 documents) with
 * a {@code .sha256} sidecar. A per-document baseline (28,102 docs x 2 requests x 500ms pacing) would
 * cost ~7.75 hours; the archive costs ~2 seconds — per-document baseline is explicitly forbidden for
 * Red Hat by the review. {@link #doSyncBaseline} downloads the whole (bounded-size) compressed body
 * into memory once — ~103MB is small enough to hold safely — verifies its SHA-256 BEFORE any byte of
 * it is trusted, then stream-decompresses ({@link ZstdCompressorInputStream} wrapping {@link
 * TarArchiveInputStream}) and upserts one entry at a time. The ~6GB uncompressed content is never
 * written to disk or held in memory as a whole — only the already-hash-verified ~103MB compressed
 * form, plus one entry's bytes at a time during the walk.
 *
 * <p><b>item 5 (continued) — decompression-bomb protection at the archive level:</b> {@code
 * SiemensCsafSyncService}'s existing hardening ({@code plan §6}) assumed one document fetched at a
 * time and has no notion of "a single archive containing many documents" at all. Three independent
 * bounds guard the walk in {@link #doSyncBaseline} — {@link #DEFAULT_MAX_ARCHIVE_ENTRY_COUNT}, the
 * per-entry cap ({@link #MAX_DOCUMENT_BYTES} by default, reused — an oversized single document is
 * exactly as suspicious whether it arrived via the archive or a per-document GET), and {@link
 * #DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES} — ANY of which aborts the whole baseline run
 * immediately (not a per-entry skip) with the sync state left untouched, so a subsequent run starts
 * baseline fresh rather than silently proceeding against a misbehaving/malicious archive.
 *
 * <p><b>item 6 — a separate, larger {@link #MAX_DOCUMENT_BYTES}, NOT Siemens' 10MB constant:</b>
 * confirmed live 2026-08-27 against the real archive: 22 real RHSA documents exceed 10MB, largest
 * observed 46,654,640 bytes ({@code 2024/rhsa-2024_9315.json}). Reusing Siemens' {@code
 * MAX_DOCUMENT_BYTES} would silently drop these as {@code TOO_LARGE}. 64MB leaves comfortable
 * headroom above the largest real document seen.
 *
 * <p><b>item 7 — batched DB ingest per document:</b> handled inside the SHARED {@link
 * CsafDocumentUpsertService} (see its own javadoc/{@code CsafProductRepositoryImpl}) — a real Red
 * Hat advisory can produce up to ~12,056 product rows and ~171,072 status rows, batched in chunks of
 * 2,000 rather than one {@code INSERT} per row or one giant statement.
 *
 * <p><b>Delta cursor encoding — a deliberate, documented departure from Siemens' plain-timestamp
 * {@code last_cursor}:</b> Red Hat has TWO independent CSV-driven change streams ({@code
 * changes.csv} for adds/updates, {@code deletions.csv} for tombstones — plan §4-2 step 4, and V17's
 * own migration comment already anticipated this: {@code "Red Hat: changes.csv/deletions.csvの最終
 * 処理タイムスタンプ"}, plural). Rather than a schema change (a second cursor column), both
 * timestamps are encoded into the single {@code csaf_sync_state.last_cursor} TEXT column as {@code
 * "<changesCursorIso>|<deletionsCursorIso>"} (see {@link #encodeCursor}/{@link #decodeCursor}) —
 * {@code last_cursor}'s per-vendor meaning was always documented as vendor-specific free text, so
 * this stays within V17's existing schema.
 *
 * <p><b>§5-5 merge-gate table (measured 2026-08-27 against the live feed — mirrored from {@code
 * docs/spec/csaf-vendor-advisory-plan.md} §5-5, which is the authoritative copy; kept in sync
 * manually, same convention as {@code SiemensCsafSyncService}/{@code NvdRateLimiter}):</b>
 *
 * <table border="1">
 * <caption>Red Hat CSAF sync — measured rate/volume</caption>
 * <tr><th>baseline doc count</th><th>pacing</th><th>baseline wall-clock</th><th>delta docs/day</th><th>cron</th><th>worst-case req/hour</th></tr>
 * <tr><td>27,930 real documents in the archive (measured 2026-08-27, {@code
 *     csaf_advisories_2026-08-25.tar.zst}; {@code changes.csv} itself lists 28,102 rows — some
 *     historic entries no longer present in the current archive snapshot, not a discrepancy in this
 *     count) — archive is 103,391,443 bytes compressed (measured via {@code Content-Length})</td>
 *     <td>baseline: 1 paced request for {@code archive_latest.txt} + 1 paced request for the archive
 *     itself (key {@code redhat_csaf}, 500ms floor, {@code ExternalRegistryRateLimiter}) — the
 *     ~103MB body download and decompression are NOT per-request paced (one download, nothing to
 *     pace against, matching {@code GhsaSyncService}'s tarball precedent)</td>
 *     <td>measured 2.49s to download the 103.4MB archive (this environment's network — network-
 *     dependent, not a portable constant) + measured 1.80s to stream-decompress and walk all 27,930
 *     entries to EOF, reading every entry's bytes (real archive, no DB writes in that measurement
 *     pass) — that decompression figure used Python's {@code zstandard} library as a fast proxy for
 *     the actual production path ({@link ZstdCompressorInputStream}/{@link TarArchiveInputStream}),
 *     NOT a direct measurement of this class's own Java code; labeled as such deliberately rather
 *     than presented as more precise than it is. Per-document upsert throughput across the full
 *     corpus (repeated batched INSERTs per advisory) was NOT measured end-to-end against a live-scale
 *     Postgres in this implementation pass either — labeled as an extrapolation gap deliberately,
 *     same discipline {@code GhsaSyncService}'s own table applies to its own unmeasured gap</td>
 *     <td>measured highly volatile: 2,012-3,561/day on 2026-08-25 through 2026-08-27 (an elevated
 *     stretch), vs. 35-254/day on 2026-08-13 through 2026-08-18 (a calmer stretch) — trailing-7-day
 *     average 1,141.6/day, all measured 2026-08-27 against the real {@code changes.csv}; {@link
 *     #MAX_DOCUMENTS_PER_RUN} (2,000, matching Siemens' cap) means a burst day is NOT fully drained
 *     in one delta run — the remainder carries to the next run (plan §7), same as Siemens' own cap
 *     behavior</td>
 *     <td>daily at 04:15 UTC, offset from {@code CveOrgScheduledSync}'s 03:30 UTC, {@code
 *     SiemensCsafScheduledSync}'s 03:45 UTC, and {@code GhsaSyncService}'s 04:00 UTC slots</td>
 *     <td>7,200 (the fixed-interval ceiling shared with {@code siemens_csaf}'s own worst case;
 *     actual traffic is far below this except during a delta run processing a burst day)</td></tr>
 * </table>
 *
 * <p><b>Baseline write volume (REVISE item 10, senior review 2026-08-27):</b> a full baseline sync
 * against the real 27,930-document archive measured 1,751,250 {@code csaf_products} rows + 4,245,640
 * {@code csaf_product_status} rows &asymp; ~6 million total {@code INSERT}s, plus ~6.09GB of raw JSON
 * landing in {@code csaf_advisories.raw_json} — the DB write volume (not the ~103MB compressed
 * download/decompression, which is fast, see the table above) is the real driver of baseline wall-clock
 * time, hence the timeout-warning language on {@code admin/csaf-redhat.html}. The 1,751,250 product-row
 * figure is the PRE-REVISE-item-3 count (before unreferenced-product-row filtering); item 3 measured
 * 46.6% of those rows as never referenced by any {@code csaf_product_status} entry, so the real
 * post-fix count is expected to be meaningfully lower — but was NOT re-measured against the live
 * 27,930-document archive in this revision pass (no live baseline re-run was performed here), so the
 * post-fix number is deliberately left as an expectation, not reported as a re-measured fact.
 */
@Service
@Slf4j
public class RedHatCsafSyncService {

    public static final String VENDOR = "redhat";

    private static final String ADVISORIES_DIR_URL = "https://security.access.redhat.com/data/csaf/v2/advisories/";
    private static final String ARCHIVE_LATEST_URL = ADVISORIES_DIR_URL + "archive_latest.txt";
    private static final String CHANGES_CSV_URL = ADVISORIES_DIR_URL + "changes.csv";
    private static final String DELETIONS_CSV_URL = ADVISORIES_DIR_URL + "deletions.csv";
    private static final Set<String> ALLOWED_HOSTS = Set.of("security.access.redhat.com");
    private static final String RATE_LIMIT_KEY = "redhat_csaf";

    private static final int MAX_REDIRECTS = 3;

    /** item 6 — see class javadoc: real max observed 46,654,640 bytes (2024/rhsa-2024_9315.json,
     *  measured 2026-08-27). Deliberately NOT {@code SiemensCsafSyncService.MAX_DOCUMENT_BYTES}
     *  (10MB) — reusing it would silently drop 22 real documents as TOO_LARGE. */
    static final long MAX_DOCUMENT_BYTES = 64L * 1024 * 1024;
    private static final long MAX_HASH_BYTES = 4_096;
    /** Real {@code changes.csv} measured 1,551,137 bytes / 28,102 rows, {@code deletions.csv}
     *  smaller — 8MB leaves comfortable headroom for both. */
    private static final long MAX_CSV_BYTES = 8L * 1024 * 1024;
    private static final long MAX_TEXT_FILE_BYTES = 1_024; // archive_latest.txt is a one-line filename

    /** Decompression-bomb protection for the baseline archive (item 5) — see class javadoc. Default
     *  (production) values; instance fields below (not these constants directly) are what {@link
     *  #doSyncBaseline} actually checks, so a test can override them without a 50,000-entry/12GB
     *  real-scale fixture — see the test-only constructor. */
    static final long MAX_ARCHIVE_COMPRESSED_BYTES = 200L * 1024 * 1024; // real measured 103,391,443 bytes (2026-08-27)
    static final int DEFAULT_MAX_ARCHIVE_ENTRY_COUNT = 50_000; // real measured 27,930 documents (2026-08-27)
    static final long DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES = 12L * 1024 * 1024 * 1024; // real measured ~6.09GB raw JSON (plan §3/§9)

    /** Mirrors {@code SiemensCsafSyncService}'s per-run cap — delta only; baseline is one archive
     *  download, not per-document GETs, so no equivalent cap applies there. */
    static final int MAX_DOCUMENTS_PER_RUN = 2_000;

    private final RestClient csafSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final CsafDocumentUpsertService documentUpsertService;
    private final CsafAdvisoryRepository csafAdvisoryRepository;
    private final CsafSyncStateRepository syncStateRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Per-vendor "sync already running" guard (plan §5-4) — same rationale/scope as {@code
     *  SiemensCsafSyncService#running}. */
    private final AtomicBoolean running = new AtomicBoolean(false);

    private final int maxArchiveEntryCount;
    private final long maxPerEntryDecompressedBytes;
    private final long maxArchiveTotalDecompressedBytes;

    @org.springframework.beans.factory.annotation.Autowired
    public RedHatCsafSyncService(RestClient csafSyncRestClient, ExternalRegistryRateLimiter rateLimiter,
            CsafDocumentUpsertService documentUpsertService, CsafAdvisoryRepository csafAdvisoryRepository,
            CsafSyncStateRepository syncStateRepository) {
        this(csafSyncRestClient, rateLimiter, documentUpsertService, csafAdvisoryRepository, syncStateRepository,
                DEFAULT_MAX_ARCHIVE_ENTRY_COUNT, MAX_DOCUMENT_BYTES, DEFAULT_MAX_ARCHIVE_TOTAL_DECOMPRESSED_BYTES);
    }

    /** Test-only constructor (mirrors {@code GhsaSyncService}'s {@code expectedBaselineCount} seam)
     *  — lets a test exercise all three decompression-bomb bounds (item 5) with small, fast
     *  fixtures instead of a 50,000-entry/12GB real-scale archive. */
    RedHatCsafSyncService(RestClient csafSyncRestClient, ExternalRegistryRateLimiter rateLimiter,
            CsafDocumentUpsertService documentUpsertService, CsafAdvisoryRepository csafAdvisoryRepository,
            CsafSyncStateRepository syncStateRepository, int maxArchiveEntryCount,
            long maxPerEntryDecompressedBytes, long maxArchiveTotalDecompressedBytes) {
        this.csafSyncRestClient = csafSyncRestClient;
        this.rateLimiter = rateLimiter;
        this.documentUpsertService = documentUpsertService;
        this.csafAdvisoryRepository = csafAdvisoryRepository;
        this.syncStateRepository = syncStateRepository;
        this.maxArchiveEntryCount = maxArchiveEntryCount;
        this.maxPerEntryDecompressedBytes = maxPerEntryDecompressedBytes;
        this.maxArchiveTotalDecompressedBytes = maxArchiveTotalDecompressedBytes;
    }

    public record SyncResult(int upserted, int failed, boolean alreadyRunning) {
    }

    /** Archive-streamed full reload, ignoring any existing cursor for the documents themselves (the
     *  changes/deletions cursor IS advanced afterward, to the archive's own as-of time — see class
     *  javadoc) — manually triggered only, see {@code AdminController}, mirroring {@code
     *  SiemensCsafSyncService#syncBaseline}'s "never {@code @Scheduled}" precedent. */
    public SyncResult syncBaseline() {
        return sync(this::doSyncBaseline);
    }

    /** {@code changes.csv} (adds/updates) then {@code deletions.csv} (tombstones), each only entries
     *  newer than their own half of the encoded cursor — safe to run routinely; see {@code
     *  RedHatCsafScheduledSync}. */
    public SyncResult syncDelta() {
        return sync(this::doSyncDelta);
    }

    private SyncResult sync(java.util.function.Supplier<SyncResult> body) {
        if (!running.compareAndSet(false, true)) {
            log.warn("Red Hat CSAF sync skipped: another sync for this vendor is already running");
            return new SyncResult(0, 0, true);
        }
        try {
            return body.get();
        } finally {
            running.set(false);
        }
    }

    // ------------------------------------------------------------------ baseline ----------------

    private SyncResult doSyncBaseline() {
        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome latestOutcome = fetchBounded(ARCHIVE_LATEST_URL, MAX_TEXT_FILE_BYTES);
        if (latestOutcome.status() != FetchStatus.OK) {
            log.error("Red Hat CSAF baseline sync aborted: could not fetch archive_latest.txt ({})", latestOutcome.status());
            return new SyncResult(0, 0, false);
        }
        String archiveFileName = new String(latestOutcome.body(), StandardCharsets.UTF_8).trim();
        if (archiveFileName.isBlank() || archiveFileName.contains("/") || !archiveFileName.endsWith(".tar.zst")) {
            log.error("Red Hat CSAF baseline sync aborted: archive_latest.txt has unexpected content: '{}'", archiveFileName);
            return new SyncResult(0, 0, false);
        }
        String archiveUrl = ADVISORIES_DIR_URL + archiveFileName;
        String archiveHashUrl = archiveUrl + ".sha256";

        // Archive download's initial request is paced; the ~103MB body itself is one download, not
        // per-request paced (class javadoc — nothing to pace a single download against).
        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome archiveOutcome = fetchBounded(archiveUrl, MAX_ARCHIVE_COMPRESSED_BYTES);
        if (archiveOutcome.status() != FetchStatus.OK) {
            log.error("Red Hat CSAF baseline sync aborted: could not download archive {} ({})", archiveUrl, archiveOutcome.status());
            return new SyncResult(0, 0, false);
        }

        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome hashOutcome = fetchBounded(archiveHashUrl, MAX_HASH_BYTES);
        if (hashOutcome.status() != FetchStatus.OK) {
            log.error("Red Hat CSAF baseline sync aborted: could not fetch archive hash sidecar {} ({})", archiveHashUrl, hashOutcome.status());
            return new SyncResult(0, 0, false);
        }
        if (!verifySha256(archiveOutcome.body(), hashOutcome.body())) {
            log.error("Red Hat CSAF baseline sync aborted: archive {} failed SHA-256 verification — not processing "
                    + "an unverified archive (plan §6 / §0-1 principle 2)", archiveUrl);
            return new SyncResult(0, 0, false);
        }

        int upserted = 0;
        int failed = 0;
        int entryCount = 0;
        long totalDecompressedBytes = 0;
        OffsetDateTime archiveAsOf = archiveOutcome.lastModified() != null
                ? archiveOutcome.lastModified()
                // Conservative fallback if the response ever lacks a Last-Modified header: overlap
                // by a full day rather than risk a delta run skipping something the archive missed.
                : OffsetDateTime.now(ZoneOffset.UTC).minusDays(1);

        try (InputStream byteIn = new ByteArrayInputStream(archiveOutcome.body());
                ZstdCompressorInputStream zstdIn = new ZstdCompressorInputStream(byteIn);
                TarArchiveInputStream tarIn = new TarArchiveInputStream(zstdIn)) {
            TarArchiveEntry entry;
            while ((entry = tarIn.getNextEntry()) != null) {
                entryCount++;
                if (entryCount > maxArchiveEntryCount) {
                    log.error("Red Hat CSAF baseline sync ABORTED mid-archive: entry count exceeded {} — "
                            + "decompression-bomb protection (item 5), not a per-document skip. {} upserted so "
                            + "far are real, verified documents and are NOT rolled back; sync state is left "
                            + "untouched so the next run starts baseline fresh.", maxArchiveEntryCount, upserted);
                    return new SyncResult(upserted, failed, false);
                }
                if (entry.isDirectory()) {
                    continue; // no bytes to read/bound for a directory entry
                }
                // REVISE item 6 (senior review 2026-08-27): EVERY non-directory entry is read/bounded
                // here now, not just .json ones — getNextEntry() alone doesn't consume an entry's
                // bytes, so a non-.json entry used to advance the tar stream (via the zstd decoder)
                // without ever being checked against either size bound, a decompression-bomb hole for
                // a maliciously/corrupted-oversized non-.json entry. Non-.json content is still
                // discarded (never parsed/upserted) — only READ and COUNTED against both bounds.
                boolean isJsonEntry = entry.getName().endsWith(".json");
                byte[] bytes = readBoundedEntry(tarIn, maxPerEntryDecompressedBytes);
                if (bytes == null) {
                    log.error("Red Hat CSAF baseline sync ABORTED mid-archive: entry {} exceeded the {}-byte "
                            + "per-entry decompression bound — decompression-bomb protection (item 5). {} "
                            + "upserted so far are real, verified documents and are NOT rolled back.",
                            entry.getName(), maxPerEntryDecompressedBytes, upserted);
                    return new SyncResult(upserted, failed, false);
                }
                totalDecompressedBytes += bytes.length;
                if (totalDecompressedBytes > maxArchiveTotalDecompressedBytes) {
                    log.error("Red Hat CSAF baseline sync ABORTED mid-archive: cumulative decompressed size "
                            + "exceeded {} bytes — decompression-bomb protection (item 5). {} upserted so far "
                            + "are real, verified documents and are NOT rolled back.",
                            maxArchiveTotalDecompressedBytes, upserted);
                    return new SyncResult(upserted, failed, false);
                }
                if (!isJsonEntry) {
                    continue; // drained and counted against both bounds above — content discarded
                }

                try {
                    String trackingId = documentUpsertService.upsertCsafDocument(VENDOR, objectMapper.readTree(bytes));
                    if (trackingId != null) {
                        upserted++;
                    } else {
                        failed++;
                    }
                } catch (Exception e) {
                    log.warn("Red Hat CSAF baseline sync: failed to parse/upsert archive entry {}", entry.getName(), e);
                    failed++;
                }
                if (upserted > 0 && upserted % 5000 == 0) {
                    log.info("Red Hat CSAF baseline sync progress: {} upserted, {} failed", upserted, failed);
                }
            }
        } catch (IOException e) {
            log.error("Red Hat CSAF baseline sync failed reading the archive after upserting {} records", upserted, e);
            return new SyncResult(upserted, failed, false);
        }

        // Advance BOTH halves of the encoded cursor to the archive's own as-of time (class javadoc):
        // the archive already reflects every add/update/deletion up to that instant, so the next
        // delta run only needs changes.csv/deletions.csv rows strictly after it.
        CsafSyncState state = loadState();
        state.setLastCursor(encodeCursor(archiveAsOf, archiveAsOf));
        state.setLastSyncedAt(OffsetDateTime.now());
        syncStateRepository.save(state);

        log.info("Red Hat CSAF baseline sync complete: {} upserted, {} failed, {} archive entries scanned, cursor={}",
                upserted, failed, entryCount, state.getLastCursor());
        return new SyncResult(upserted, failed, false);
    }

    /** Reads one already-open tar entry's bytes, bounded — returns null (caller aborts the whole
     *  run, item 5) rather than trusting the entry's own declared size, which a malicious/corrupted
     *  archive could misstate. */
    private byte[] readBoundedEntry(InputStream entryStream, long maxBytes) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = entryStream.read(chunk)) != -1) {
            total += read;
            if (total > maxBytes) {
                return null;
            }
            buffer.write(chunk, 0, read);
        }
        return buffer.toByteArray();
    }

    // -------------------------------------------------------------------- delta -----------------

    // Package-private (not private), same as DEFAULT_MAX_ARCHIVE_ENTRY_COUNT etc. above — lets
    // RedHatCsafSyncServiceTest exercise capWithTiedTimestampExtension directly with small synthetic
    // lists rather than needing a genuine 2,000+-row changes.csv fixture (REVISE item 4).
    record ChangeEntry(String path, OffsetDateTime timestamp) {
    }

    private record Cursor(OffsetDateTime changesCursor, OffsetDateTime deletionsCursor) {
    }

    /** REVISE item 4 (senior review 2026-08-27, HIGH): a bare {@code entries.subList(0, cap)}
     *  truncation is a HARD cutoff mid-timestamp-group — the real {@code changes.csv} measured 18,422
     *  of 28,103 rows sharing a timestamp with at least one other row (largest tie group: 10), and the
     *  strict {@code isAfter(cursor)} filter used to decide "already processed" means anything at
     *  exactly the truncation boundary's timestamp, positioned after the cutoff index, is silently
     *  skipped FOREVER on every future run (never {@code isAfter} a cursor already sitting at that same
     *  timestamp). {@code entries} must already be sorted ascending by timestamp. Extends the cutoff
     *  forward (a soft floor, not a hard ceiling) to include every entry sharing the boundary
     *  timestamp — {@code cap} is a minimum-work-per-run guarantee, not a hard row-count ceiling. */
    // REVISE follow-up item 5 (senior review 2026-08-27): capWithTiedTimestampExtension is
    // intentionally unbounded — correctly avoiding a split tied-timestamp group matters more than any
    // fixed ceiling — but that means a real bulk republish can silently balloon one delta run to fetch
    // far more documents than MAX_DOCUMENTS_PER_RUN with no operational signal. Escalate to a WARN
    // (instead of INFO) once the extension itself is large enough to plausibly indicate that, so it
    // shows up without needing INFO-level logs enabled.
    private static final int CAP_EXTENSION_WARN_THRESHOLD = 100;

    List<ChangeEntry> capWithTiedTimestampExtension(List<ChangeEntry> entries, int cap) {
        if (entries.size() <= cap) {
            return entries;
        }
        OffsetDateTime boundaryTimestamp = entries.get(cap - 1).timestamp();
        int end = cap;
        while (end < entries.size() && entries.get(end).timestamp().equals(boundaryTimestamp)) {
            end++;
        }
        if (end > cap) {
            int extension = end - cap;
            if (extension > CAP_EXTENSION_WARN_THRESHOLD) {
                log.warn("Red Hat CSAF delta sync: extended the {}-entry per-run cap by {} additional entries "
                        + "sharing the boundary timestamp {} — this run will process {} documents in total, "
                        + "well beyond the configured cap (REVISE item 4/5) — possible bulk republish",
                        cap, extension, boundaryTimestamp, end);
            } else {
                log.info("Red Hat CSAF delta sync: extended the {}-entry per-run cap by {} additional entries "
                        + "sharing the boundary timestamp {} — a hard cutoff mid-timestamp-group would silently "
                        + "and permanently skip them (REVISE item 4)", cap, extension, boundaryTimestamp);
            }
        }
        return entries.subList(0, end);
    }

    private SyncResult doSyncDelta() {
        CsafSyncState state = loadState();
        Cursor cursor = decodeCursor(state.getLastCursor());
        if (cursor.changesCursor() == null) {
            // REVISE item 10 (senior review 2026-08-27): a null changes-cursor means baseline was
            // never run (or csaf_sync_state was reset) — without this warning, a delta run would
            // silently process only the OLDEST 2,000-of-28,102 entries with no indication anything is
            // wrong, needing roughly 15 daily runs to catch up to real time.
            log.warn("Red Hat CSAF delta sync: changes cursor is null (no prior baseline sync recorded, or "
                    + "csaf_sync_state was reset) — this run will only process the OLDEST eligible entries up "
                    + "to the {}-entry per-run cap, NOT a full catch-up. Run syncBaseline (the archive-based "
                    + "full sync) first, or expect roughly ~15 daily delta runs to reach real time.",
                    MAX_DOCUMENTS_PER_RUN);
        }

        int upserted = 0;
        int failed = 0;

        // --- changes.csv: adds/updates -------------------------------------------------------
        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome changesOutcome = fetchBounded(CHANGES_CSV_URL, MAX_CSV_BYTES);
        OffsetDateTime advancedChangesCursor = cursor.changesCursor();
        if (changesOutcome.status() != FetchStatus.OK) {
            log.error("Red Hat CSAF delta sync: could not fetch changes.csv ({}) — skipping the changes half "
                    + "of this run entirely (deletions.csv is still attempted below)", changesOutcome.status());
        } else {
            List<ChangeEntry> entries = parseCsv(changesOutcome.body()).stream()
                    .filter(e -> cursor.changesCursor() == null || e.timestamp().isAfter(cursor.changesCursor()))
                    .sorted(Comparator.comparing(ChangeEntry::timestamp)) // ascending — plan §7
                    .toList();
            if (entries.size() > MAX_DOCUMENTS_PER_RUN) {
                log.info("Red Hat CSAF delta sync: {} eligible changed entries exceeds the per-run cap of {} — "
                        + "processing the oldest {} (plus any tied-timestamp extension, REVISE item 4) now, "
                        + "the remainder next run", entries.size(), MAX_DOCUMENTS_PER_RUN, MAX_DOCUMENTS_PER_RUN);
                entries = capWithTiedTimestampExtension(entries, MAX_DOCUMENTS_PER_RUN);
            }

            boolean sawFailure = false;
            for (ChangeEntry entry : entries) {
                rateLimiter.awaitTurn(RATE_LIMIT_KEY);
                FetchOutcome docOutcome = fetchBounded(ADVISORIES_DIR_URL + entry.path(), MAX_DOCUMENT_BYTES);
                if (docOutcome.status() == FetchStatus.RATE_LIMITED) {
                    log.error("Red Hat CSAF delta sync aborting changes.csv processing: got a block-signal HTTP "
                            + "status fetching {} — cursor left at the last successfully processed entry.", entry.path());
                    break;
                }
                if (docOutcome.status() != FetchStatus.OK) {
                    failed++;
                    sawFailure = true;
                    continue;
                }

                rateLimiter.awaitTurn(RATE_LIMIT_KEY);
                FetchOutcome hashOutcome = fetchBounded(ADVISORIES_DIR_URL + entry.path() + ".sha256", MAX_HASH_BYTES);
                if (hashOutcome.status() == FetchStatus.RATE_LIMITED) {
                    log.error("Red Hat CSAF delta sync aborting changes.csv processing: got a block-signal HTTP "
                            + "status fetching the hash sidecar for {} — cursor left at the last successfully "
                            + "processed entry.", entry.path());
                    break;
                }
                if (hashOutcome.status() != FetchStatus.OK || !verifySha256(docOutcome.body(), hashOutcome.body())) {
                    log.warn("Red Hat CSAF delta sync: {} failed hash verification or its sidecar could not be "
                            + "fetched — skipping, cursor not advanced", entry.path());
                    failed++;
                    sawFailure = true;
                    continue;
                }

                try {
                    String trackingId = documentUpsertService.upsertCsafDocument(VENDOR, objectMapper.readTree(docOutcome.body()));
                    if (trackingId == null) {
                        failed++;
                        sawFailure = true;
                        continue;
                    }
                    upserted++;
                } catch (Exception e) {
                    log.warn("Red Hat CSAF delta sync: failed to parse/upsert {}", entry.path(), e);
                    failed++;
                    sawFailure = true;
                    continue;
                }

                // Per-entry checkpoint (plan §7) — gated on !sawFailure, same discipline as
                // SiemensCsafSyncService: once any entry in this run has failed, no later entry's
                // success may advance the cursor past it.
                if (!sawFailure) {
                    advancedChangesCursor = entry.timestamp();
                    state.setLastCursor(encodeCursor(advancedChangesCursor, cursor.deletionsCursor()));
                    state.setLastSyncedAt(OffsetDateTime.now());
                    syncStateRepository.save(state);
                }
            }
        }

        // --- deletions.csv: tombstones ---------------------------------------------------------
        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome deletionsOutcome = fetchBounded(DELETIONS_CSV_URL, MAX_CSV_BYTES);
        OffsetDateTime advancedDeletionsCursor = cursor.deletionsCursor();
        if (deletionsOutcome.status() != FetchStatus.OK) {
            log.error("Red Hat CSAF delta sync: could not fetch deletions.csv ({}) — a withdrawn/retracted "
                    + "advisory may remain in the local mirror until a future run consumes it (plan §7)", deletionsOutcome.status());
        } else {
            List<ChangeEntry> entries = parseCsv(deletionsOutcome.body()).stream()
                    .filter(e -> cursor.deletionsCursor() == null || e.timestamp().isAfter(cursor.deletionsCursor()))
                    .sorted(Comparator.comparing(ChangeEntry::timestamp)) // ascending — plan §7
                    .toList();
            if (entries.size() > MAX_DOCUMENTS_PER_RUN) {
                entries = capWithTiedTimestampExtension(entries, MAX_DOCUMENTS_PER_RUN); // REVISE item 4
            }

            boolean sawDeletionFailure = false;
            for (ChangeEntry entry : entries) {
                String trackingId = deriveTrackingIdFromPath(entry.path());
                if (trackingId == null) {
                    log.warn("Red Hat CSAF delta sync: could not derive a tracking id from deletions.csv path "
                            + "'{}' — skipping", entry.path());
                    failed++;
                    sawDeletionFailure = true;
                    continue;
                }
                try {
                    csafAdvisoryRepository.deleteByVendorAndTrackingId(VENDOR, trackingId);
                } catch (Exception e) {
                    log.warn("Red Hat CSAF delta sync: failed to delete {} ({})", trackingId, entry.path(), e);
                    failed++;
                    sawDeletionFailure = true;
                    continue;
                }
                if (!sawDeletionFailure) {
                    advancedDeletionsCursor = entry.timestamp();
                    state.setLastCursor(encodeCursor(advancedChangesCursor, advancedDeletionsCursor));
                    state.setLastSyncedAt(OffsetDateTime.now());
                    syncStateRepository.save(state);
                }
            }
        }

        log.info("Red Hat CSAF delta sync complete: {} upserted, {} failed, cursor={}", upserted, failed, state.getLastCursor());
        return new SyncResult(upserted, failed, false);
    }

    private CsafSyncState loadState() {
        return syncStateRepository.findById(VENDOR).orElseGet(() -> new CsafSyncState(VENDOR));
    }

    /** {@code "<changesIso>|<deletionsIso>"} — either half may be blank (encoded as an empty
     *  segment). See class javadoc for why this reuses {@code last_cursor} rather than a schema
     *  change. */
    private String encodeCursor(OffsetDateTime changesCursor, OffsetDateTime deletionsCursor) {
        return (changesCursor != null ? changesCursor.toString() : "") + "|" + (deletionsCursor != null ? deletionsCursor.toString() : "");
    }

    private Cursor decodeCursor(String raw) {
        if (raw == null || raw.isBlank()) {
            return new Cursor(null, null);
        }
        String[] parts = raw.split("\\|", -1);
        OffsetDateTime changes = parts.length > 0 ? parseTimestamp(parts[0]) : null;
        OffsetDateTime deletions = parts.length > 1 ? parseTimestamp(parts[1]) : null;
        return new Cursor(changes, deletions);
    }

    /** {@code 2024/rhsa-2024_9315.json} -> {@code RHSA-2024:9315} — confirmed live 2026-08-27 against
     *  real documents that this is exactly how the path maps to {@code document.tracking.id}
     *  (uppercase the filename stem, replace the first {@code _} with {@code :}). Used only for
     *  {@code deletions.csv}, where there is no document body left to read the real tracking id from
     *  (it has already been removed from the advisories directory). */
    private String deriveTrackingIdFromPath(String path) {
        if (path == null) {
            return null;
        }
        int lastSlash = path.lastIndexOf('/');
        String fileName = lastSlash >= 0 ? path.substring(lastSlash + 1) : path;
        if (!fileName.endsWith(".json")) {
            return null;
        }
        String stem = fileName.substring(0, fileName.length() - ".json".length());
        int underscoreIdx = stem.indexOf('_');
        if (underscoreIdx < 0) {
            return null;
        }
        return (stem.substring(0, underscoreIdx) + ":" + stem.substring(underscoreIdx + 1)).toUpperCase(Locale.ROOT);
    }

    /** REVISE item 10 (senior review 2026-08-27): {@code changes.csv}/{@code deletions.csv} path
     *  values are used unvalidated in URL construction ({@link #fetchBounded}) and as a DELETE
     *  query's tracking-id parameter ({@link #deriveTrackingIdFromPath}) — impact is already bounded
     *  (HTTPS + host allowlist + parameterized SQL prevents real exploitation), but this shape check
     *  is defense in depth against a malformed/malicious CSV row, matching the real observed path
     *  convention (e.g. {@code 2024/rhsa-2024_9315.json}). */
    private static final java.util.regex.Pattern CSV_PATH_SHAPE = java.util.regex.Pattern.compile("^\\d{4}/[a-z0-9_.\\-]+\\.json$");

    private List<ChangeEntry> parseCsv(byte[] body) {
        List<ChangeEntry> entries = new ArrayList<>();
        CSVFormat format = CSVFormat.DEFAULT.builder().setHeader((String[]) null).build();
        try (CSVParser parser = CSVParser.parse(
                new InputStreamReader(new ByteArrayInputStream(body), StandardCharsets.UTF_8), format)) {
            for (CSVRecord record : parser) {
                if (record.size() < 2) {
                    continue;
                }
                String path = record.get(0);
                OffsetDateTime timestamp = parseTimestamp(record.get(1));
                if (path == null || path.isBlank() || timestamp == null) {
                    continue;
                }
                if (!CSV_PATH_SHAPE.matcher(path).matches()) {
                    log.warn("Red Hat CSAF sync: changes/deletions CSV row has an unexpected path shape '{}' — "
                            + "skipping (defense in depth, REVISE item 10)", path);
                    continue;
                }
                entries.add(new ChangeEntry(path, timestamp));
            }
        } catch (IOException e) {
            log.warn("Red Hat CSAF sync: failed to parse a changes/deletions CSV", e);
        }
        return entries;
    }

    private boolean verifySha256(byte[] data, byte[] hashSidecarBytes) {
        String sidecarText = new String(hashSidecarBytes, StandardCharsets.US_ASCII).trim();
        if (sidecarText.isBlank()) {
            return false;
        }
        // Real Red Hat sidecar format confirmed live: "<hex>  <filename>" (two spaces) — only the
        // first whitespace-delimited token is the digest.
        String expectedHex = sidecarText.split("\\s+")[0].toLowerCase(Locale.ROOT);
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String actualHex = HexFormat.of().formatHex(digest.digest(data));
            return actualHex.equalsIgnoreCase(expectedHex);
        } catch (NoSuchAlgorithmException e) {
            return false;
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

    // --- SSRF-hardened fetch (plan §6): https-only, host allowlist re-checked on every redirect
    // hop (redirects are never auto-followed by csafSyncRestClient — see RestClientConfig), a
    // bounded redirect count, and a bounded response size (read manually rather than trusted from
    // Content-Length). Mirrors SiemensCsafSyncService's fetch machinery, extended to also surface
    // the Last-Modified response header (used only by the archive download — see doSyncBaseline). ---

    private enum FetchStatus {
        OK, REJECTED_SCHEME_OR_HOST, TOO_MANY_REDIRECTS, TOO_LARGE, RATE_LIMITED, HTTP_ERROR, TRANSPORT_ERROR
    }

    private record FetchOutcome(FetchStatus status, byte[] body, Integer httpStatus, OffsetDateTime lastModified) {
        static FetchOutcome ok(byte[] body, OffsetDateTime lastModified) {
            return new FetchOutcome(FetchStatus.OK, body, null, lastModified);
        }
        static FetchOutcome of(FetchStatus status, Integer httpStatus) {
            return new FetchOutcome(status, null, httpStatus, null);
        }
    }

    private FetchOutcome fetchBounded(String url, long maxBytes) {
        return fetchBounded(url, maxBytes, MAX_REDIRECTS);
    }

    private FetchOutcome fetchBounded(String url, long maxBytes, int redirectsRemaining) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            return FetchOutcome.of(FetchStatus.REJECTED_SCHEME_OR_HOST, null);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || !ALLOWED_HOSTS.contains(uri.getHost())) {
            log.warn("Red Hat CSAF sync: rejecting fetch of {} — not https or not an allowlisted host", url);
            return FetchOutcome.of(FetchStatus.REJECTED_SCHEME_OR_HOST, null);
        }

        try {
            return csafSyncRestClient.get().uri(uri).exchange((request, response) -> {
                HttpStatusCode status = response.getStatusCode();
                if (status.is3xxRedirection()) {
                    String location = response.getHeaders().getFirst(HttpHeaders.LOCATION);
                    if (location == null) {
                        return FetchOutcome.of(FetchStatus.HTTP_ERROR, status.value());
                    }
                    if (redirectsRemaining <= 0) {
                        log.warn("Red Hat CSAF sync: too many redirects fetching {}", url);
                        return FetchOutcome.of(FetchStatus.TOO_MANY_REDIRECTS, status.value());
                    }
                    URI redirectTarget = uri.resolve(location);
                    return fetchBounded(redirectTarget.toString(), maxBytes, redirectsRemaining - 1);
                }
                if (status.value() == 429 || status.value() == 403) {
                    return FetchOutcome.of(FetchStatus.RATE_LIMITED, status.value());
                }
                if (!status.is2xxSuccessful()) {
                    return FetchOutcome.of(FetchStatus.HTTP_ERROR, status.value());
                }
                byte[] body = readBounded(response.getBody(), maxBytes);
                if (body == null) {
                    return FetchOutcome.of(FetchStatus.TOO_LARGE, status.value());
                }
                return FetchOutcome.ok(body, parseHttpDate(response.getHeaders().getFirst(HttpHeaders.LAST_MODIFIED)));
            });
        } catch (Exception e) {
            log.warn("Red Hat CSAF sync: transport error fetching {}", url, e);
            return FetchOutcome.of(FetchStatus.TRANSPORT_ERROR, null);
        }
    }

    private OffsetDateTime parseHttpDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    /** Reads at most {@code maxBytes} from {@code in} — returns null (caller treats as "too large")
     *  if the stream still had data past that point, rather than trusting a possibly-absent/lying
     *  {@code Content-Length} header (plan §6). */
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
