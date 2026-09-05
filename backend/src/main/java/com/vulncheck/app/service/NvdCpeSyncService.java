package com.vulncheck.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.CpeDictionarySyncState;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.CpeDictionarySyncStateRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.nvd.NvdUriBuilder;
import java.net.URI;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Mirrors (a subset of) the NVD CPE Dictionary into the local {@code cpe_dictionary} table, which
 * Stage1 Tier1 then fuzzy-matches against via pg_trgm instead of hitting NVD synchronously per
 * product lookup.
 *
 * <p>Works without an API key (5 req/30s). If the calling user has registered an NVD key via
 * {@code UserApiKeyService}, callers pass it through here and it's sent as the {@code apiKey}
 * request header, raising the limit to 50 req/30s (see {@link NvdRateLimiter}) — a full mirror
 * (~1.3M entries) still isn't practical even with a key, so {@link #syncByKeyword} remains the
 * practical entry point, while {@link #syncAllAndRelease} is the same pagination loop with no
 * keyword filter for when a full mirror is actually wanted.
 *
 * <p>{@link #syncAllAndRelease} returns a {@link SyncOutcome} rather than a bare upserted count so
 * callers can tell a clean finish from an early abort (a page fetch failing part-way through a
 * ~180-page, multi-hour sync) — treating both as "finished" made an aborted, only-partially-synced
 * dictionary look complete in the admin/startup logs, silently degrading Stage1 accuracy.
 *
 * <p><b>Delta sync</b> (closed-mode backlog item 283): {@link #syncDeltaAndRelease} is {@link
 * #syncAllAndRelease}'s sibling for the weekly scheduled resync ({@code
 * CpeDictionaryScheduledResync}) — instead of re-pulling the whole ~1.8M-entry dictionary (~103
 * minutes measured), it asks NVD for only the CPEs modified since the last successful unfiltered
 * sync, via the {@code lastModStartDate}/{@code lastModEndDate} filters {@link #fetchPage} already
 * supports (same API parameters {@link com.vulncheck.app.service.NvdCveSyncService} uses for its
 * own delta side). {@link #hasCompletedInitialSync()} is the guard callers (the scheduler) must
 * check first: there is nothing to diff against until a full sync has completed at least once, so
 * every sync stays a full {@link #syncAllAndRelease} until then. Both the initial-sync flag and the
 * delta cursor live in {@link CpeDictionarySyncState} (see {@code
 * V42__cpe_dictionary_sync_state.sql}), set only when an <em>unfiltered</em> sync (full or delta,
 * never {@link #syncByKeyword}'s keyword-filtered subset) completes cleanly.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NvdCpeSyncService {

    private static final String NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    /** NVD's documented maximum for this endpoint. At ~1.8M total CPEs this is the difference
     *  between 182 requests and 908 — and since each request pays a fixed rate-limit wait
     *  (6.5s unkeyed), the page count, not the byte count, dominates total sync time. */
    private static final int RESULTS_PER_PAGE = 10000;
    /** NVD's documented maximum span for {@code lastModStartDate}/{@code lastModEndDate} — same
     *  cap {@link NvdCveSyncService#WINDOW_DAYS} applies to the CVE 2.0 endpoint; the CPE 2.0
     *  endpoint shares the same underlying date-range restriction. */
    private static final int MAX_LAST_MOD_WINDOW_DAYS = 120;
    /** Clock-skew / mid-sync-change safety margin applied to the delta cursor — re-fetching a small
     *  overlap is harmless (every write here is an upsert), missing a just-modified CPE isn't. Same
     *  value and rationale as {@link NvdCveSyncService#DELTA_SAFETY_MARGIN}. */
    private static final Duration DELTA_SAFETY_MARGIN = Duration.ofHours(2);
    /** Singleton row id for {@link CpeDictionarySyncState} — same {@code CHECK(id = 1)} convention
     *  as {@code cve_org_sync_state}/{@code nvd_cve_sync_state}. */
    private static final short SYNC_STATE_ID = 1;

    private final RestClient externalApiRestClient;
    private final RestClient nvdSyncRestClient;
    private final CpeDictionaryRepository cpeDictionaryRepository;
    private final NvdRateLimiter nvdRateLimiter;
    private final CpeDictionarySyncStateRepository cpeDictionarySyncStateRepository;

    /** Result of an unfiltered full-dictionary sync. {@code completed} is false when the
     *  pagination loop had to abort early (a page fetch failed after {@code startIndex}
     *  advanced past 0) rather than exhausting {@code totalResults} — callers must not log this
     *  as a plain success, since the dictionary is then only partially synced. */
    public record SyncOutcome(int upserted, boolean completed) {
    }

    /** Sync-in-progress guard, shared across every caller of {@link #tryBeginFullSync} — originally
     *  just the full-sync guard (admin-triggered and startup-triggered full syncs), now also shared
     *  by {@link #syncDeltaAndRelease} (closed-mode backlog item 283): both hit the same {@link
     *  NvdRateLimiter} and the same {@code cpe_dictionary} upserts, so only one sync of either kind
     *  may run at a time no matter which trigger started it. Matches this codebase's existing
     *  convention of an {@code AtomicBoolean running} guard held by the service itself (see {@code
     *  SiemensCsafSyncService}, {@code GhsaSyncService}, {@code OsvSyncService}), rather than by
     *  each caller separately. The CAS in {@link #tryBeginFullSync} is itself the acquisition —
     *  callers must not check-then-call, since that would reopen the exact TOCTOU window this
     *  guard exists to close. */
    private final AtomicBoolean fullSyncRunning = new AtomicBoolean(false);

    /**
     * Syncs only CPEs matching the given keyword — the practical way to populate/test locally.
     *
     * @throws IllegalArgumentException if {@code keyword} is null or blank. A blank keyword makes
     *         {@link #fetchPage} omit the {@code keywordSearch} query parameter entirely, silently
     *         turning what looks like a scoped, single-keyword sync into a full, unfiltered
     *         ~1.8M-entry mirror sync — closed-mode backlog item 330. {@code
     *         AdminController#sync} exposes this as an admin-form POST with only client-side
     *         {@code required} validation, so a direct POST with a blank/whitespace keyword would
     *         otherwise run a ~103-minute full sync on the Tomcat request thread itself, without
     *         ever going through {@link #tryBeginFullSync}'s guard.
     */
    public int syncByKeyword(String keyword, Optional<String> apiKey) {
        requireNonBlankKeyword(keyword);
        return sync(keyword, apiKey, null, null).upserted();
    }

    private static void requireNonBlankKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            throw new IllegalArgumentException("keyword must not be blank — a blank keyword would run an "
                    + "unfiltered full sync instead of a scoped one");
        }
    }

    /**
     * Attempts to reserve the sync slot; returns {@code true} only for the caller that wins the
     * race. Callers that get {@code false} must not proceed to call {@link #syncAllAndRelease} or
     * {@link #syncDeltaAndRelease} — another sync (admin-triggered, startup-triggered, or the
     * weekly scheduler, full or delta) is already in flight and would otherwise double the upsert
     * load on {@code cpe_dictionary} and halve the shared {@link NvdRateLimiter}'s effective
     * throughput for every other concurrent caller.
     */
    public boolean tryBeginFullSync() {
        return fullSyncRunning.compareAndSet(false, true);
    }

    /**
     * Releases the sync guard without ever having run a sync. For callers of {@link
     * #tryBeginFullSync} only, and only when they are certain the acquired slot will never reach
     * {@link #syncAllAndRelease}/{@link #syncDeltaAndRelease} — e.g. spawning or starting the
     * background worker thread itself threw, so that method's own {@code finally}-block release
     * will never run. Without this escape hatch, that failure mode leaves {@code fullSyncRunning}
     * stuck {@code true} until the process restarts, permanently locking out every trigger
     * (startup, admin screen, weekly scheduler — task-backlog items 81/136/141). Calling this after
     * a sync legitimately reached {@link #syncAllAndRelease}/{@link #syncDeltaAndRelease} would let
     * a second, concurrent sync start against the same NVD rate limit and {@code cpe_dictionary}
     * table, so callers must not call it once the worker thread has actually started running.
     *
     * <p>A second legitimate call site (senior-reviewer REVISE, PR #207 round 1): {@code
     * CpeDictionaryScheduledResync#runScheduledResync} — running <em>on</em> the already-spawned
     * worker thread, after {@link #tryBeginFullSync} already won the slot — calls this if {@link
     * #hasCompletedInitialSync()} itself throws (a transient DB read failure), for exactly the same
     * reason: that thread's own path into {@link #syncAllAndRelease}/{@link #syncDeltaAndRelease}
     * is what was supposed to release the guard, and a failure before reaching either one leaves
     * this method as the only remaining release path. Not limited to "worker thread never started"
     * the way the rest of this javadoc originally described it — any code path on the guard-holding
     * thread that can determine, with certainty, that neither release-bearing method will be
     * reached is a legitimate caller.
     */
    public void releaseFullSyncGuard() {
        fullSyncRunning.set(false);
    }

    /**
     * Full mirror sync, no keyword filter. Slow (rate-limited) — intended for a scheduled/off-hours
     * run. Callers must only invoke this after {@link #tryBeginFullSync} returned {@code true}; the
     * slot is released here unconditionally (success or exception) so a failed sync doesn't
     * permanently wedge the guard.
     */
    public SyncOutcome syncAllAndRelease(Optional<String> apiKey) {
        try {
            return sync(null, apiKey, null, null);
        } finally {
            fullSyncRunning.set(false);
        }
    }

    /**
     * Whether the NVD CPE Dictionary mirror has ever completed an unfiltered sync (full or delta)
     * — closed-mode backlog item 283. {@code CpeDictionaryScheduledResync} checks this first to
     * decide whether its weekly run must be a full {@link #syncAllAndRelease} (nothing to diff
     * against yet) or can be a {@link #syncDeltaAndRelease}. Backed by {@link
     * CpeDictionarySyncState}, deliberately not a {@code cpe_dictionary} row-count check: a sync
     * that aborted early ({@link SyncOutcome#completed()} false) still upserts a partial set of
     * rows, and a row-count check would misread that partial dictionary as "already fully synced
     * once", permanently skipping the full resync it still actually needs.
     */
    public boolean hasCompletedInitialSync() {
        return cpeDictionarySyncStateRepository.findById(SYNC_STATE_ID)
                .map(CpeDictionarySyncState::isInitialSyncCompleted)
                .orElse(false);
    }

    /**
     * Whether the NVD CPE Dictionary mirror's most recent unfiltered sync (full or delta, same
     * {@link CpeDictionarySyncState#getLastSyncedAt()} high-water mark {@link #hasCompletedInitialSync()}
     * and {@link #resolveDeltaCursor} already use) is younger than {@code maxAge} — closed-mode
     * backlog item 330. {@code CpeDictionaryBootstrapSync} calls this to decide whether its
     * startup-triggered full sync is even necessary: once the weekly delta chain ({@link
     * #syncDeltaAndRelease}, {@code CpeDictionaryScheduledResync}) is running healthily, the mirror
     * never actually goes stale between deltas — delta sync is structurally gap-free (each tick's
     * window starts from the previous tick's own end, minus {@link #DELTA_SAFETY_MARGIN}), so
     * forcing a redundant ~103-minute full re-pull every time a long-lived process happens to
     * restart (or every boot, if {@code CPE_FULL_SYNC_ON_STARTUP} is left on) is pure loss: same
     * NVD rate-limit load, same {@code cpe_dictionary} upsert traffic, zero additional coverage over
     * what the delta chain already guarantees.
     *
     * <p>Returns {@code false} (never "fresh enough") when no unfiltered sync has ever completed,
     * or {@link CpeDictionarySyncState#getLastSyncedAt()} is somehow still null despite {@code
     * initialSyncCompleted} being true (the same defensive case {@link #resolveDeltaCursor} already
     * guards) — both cases mean there is nothing to trust as "recent" yet, so callers must not skip
     * their full sync.
     */
    public boolean isMirrorFresherThan(Duration maxAge) {
        return cpeDictionarySyncStateRepository.findById(SYNC_STATE_ID)
                .filter(CpeDictionarySyncState::isInitialSyncCompleted)
                .map(CpeDictionarySyncState::getLastSyncedAt)
                .filter(Objects::nonNull)
                .map(lastSyncedAt -> lastSyncedAt.isAfter(OffsetDateTime.now(ZoneOffset.UTC).minus(maxAge)))
                .orElse(false);
    }

    /**
     * Delta sync: asks NVD for only the CPEs modified since the last successful unfiltered sync
     * (full or delta), via {@code lastModStartDate}/{@code lastModEndDate} — closed-mode backlog
     * item 283. Callers must only invoke this after {@link #tryBeginFullSync} returned {@code
     * true}; the slot is released here unconditionally (success or exception), same contract as
     * {@link #syncAllAndRelease}. Callers should also check {@link #hasCompletedInitialSync()}
     * first — a delta sync against a dictionary that has never completed a full sync would miss
     * every CPE modified before whatever cursor {@link #resolveDeltaCursor} falls back to; this
     * method does not enforce that itself; it still runs and still produces a valid (if
     * conservative) result if called anyway.
     */
    public SyncOutcome syncDeltaAndRelease(Optional<String> apiKey) {
        try {
            return syncDelta(apiKey);
        } finally {
            fullSyncRunning.set(false);
        }
    }

    private SyncOutcome syncDelta(Optional<String> apiKey) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        OffsetDateTime cursor = resolveDeltaCursor(now);
        OffsetDateTime windowStart = cursor.minus(DELTA_SAFETY_MARGIN);
        OffsetDateTime uncappedWindowEnd = windowStart.plusDays(MAX_LAST_MOD_WINDOW_DAYS);
        OffsetDateTime windowEnd = uncappedWindowEnd.isBefore(now) ? uncappedWindowEnd : now;
        return sync(null, apiKey, windowStart, windowEnd);
    }

    /**
     * Cursor fallback for {@link #syncDelta}: {@code cpe_dictionary_sync_state.last_synced_at} in
     * the normal case (every delta tick after the sync that first set {@link
     * CpeDictionarySyncState#isInitialSyncCompleted()} true), or {@code now.minusDays(7)} — this
     * job's own weekly cadence — if that column is somehow still null despite {@link
     * #hasCompletedInitialSync()} having returned true (defensive; both are set together, in the
     * same {@link #recordUnfilteredSyncCompleted} call, so this should not happen in practice).
     */
    private OffsetDateTime resolveDeltaCursor(OffsetDateTime now) {
        return cpeDictionarySyncStateRepository.findById(SYNC_STATE_ID)
                .map(CpeDictionarySyncState::getLastSyncedAt)
                .filter(Objects::nonNull)
                .orElseGet(() -> now.minusDays(7));
    }

    /**
     * Single-page, on-demand keyword lookup — bounded to exactly one rate-limited NVD call, never
     * paginates. Used by {@code Stage1IdentificationService} when the local dictionary has no
     * candidates at all for a product, so an unknown-to-us product can still be resolved live
     * instead of requiring someone to have pre-synced that keyword via the admin screen first.
     * Upserted rows land in the same {@code cpe_dictionary} table, so the lookup doubly serves as
     * an incremental cache warm for future items with the same/similar product name.
     */
    public int syncKeywordSinglePage(String keyword, int resultsPerPage, Optional<String> apiKey) {
        requireNonBlankKeyword(keyword);
        nvdRateLimiter.awaitTurn(apiKey.isPresent());
        JsonNode page = fetchPage(keyword, 0, resultsPerPage, apiKey);
        if (page == null) {
            return 0;
        }
        int upserted = 0;
        for (JsonNode productNode : page.path("products")) {
            if (upsertProduct(productNode.path("cpe"))) {
                upserted++;
            }
        }
        return upserted;
    }

    /**
     * @param lastModStart when non-null (together with {@code lastModEnd}), restricts this sync to
     *                     only the CPEs NVD reports as modified within {@code [lastModStart,
     *                     lastModEnd)} — the delta sync case ({@link #syncDelta}). Null for a full,
     *                     unfiltered sync ({@link #syncAllAndRelease}) or a keyword-filtered one
     *                     ({@link #syncByKeyword}).
     */
    private SyncOutcome sync(String keyword, Optional<String> apiKey, OffsetDateTime lastModStart,
            OffsetDateTime lastModEnd) {
        OffsetDateTime syncStartedAt = OffsetDateTime.now(ZoneOffset.UTC);
        int startIndex = 0;
        int totalUpserted = 0;
        int totalResults = Integer.MAX_VALUE;

        while (startIndex < totalResults) {
            nvdRateLimiter.awaitTurn(apiKey.isPresent());
            JsonNode page = fetchPage(keyword, startIndex, RESULTS_PER_PAGE, apiKey, nvdSyncRestClient,
                    lastModStart, lastModEnd);
            if (page == null) {
                // fetchPage() treats a failed request (429/5xx/etc, see NvdRateLimiter) as an
                // empty result rather than throwing, so this is an early abort, not a clean
                // exhaustion of totalResults — callers must not report this as "finished".
                return new SyncOutcome(totalUpserted, false);
            }

            JsonNode totalResultsNode = page.path("totalResults");
            JsonNode products = page.path("products");
            // Closed-mode backlog item 330 (先行修正 B): a page missing a numeric totalResults
            // (or carrying something non-numeric) can't be trusted to say whether pagination is
            // actually finished -- without this check, page.path("totalResults").asInt(0)'s silent
            // default of 0 would make `startIndex < totalResults` false immediately, misreporting
            // this as a clean, fully-exhausted finish (and, for an unfiltered sync, recording
            // cpe_dictionary_sync_state.initial_sync_completed=true off whatever partial dictionary
            // had synced so far). Treated the same as fetchPage() returning null: an early abort.
            if (totalResultsNode.isMissingNode() || !totalResultsNode.canConvertToInt()) {
                log.error("NVD CPE API page at startIndex={} is missing a numeric totalResults -- "
                        + "treating as a failed fetch (keyword={})", startIndex, LogSanitizer.sanitize(keyword));
                return new SyncOutcome(totalUpserted, false);
            }
            totalResults = totalResultsNode.asInt();
            // Self-contradictory page: NVD reports zero results overall, yet this very page still
            // carries products. Left unchecked, `startIndex < totalResults` (0 < 0) would be false
            // right away, again misreporting a clean finish off a page that plainly still had data.
            // Deliberately NOT "totalResults decreased from the previous page" -- NVD's own
            // dictionary can legitimately shrink or grow mid-sync over a ~103-minute run, so that
            // alone is not a sign of a bad page.
            if (totalResults == 0 && products.size() > 0) {
                log.error("NVD CPE API page at startIndex={} reported totalResults=0 but returned {} "
                        + "products -- treating as a failed fetch (keyword={})", startIndex, products.size(),
                        LogSanitizer.sanitize(keyword));
                return new SyncOutcome(totalUpserted, false);
            }

            // Batched rather than a statement per row: a full sync is ~1.8M rows, where per-row
            // round trips dominate the runtime far more than the NVD transfer itself does.
            List<CpeDictionaryEntry> batch = new ArrayList<>(products.size());
            for (JsonNode productNode : products) {
                CpeDictionaryEntry entry = toEntry(productNode.path("cpe"));
                if (entry != null) {
                    batch.add(entry);
                }
            }
            cpeDictionaryRepository.upsertBatch(batch);
            totalUpserted += batch.size();

            int fetched = products.size();
            startIndex += fetched;
            log.info("NVD CPE sync progress: {}/{} (keyword={})", startIndex, totalResults,
                    LogSanitizer.sanitize(keyword));

            if (fetched == 0) {
                if (startIndex < totalResults) {
                    // senior-reviewer REVISE (PR #207 round 1): NVD reported more results than this
                    // page actually carried (an empty/malformed "products" array on a page NVD's own
                    // totalResults says shouldn't be empty yet) — a page fetch failure that a 2xx
                    // response smuggled past the page == null check above. Reporting this as a clean
                    // finish would (a) let a full/delta sync mark cpe_dictionary_sync_state
                    // initial_sync_completed true off a partial dictionary — exactly the
                    // misclassification that table exists to prevent — and (b) advance the delta
                    // cursor past a window this run never actually fetched, permanently skipping
                    // that gap on every future delta tick (the cursor only ever moves forward).
                    return new SyncOutcome(totalUpserted, false);
                }
                // startIndex >= totalResults here (including the legitimate totalResults == 0 case,
                // startIndex == 0) -- a clean, fully-exhausted finish.
                break;
            }
        }

        if (keyword == null) {
            // Only an unfiltered sync (full or delta) is a legitimate signal that the whole
            // dictionary is now this fresh — see recordUnfilteredSyncCompleted's own javadoc for
            // why a keyword-filtered subset sync must never reach this.
            recordUnfilteredSyncCompleted(lastModEnd != null ? lastModEnd : syncStartedAt);
        }
        return new SyncOutcome(totalUpserted, true);
    }

    /**
     * Persists {@link CpeDictionarySyncState} after an unfiltered sync (full or delta) finishes
     * cleanly, so {@link #hasCompletedInitialSync()} and the next delta sync's own cursor ({@link
     * #resolveDeltaCursor}) both reflect it.
     *
     * @param asOf the new high-water mark: the delta sync's own requested {@code lastModEndDate}
     *             when this was a delta sync — never wall-clock "now" at completion, since a
     *             clamped/partial window's actual end must be recorded, or the gap between it and
     *             "now" would be silently skipped on the next tick (same rationale as {@code
     *             NvdCveSyncService#runDeltaTick}'s "the chunk's own window_end, not now" comment)
     *             — or this sync's own start time for a full sync (never its completion time — a
     *             full sync spans up to ~103 minutes, during which NVD-side changes can land;
     *             starting the next delta window from this run's start, minus {@link
     *             #DELTA_SAFETY_MARGIN}, is the safe choice).
     */
    private void recordUnfilteredSyncCompleted(OffsetDateTime asOf) {
        CpeDictionarySyncState state = cpeDictionarySyncStateRepository.findById(SYNC_STATE_ID)
                .orElseGet(CpeDictionarySyncState::new);
        state.setId(SYNC_STATE_ID);
        state.setInitialSyncCompleted(true);
        state.setLastSyncedAt(asOf);
        cpeDictionarySyncStateRepository.save(state);
    }

    private JsonNode fetchPage(String keyword, int startIndex, int resultsPerPage, Optional<String> apiKey) {
        return fetchPage(keyword, startIndex, resultsPerPage, apiKey, externalApiRestClient, null, null);
    }

    private JsonNode fetchPage(String keyword, int startIndex, int resultsPerPage, Optional<String> apiKey,
            RestClient restClient, OffsetDateTime lastModStart, OffsetDateTime lastModEnd) {
        // keyword is the CSV-supplied product name (see Stage1IdentificationService's
        // syncKeywordSinglePage / AdminController's syncByKeyword), so a product cell like
        // "foo&resultsPerPage=1" would otherwise inject an unencoded "&" into the query string and
        // let CSV input override resultsPerPage/startIndex above -- same class of bug as
        // NvdVulnerabilitySource's cpeName case (PR#163).
        //
        // NvdUriBuilder (task-backlog item 254) percent-encodes keyword -- including literal
        // braces (e.g. MSI ProductCode GUIDs like "{90160000-008C-0000-1000-0000000FF1CE}", which
        // show up verbatim in Windows installed-software listings) and "+" (item 255) -- see its
        // own javadoc for why and how.
        NvdUriBuilder uriBuilder = NvdUriBuilder.fromHttpUrl(NVD_CPE_API)
                .queryParam("resultsPerPage", resultsPerPage)
                .queryParam("startIndex", startIndex);
        if (keyword != null && !keyword.isBlank()) {
            uriBuilder.queryParam("keywordSearch", keyword);
        }
        // lastModStart/lastModEnd are always programmatically computed (never CSV/user-supplied —
        // see the delta sync's own javadoc), but routing them through the same CSV-safe
        // queryParam(String, String) as keyword is still correct here: it's the same encoder every
        // other query value on this request goes through, so there's no second, parallel encoding
        // path to keep in sync with NvdUriBuilder's own (task-backlog item 255) if this endpoint's
        // ISO offset format ever produces a non-UTC ("+HH:MM"-style) offset for some caller.
        // (Note: DateTimeFormatter.ISO_OFFSET_DATE_TIME renders a UTC OffsetDateTime as "Z", not
        // "+00:00", so today's callers never actually hit that "+" case in practice.)
        if (lastModStart != null) {
            uriBuilder.queryParam("lastModStartDate", formatNvdTimestamp(lastModStart));
        }
        if (lastModEnd != null) {
            uriBuilder.queryParam("lastModEndDate", formatNvdTimestamp(lastModEnd));
        }

        try {
            URI uri = uriBuilder.build();
            return restClient.get()
                    .uri(uri)
                    .headers(headers -> apiKey.ifPresent(key -> headers.set("apiKey", key)))
                    .retrieve()
                    .body(JsonNode.class);
        } catch (Exception e) {
            log.error("NVD CPE API request failed at startIndex={}", startIndex, e);
            return null;
        }
    }

    private static String formatNvdTimestamp(OffsetDateTime value) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(value);
    }

    /** Parsed form of one CPE API product node, or null when it carries no usable {@code cpeName}. */
    private CpeDictionaryEntry toEntry(JsonNode cpe) {
        String cpeName = cpe.path("cpeName").asText(null);
        if (cpeName == null) {
            return null;
        }
        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(cpeName);
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeName);
        entry.setTitle(englishTitle(cpe));
        entry.setVendor(vendorProduct != null ? vendorProduct.vendor() : null);
        entry.setProduct(vendorProduct != null ? vendorProduct.product() : null);
        return entry;
    }

    private String englishTitle(JsonNode cpe) {
        for (JsonNode titleNode : cpe.path("titles")) {
            if ("en".equals(titleNode.path("lang").asText())) {
                return titleNode.path("title").asText(null);
            }
        }
        return cpe.path("titles").size() > 0 ? cpe.path("titles").get(0).path("title").asText(null) : null;
    }

    private boolean upsertProduct(JsonNode cpe) {
        String cpeName = cpe.path("cpeName").asText(null);
        if (cpeName == null) {
            return false;
        }

        CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(cpeName);
        String vendor = vendorProduct != null ? vendorProduct.vendor() : null;
        String product = vendorProduct != null ? vendorProduct.product() : null;

        String title = null;
        for (JsonNode titleNode : cpe.path("titles")) {
            if ("en".equals(titleNode.path("lang").asText())) {
                title = titleNode.path("title").asText(null);
                break;
            }
        }
        if (title == null && cpe.path("titles").size() > 0) {
            title = cpe.path("titles").get(0).path("title").asText(null);
        }

        cpeDictionaryRepository.upsert(cpeName, title, vendor, product);
        return true;
    }
}
