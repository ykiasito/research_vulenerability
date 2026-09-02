package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.RegistryMirrorSeedNameRepository;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import java.util.regex.Pattern;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Closed-mode backlog item 183 (B3 prerequisite): the only production caller of the 9 registry
 * {@code *MirrorSyncService#syncPackages}/{@code #syncModules} methods (crates.io/RubyGems/
 * Packagist/Hex/npm/PyPI/NuGet/pub.dev/Go — Maven Central has no mirror, see {@code
 * docs/spec/closed-mode-plan.md}§5-4) added by the closed-mode registry-mirror rollout (backlog
 * item 176). Before this class, every one of those methods was only ever invoked from a test.
 *
 * <p><b>Seed source (the design decision this item flagged as needing a choice)</b>: the union of
 * two sources, both plain distinct-name lists rather than a bulk registry crawl — see {@link
 * #collectSeedNames}:
 *
 * <ol>
 *   <li>the distinct (ecosystem, package_name) pairs already recorded in {@code
 *       identified_products} — i.e. every package this app has previously resolved via a live
 *       registry lookup, across every job any user has ever run;
 *   <li>{@code registry_mirror_seed_name} (closed-mode backlog item 185) — package names an admin
 *       has explicitly uploaded via {@link #addOperatorSuppliedNames}/{@code
 *       AdminController#registryMirrorAddSeedNames}, the (2) growth path chosen for the problem
 *       (1) alone doesn't solve: once Phase B3 removes the live {@code *RegistryClient} lookups,
 *       every future {@code RegistryMatch} comes from {@code lookupViaMirror} itself, so (1) alone
 *       becomes a closed loop — a package never resolved live before B3 lands would otherwise stay
 *       unmirrored forever, with no path back into the seed set.
 * </ol>
 *
 * <p>Both sources were chosen over implementing a true full-registry bulk crawl (e.g. npm's {@code
 * _changes} feed, PyPI's Simple API index, NuGet's Catalog) for three reasons: (1) each {@code
 * *MirrorSyncService} was already built, deliberately, as a per-name fetcher — see e.g. {@link
 * CratesIoMirrorSyncService}'s own class javadoc, which explicitly names "names actually seen in
 * real job CSVs" as the intended seed source for anything beyond its hand-picked pilot list — not a
 * bulk-enumeration consumer, so this reuses the existing per-service contract exactly as designed
 * rather than rewriting all 9 of them; (2) it requires no new external calls of any kind (only
 * {@code registry_mirror_seed_name} is new schema, a plain admin-write table — no bulk-index
 * fetcher was added); and (3) it grows the mirror exactly where it matters most for this app's own
 * workload (packages real users have actually asked about, or that an operator already knows are
 * relevant) rather than paying the multi-GB/multi-day bulk-crawl cost of §5-6 for ecosystems/
 * packages nobody here has ever queried — for some ecosystems (NuGet Catalog ~100–200GB, npm ~
 * hundreds of GB, per §5-6's initial-ingest table) that cost would itself conflict with closed
 * mode's "minimize new external communication" posture. The tradeoff that remains: a package
 * nobody has resolved live *and* no admin has uploaded stays unmirrored — acceptable, since an
 * operator who cares about a specific package's post-B3 coverage now has a direct way to add it,
 * rather than being stuck waiting for a live lookup that Phase B3 has removed.
 *
 * <p>Chunks each ecosystem's seed list (see {@link #chunkSize}) before calling into the
 * per-ecosystem sync method — every {@code *MirrorSyncService#syncPackages} accumulates its whole
 * input batch in memory before a single {@code upsertBatch} call, so chunking bounds both memory
 * and gives visible incremental progress in the logs for a seed list large enough to take a while
 * (bounded today by real observed usage, but not assumed to stay small forever).
 *
 * <p>Single-run guard ({@link #tryBeginFullSync}/{@link #releaseFullSyncGuard}/{@link
 * #syncAllAndRelease}) follows the same shape as {@code NvdCpeSyncService}'s full-sync guard —
 * shared by every caller (admin-triggered and scheduled) of this service instance, so a second
 * trigger while one run is already in flight doesn't double up on the same 9 ecosystems' rate
 * limits and the same {@code registry_package_mirror} upserts.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RegistryMirrorSyncService {

    /**
     * Fallback used by {@link #syncEcosystem} whenever {@link #chunkSize} is not a positive value
     * (senior review, PR #122 REVISE) — {@code app.registry-mirror-sync-chunk-size=0} would
     * otherwise turn {@link #chunk}'s {@code i += chunkSize} into an infinite loop (unbounded
     * empty-sublist accumulation, eventual OOM, and — since this happens inside {@link #syncAll},
     * called from {@link #syncAllAndRelease}'s {@code try} block before its {@code finally} is ever
     * reached because the loop never returns — the {@link #fullSyncRunning} guard leaks
     * permanently). A negative value throws {@link IndexOutOfBoundsException} from {@code
     * List#subList} instead of hanging, but is equally not a value this class should ever act on.
     */
    private static final int DEFAULT_CHUNK_SIZE = 200;

    /**
     * The 9 mirrored ecosystem identifiers, exactly as used as the literal {@code syncEcosystem}
     * argument in {@link #syncAll}. Kept as one set here (rather than re-deriving it from {@link
     * #syncAll}'s call sites) purely so {@link #addOperatorSuppliedNames} can reject an unknown/
     * mistyped ecosystem string at upload time instead of silently storing a row nothing will ever
     * pick up. This is a second place these 9 strings are listed — see closed-mode-backlog item 187
     * (already-tracked, low-priority) for the broader "ecosystem identifiers aren't a single shared
     * constant anywhere in this class" debt; not fixed here since it's out of this item's scope.
     */
    private static final Set<String> KNOWN_ECOSYSTEMS = Set.of(
            "crates.io", "rubygems", "packagist", "hex", "npm", "pypi", "nuget", "go", "pub");

    /**
     * Single, conservative, registry-agnostic character allowlist for {@link
     * #addOperatorSuppliedNames} (senior review, PR #126 REVISE, closed-mode backlog item 185).
     * Deliberately not per-ecosystem — a per-registry grammar (e.g. Packagist's exactly-one-slash
     * rule) is closed-mode backlog item 184's concern on the URL-assembly side ({@code
     * CratesIoMirrorSyncService}/{@code PackagistMirrorSyncService}), not this input-side gate. This
     * set is chosen wide enough to admit every legitimate name shape across all 9 mirrored
     * ecosystems — Go module paths ({@code github.com/foo/bar}), npm scoped packages ({@code
     * @scope/pkg}), Packagist vendor/package pairs ({@code vendor/pkg}), and NuGet's dotted IDs
     * ({@code Newtonsoft.Json}) — while still excluding the traversal-shaped inputs {@link
     * #isValidSeedName} rejects.
     */
    private static final Pattern SEED_NAME_ALLOWED_CHARS = Pattern.compile("[A-Za-z0-9._@/~+-]+");

    /** {@link #isValidSeedName} rejects any name longer than this. */
    private static final int MAX_SEED_NAME_LENGTH = 200;

    /**
     * Hard cap on the number of *distinct, valid* names {@link #addOperatorSuppliedNames} will
     * accept in a single submission (senior review, PR #126 REVISE, closed-mode backlog item 185).
     * Every name recorded in {@code registry_mirror_seed_name} is picked up by every future
     * {@link #syncAllAndRelease} run (scheduled weekly) for as long as it stays in the table — see
     * {@code RegistryMirrorSeedNameRepository} — and each occurrence costs one rate-limited external
     * request to that ecosystem's registry. An operator submitting an oversized list (e.g. an entire
     * lockfile pasted by mistake) would therefore not just cost one sync run; it would permanently
     * degrade every subsequent weekly sync's cost and duration, with no delete path yet available
     * (see closed-mode backlog item 185's "no delete path" follow-up). Rejecting the whole
     * submission — rather than accepting the first {@code MAX_SEED_NAMES_PER_SUBMISSION} names —
     * forces the operator to notice and deliberately split the list, instead of silently truncating
     * it. Because this cap exists, {@link #syncEcosystem}'s per-sync chunking is still needed (an
     * ecosystem's seed list also includes {@code identified_products}, which isn't capped here), but
     * {@code RegistryMirrorSeedNameRepositoryImpl#insertBatch} itself does not need its own chunking
     * — a single {@code JdbcTemplate#batchUpdate} call for up to {@code
     * MAX_SEED_NAMES_PER_SUBMISSION} rows is bounded and sufficient.
     */
    private static final int MAX_SEED_NAMES_PER_SUBMISSION = 10_000;

    private final IdentifiedProductRepository identifiedProductRepository;
    private final RegistryMirrorSeedNameRepository registryMirrorSeedNameRepository;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;
    private final CratesIoMirrorSyncService cratesIoMirrorSyncService;
    private final RubyGemsMirrorSyncService rubyGemsMirrorSyncService;
    private final PackagistMirrorSyncService packagistMirrorSyncService;
    private final HexMirrorSyncService hexMirrorSyncService;
    private final NpmMirrorSyncService npmMirrorSyncService;
    private final PyPiMirrorSyncService pyPiMirrorSyncService;
    private final NuGetMirrorSyncService nuGetMirrorSyncService;
    private final GoMirrorSyncService goMirrorSyncService;
    private final PubMirrorSyncService pubMirrorSyncService;

    /** See {@code AsyncConfig#registryMirrorSyncExecutor}'s javadoc for why this fans the 9
     *  per-ecosystem syncs out concurrently rather than reusing {@code registryLookupExecutor}. */
    @Qualifier("registryMirrorSyncExecutor")
    private final Executor registryMirrorSyncExecutor;

    /** Names per {@code syncPackages}/{@code syncModules} call — see the class javadoc. */
    @Value("${app.registry-mirror-sync-chunk-size:200}")
    private int chunkSize;

    /**
     * Closed-mode backlog item 186: a seed name whose {@code registry_package_mirror.
     * last_synced_at} is already within this many days of "now" is skipped by {@link
     * #collectSeedNames} rather than re-fetched — every weekly {@link #syncAllAndRelease} run
     * previously re-fetched every observed name unconditionally, so cost grew monotonically with
     * install-history size even though most names' published-version lists rarely change week to
     * week. 7 days is the default: this sync's own schedule is weekly, so 7 days keeps a name that
     * was actually refreshed on last week's run from being re-fetched again this run, while still
     * re-fetching anything that was added, or that missed a run, since then. A name never synced
     * before (no {@code registry_package_mirror} row at all) has no {@code last_synced_at} to
     * compare and is therefore never filtered out by this, regardless of this value — see {@link
     * #collectSeedNames}. A non-positive value disables the filter entirely (every observed name is
     * always re-synced), same escape-hatch convention as {@link #chunkSize}'s own non-positive
     * fallback.
     */
    @Value("${app.registry-mirror-sync-freshness-days:7}")
    private int freshnessDays;

    /** Same convention as {@code NvdCpeSyncService#fullSyncRunning} — see that field's javadoc. */
    private final AtomicBoolean fullSyncRunning = new AtomicBoolean(false);

    /**
     * @param totalSynced sum of every ecosystem's synced count.
     * @param totalUnresolved sum of every ecosystem's unresolved count.
     * @param observedNameCountByEcosystem how many distinct seed package names ({@code
     *                                     identified_products} union {@code
     *                                     registry_mirror_seed_name}, minus any name {@link
     *                                     #freshnessDays} skipped as recently synced — see {@link
     *                                     #collectSeedNames}) were actually candidates to sync for
     *                                     each ecosystem, before syncing — kept separate from {@code
     *                                     totalSynced} so a caller can tell "0 candidates this run"
     *                                     apart from "synced 0 of N candidates" (every candidate
     *                                     name failed to resolve). 0 here is ambiguous by design and
     *                                     must not be read as "nothing to sync yet" (senior review,
     *                                     PR #145 REVISE): it means either "no seed names observed
     *                                     at all for this ecosystem" or "every observed name was
     *                                     already fresh (synced within {@link #freshnessDays}) and
     *                                     therefore skipped" — the latter is the expected steady
     *                                     state for a healthy weekly deployment once every name has
     *                                     been synced at least once, not a sign of a problem.
     */
    public record SyncOutcome(int totalSynced, int totalUnresolved, Map<String, Integer> observedNameCountByEcosystem) {
    }

    /**
     * Attempts to reserve the sync slot; returns {@code true} only for the caller that wins the
     * race. Same contract as {@code NvdCpeSyncService#tryBeginFullSync} — callers that get {@code
     * false} must not proceed to {@link #syncAllAndRelease}.
     */
    public boolean tryBeginFullSync() {
        return fullSyncRunning.compareAndSet(false, true);
    }

    /**
     * Releases the guard without ever having run a sync — for callers of {@link #tryBeginFullSync}
     * only, and only when the acquired slot will never reach {@link #syncAllAndRelease} (e.g.
     * spawning the background worker thread itself threw). Same escape-hatch contract as {@code
     * NvdCpeSyncService#releaseFullSyncGuard}; see that method's javadoc for why this exists.
     */
    public void releaseFullSyncGuard() {
        fullSyncRunning.set(false);
    }

    /**
     * @param accepted the number of distinct, valid names actually submitted for insertion (after
     *                 trimming/blank-filtering/validating/de-duplicating {@code names} itself) — not
     *                 the number of genuinely new rows, since a name already present (from a prior
     *                 upload, or already promoted into {@code registry_mirror_seed_name} by some
     *                 other means) is a silent no-op at the DB level (see {@link
     *                 RegistryMirrorSeedNameRepository#insertBatch}) and this method has no cheap way
     *                 to tell the two cases apart without an extra round trip nothing here needs.
     * @param rejected how many trimmed, non-blank names failed {@link #isValidSeedName} and were
     *                 skipped rather than inserted (senior review, PR #126 REVISE) — counted once per
     *                 rejected occurrence in the caller's original list (before de-duplication), so a
     *                 caller can tell "nothing wrong, just an empty submission" (0/0) apart from
     *                 "N names silently dropped" (0/N or accepted&gt;0, rejected&gt;0).
     */
    public record SeedNameSubmissionOutcome(int accepted, int rejected) {
    }

    /**
     * Thrown by {@link #addOperatorSuppliedNames} when the post-cleanup (trimmed, validated,
     * de-duplicated) name count exceeds {@link #MAX_SEED_NAMES_PER_SUBMISSION} — see that constant's
     * javadoc for why the whole submission is rejected outright rather than partially inserted.
     */
    public static class SeedNameBatchTooLargeException extends IllegalArgumentException {
        public SeedNameBatchTooLargeException(String message) {
            super(message);
        }
    }

    /**
     * Closed-mode backlog item 185: records an operator-supplied package name list as a seed for
     * this ecosystem — see the class javadoc's "Seed source" section for why this exists alongside
     * {@code identified_products}. Does not itself trigger a sync; the names are picked up by the
     * next {@link #syncAllAndRelease} (admin-triggered or scheduled), same as any other seed name.
     *
     * <p>Per-name validation ({@link #isValidSeedName}) runs after trimming/blank-filtering but
     * before de-duplication (senior review, PR #126 REVISE) — an invalid name never reaches {@link
     * RegistryMirrorSeedNameRepository#insertBatch} and never throws (this app has no {@code
     * @ControllerAdvice}/{@code @ExceptionHandler}, so an unhandled exception here would surface as a
     * bare 500 and silently lose the entire submission, valid names included); it is only counted in
     * {@link SeedNameSubmissionOutcome#rejected()} so the caller can report both counts to the
     * operator instead of leaving a rejected name indistinguishable from one that simply never made
     * it into the request.
     *
     * @throws IllegalArgumentException if {@code ecosystem} isn't one of the 9 mirrored ecosystems
     *         (see {@link #KNOWN_ECOSYSTEMS}) — catches a typo at upload time rather than silently
     *         storing a row {@link #syncAll} will never query for.
     * @throws SeedNameBatchTooLargeException if the post-cleanup name count exceeds {@link
     *         #MAX_SEED_NAMES_PER_SUBMISSION} — see that constant's javadoc.
     */
    public SeedNameSubmissionOutcome addOperatorSuppliedNames(String ecosystem, List<String> names) {
        if (!KNOWN_ECOSYSTEMS.contains(ecosystem)) {
            throw new IllegalArgumentException("Unknown registry mirror ecosystem: " + ecosystem);
        }
        List<String> trimmedNonBlank = names.stream()
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .toList();

        int rejected = 0;
        List<String> valid = new ArrayList<>();
        for (String name : trimmedNonBlank) {
            if (isValidSeedName(name)) {
                valid.add(name);
            } else {
                rejected++;
            }
        }
        List<String> cleaned = valid.stream().distinct().toList();

        if (cleaned.size() > MAX_SEED_NAMES_PER_SUBMISSION) {
            throw new SeedNameBatchTooLargeException("シード名の投稿を却下しました（" + ecosystem + "）: クリーンアップ後 "
                    + cleaned.size() + " 件が上限（" + MAX_SEED_NAMES_PER_SUBMISSION + "件）を超えています。"
                    + "リストを分割して投稿し直してください。");
        }
        if (cleaned.isEmpty()) {
            return new SeedNameSubmissionOutcome(0, rejected);
        }
        registryMirrorSeedNameRepository.insertBatch(ecosystem, cleaned);
        log.info("Registry mirror seed names added ({}): {} names submitted, {} rejected as invalid",
                ecosystem, cleaned.size(), rejected);
        return new SeedNameSubmissionOutcome(cleaned.size(), rejected);
    }

    /**
     * Registry-agnostic validity gate for {@link #addOperatorSuppliedNames} (senior review, PR #126
     * REVISE, closed-mode backlog item 185) — see {@link #SEED_NAME_ALLOWED_CHARS}'s javadoc for why
     * this is one conservative rule rather than 9 per-ecosystem grammars. Rejects a name that:
     *
     * <ul>
     *   <li>is longer than {@link #MAX_SEED_NAME_LENGTH} characters;
     *   <li>contains any character outside {@link #SEED_NAME_ALLOWED_CHARS};
     *   <li>starts or ends with {@code /}, or contains {@code //};
     *   <li>has any {@code /}-separated segment equal to {@code .} or {@code ..} (including the
     *       whole name itself, for a name with no {@code /} at all).
     * </ul>
     *
     * <p>The last three rules exist specifically to keep a traversal-shaped name (e.g. {@code ../
     * ../etc/passwd} or a bare {@code ..}) out of {@code registry_mirror_seed_name} at the point of
     * entry — the outbound URL-assembly hardening for the same risk (closed-mode backlog item 184) is
     * a separate concern, handled by {@code RegistryMirrorPackageNameValidator} at the point {@code
     * CratesIoMirrorSyncService}/{@code PackagistMirrorSyncService} build their outbound request URL
     * (see that class's javadoc).
     */
    private static boolean isValidSeedName(String name) {
        if (name.length() > MAX_SEED_NAME_LENGTH) {
            return false;
        }
        if (!SEED_NAME_ALLOWED_CHARS.matcher(name).matches()) {
            return false;
        }
        if (name.startsWith("/") || name.endsWith("/") || name.contains("//")) {
            return false;
        }
        for (String segment : name.split("/", -1)) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
        }
        return true;
    }

    /**
     * Syncs all 9 mirrored ecosystems from their observed-name seed lists, concurrently — see
     * {@link #syncAll}'s own javadoc for why running them in parallel is safe. Callers must only
     * invoke this after {@link #tryBeginFullSync} returned {@code true}; the slot is released here
     * unconditionally (success or exception) so a failed run doesn't permanently wedge the guard.
     */
    public SyncOutcome syncAllAndRelease() {
        try {
            return syncAll();
        } finally {
            fullSyncRunning.set(false);
        }
    }

    /**
     * One (ecosystem identifier, per-chunk sync function) pair — see {@link #syncEcosystem} for
     * what the function itself does with it.
     */
    private record EcosystemSyncTask(String ecosystem, Function<List<String>, int[]> syncOneChunk) {
    }

    /**
     * Closed-mode backlog item 186: fans the 9 per-ecosystem syncs out onto {@link
     * #registryMirrorSyncExecutor} instead of running them one after another. Safe to parallelize
     * because each ecosystem's own {@link com.vulncheck.app.service.ratelimit.
     * ExternalRegistryRateLimiter} pacing is an independent gate keyed by ecosystem (see that
     * class's javadoc) — running all 9 concurrently paces each one exactly as it would running
     * alone, it just stops one slow ecosystem's run from serializing behind the other 8. Wall-clock
     * cost for a full sync therefore drops from roughly the *sum* of every ecosystem's own sync time
     * to roughly the *slowest single ecosystem's* sync time.
     *
     * <p><b>Per-ecosystem failures are isolated, not propagated</b> (senior review, PR #145 REVISE):
     * an earlier version let {@link CompletableFuture#join} on the first task's future throw as soon
     * as that one ecosystem failed, while the other 8 tasks were still running unobserved on {@link
     * #registryMirrorSyncExecutor} — {@link #syncAllAndRelease}'s {@code finally} released {@link
     * #fullSyncRunning} at that point regardless, so a second admin click or the weekly schedule
     * could start a competing sync while those 8 tasks were still in flight, and whichever of them
     * failed too did so silently (no log line at all). Each task submitted below therefore catches
     * its own {@link RuntimeException} internally, logs it, and returns a zero outcome instead of
     * letting the exception reach the {@link CompletableFuture} — {@link #syncAll} (and so {@link
     * #syncAllAndRelease}) now always returns normally once every task's future completes, and one
     * ecosystem failing never stops, or hides the failure of, any of the other 8.
     */
    private SyncOutcome syncAll() {
        List<EcosystemSyncTask> tasks = List.of(
                new EcosystemSyncTask("crates.io", names -> {
                    CratesIoMirrorSyncService.SyncOutcome o = cratesIoMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("rubygems", names -> {
                    RubyGemsMirrorSyncService.SyncOutcome o = rubyGemsMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("packagist", names -> {
                    PackagistMirrorSyncService.SyncOutcome o = packagistMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("hex", names -> {
                    HexMirrorSyncService.SyncOutcome o = hexMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("npm", names -> {
                    NpmMirrorSyncService.SyncOutcome o = npmMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("pypi", names -> {
                    PyPiMirrorSyncService.SyncOutcome o = pyPiMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("nuget", names -> {
                    NuGetMirrorSyncService.SyncOutcome o = nuGetMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("go", names -> {
                    GoMirrorSyncService.SyncOutcome o = goMirrorSyncService.syncModules(names);
                    return new int[] {o.synced(), o.unresolved()};
                }),
                new EcosystemSyncTask("pub", names -> {
                    PubMirrorSyncService.SyncOutcome o = pubMirrorSyncService.syncPackages(names);
                    return new int[] {o.synced(), o.unresolved()};
                }));

        List<CompletableFuture<int[]>> futures = tasks.stream()
                .map(task -> CompletableFuture.supplyAsync(() -> {
                    try {
                        return syncEcosystem(task.ecosystem(), task.syncOneChunk());
                    } catch (RuntimeException e) {
                        log.error("Registry mirror sync ({}) failed — other ecosystems are unaffected",
                                task.ecosystem(), e);
                        return new int[] {0, 0, 0};
                    }
                }, registryMirrorSyncExecutor))
                .toList();

        int totalSynced = 0;
        int totalUnresolved = 0;
        Map<String, Integer> observedNameCountByEcosystem = new LinkedHashMap<>();
        for (int i = 0; i < tasks.size(); i++) {
            // .join() never throws here — a per-ecosystem failure is already caught and logged
            // inside the supplyAsync task above, so every future always completes normally.
            int[] result = futures.get(i).join();
            totalSynced += result[0];
            totalUnresolved += result[1];
            observedNameCountByEcosystem.put(tasks.get(i).ecosystem(), result[2]);
        }

        log.info("Registry mirror sync (all ecosystems): {} synced, {} unresolved, candidate name counts "
                        + "(after freshness filter): {}",
                totalSynced, totalUnresolved, observedNameCountByEcosystem);
        return new SyncOutcome(totalSynced, totalUnresolved, observedNameCountByEcosystem);
    }

    /**
     * Pulls this ecosystem's seed list (see {@link #collectSeedNames}), chunks it, and hands each
     * chunk to {@code syncOneChunk}, accumulating the {@code (synced, unresolved)} totals a {@code
     * *MirrorSyncService}'s own {@code SyncOutcome} record carries (each ecosystem has its own
     * distinct nested record type, so this method takes a plain {@code int[]} rather than trying to
     * unify them behind a shared interface those 9 classes never declared).
     *
     * @return {@code [synced, unresolved, observedNameCount]}
     */
    private int[] syncEcosystem(String ecosystem, Function<List<String>, int[]> syncOneChunk) {
        List<String> observedNames = collectSeedNames(ecosystem);
        int synced = 0;
        int unresolved = 0;
        // Deliberately not validated at @Value-injection time (e.g. @PostConstruct) — that would
        // only catch a bad value when Spring itself constructs this bean, not a plain `new
        // RegistryMirrorSyncService(...)` (every unit test), so the guard must live here, at the
        // one call site that actually uses chunkSize as a divisor of loop progress. See
        // DEFAULT_CHUNK_SIZE's own javadoc for what a non-positive value would otherwise do.
        int effectiveChunkSize = chunkSize > 0 ? chunkSize : DEFAULT_CHUNK_SIZE;
        if (effectiveChunkSize != chunkSize) {
            log.warn("app.registry-mirror-sync-chunk-size={} is not a positive value — falling back to {}",
                    chunkSize, DEFAULT_CHUNK_SIZE);
        }
        for (List<String> batch : chunk(observedNames, effectiveChunkSize)) {
            int[] batchOutcome = syncOneChunk.apply(batch);
            synced += batchOutcome[0];
            unresolved += batchOutcome[1];
        }
        log.info("Registry mirror sync ({}): {} seed package names ({} synced, {} unresolved)",
                ecosystem, observedNames.size(), synced, unresolved);
        return new int[] {synced, unresolved, observedNames.size()};
    }

    /**
     * Union of this ecosystem's two seed sources — see the class javadoc's "Seed source" section —
     * minus any name {@link #freshnessDays} says was mirrored recently enough to skip (closed-mode
     * backlog item 186). A {@link LinkedHashSet} both de-duplicates (a name present in both sources
     * must not be synced twice) and keeps a stable, deterministic iteration order
     * (identified_products names first, then any operator-uploaded names not already covered)
     * rather than depending on whatever order two separate SQL queries happen to return rows in.
     */
    private List<String> collectSeedNames(String ecosystem) {
        Set<String> names = new LinkedHashSet<>(identifiedProductRepository.findDistinctPackageNamesByEcosystem(ecosystem));
        names.addAll(registryMirrorSeedNameRepository.findDistinctPackageNames(ecosystem));
        if (freshnessDays <= 0) {
            // Non-positive disables the filter entirely — see freshnessDays' own javadoc.
            return List.copyOf(names);
        }
        Instant cutoff = Instant.now().minus(freshnessDays, ChronoUnit.DAYS);
        Set<String> freshNormalizedNames =
                registryPackageMirrorRepository.findFreshlySyncedNormalizedPackageNames(ecosystem, cutoff);
        if (freshNormalizedNames.isEmpty()) {
            return List.copyOf(names);
        }
        List<String> stale = names.stream()
                .filter(name -> !freshNormalizedNames.contains(OsvPackageNameNormalizer.normalize(ecosystem, name)))
                .toList();
        int skipped = names.size() - stale.size();
        if (skipped > 0) {
            log.info("Registry mirror sync ({}): skipping {} of {} observed names already synced within "
                    + "the last {} day(s)", ecosystem, skipped, names.size(), freshnessDays);
        }
        return stale;
    }

    private static List<List<String>> chunk(List<String> names, int chunkSize) {
        List<List<String>> chunks = new ArrayList<>();
        for (int i = 0; i < names.size(); i += chunkSize) {
            chunks.add(names.subList(i, Math.min(i + chunkSize, names.size())));
        }
        return chunks;
    }
}
