package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.RegistryMirrorSeedNameRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    private final IdentifiedProductRepository identifiedProductRepository;
    private final RegistryMirrorSeedNameRepository registryMirrorSeedNameRepository;
    private final CratesIoMirrorSyncService cratesIoMirrorSyncService;
    private final RubyGemsMirrorSyncService rubyGemsMirrorSyncService;
    private final PackagistMirrorSyncService packagistMirrorSyncService;
    private final HexMirrorSyncService hexMirrorSyncService;
    private final NpmMirrorSyncService npmMirrorSyncService;
    private final PyPiMirrorSyncService pyPiMirrorSyncService;
    private final NuGetMirrorSyncService nuGetMirrorSyncService;
    private final GoMirrorSyncService goMirrorSyncService;
    private final PubMirrorSyncService pubMirrorSyncService;

    /** Names per {@code syncPackages}/{@code syncModules} call — see the class javadoc. */
    @Value("${app.registry-mirror-sync-chunk-size:200}")
    private int chunkSize;

    /** Same convention as {@code NvdCpeSyncService#fullSyncRunning} — see that field's javadoc. */
    private final AtomicBoolean fullSyncRunning = new AtomicBoolean(false);

    /**
     * @param totalSynced sum of every ecosystem's synced count.
     * @param totalUnresolved sum of every ecosystem's unresolved count.
     * @param observedNameCountByEcosystem how many distinct seed package names ({@code
     *                                     identified_products} union {@code
     *                                     registry_mirror_seed_name}, see {@link #collectSeedNames})
     *                                     were pulled for each ecosystem, before syncing — kept
     *                                     separate from {@code totalSynced} so a caller can tell
     *                                     "nothing to sync yet" (0 observed) apart from "synced 0 of
     *                                     N" (every observed name failed to resolve).
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
     * Closed-mode backlog item 185: records an operator-supplied package name list as a seed for
     * this ecosystem — see the class javadoc's "Seed source" section for why this exists alongside
     * {@code identified_products}. Does not itself trigger a sync; the names are picked up by the
     * next {@link #syncAllAndRelease} (admin-triggered or scheduled), same as any other seed name.
     *
     * @return the number of names actually submitted for insertion (after trimming/blank-filtering/
     *         de-duplicating {@code names} itself) — not the number of genuinely new rows, since a
     *         name already present (from a prior upload, or already promoted into {@code
     *         registry_mirror_seed_name} by some other means) is a silent no-op at the DB level (see
     *         {@link RegistryMirrorSeedNameRepository#insertBatch}) and this method has no cheap way
     *         to tell the two cases apart without an extra round trip nothing here needs.
     * @throws IllegalArgumentException if {@code ecosystem} isn't one of the 9 mirrored ecosystems
     *         (see {@link #KNOWN_ECOSYSTEMS}) — catches a typo at upload time rather than silently
     *         storing a row {@link #syncAll} will never query for.
     */
    public int addOperatorSuppliedNames(String ecosystem, List<String> names) {
        if (!KNOWN_ECOSYSTEMS.contains(ecosystem)) {
            throw new IllegalArgumentException("Unknown registry mirror ecosystem: " + ecosystem);
        }
        List<String> cleaned = names.stream()
                .map(String::trim)
                .filter(name -> !name.isEmpty())
                .distinct()
                .toList();
        if (cleaned.isEmpty()) {
            return 0;
        }
        registryMirrorSeedNameRepository.insertBatch(ecosystem, cleaned);
        log.info("Registry mirror seed names added ({}): {} names submitted", ecosystem, cleaned.size());
        return cleaned.size();
    }

    /**
     * Syncs all 9 mirrored ecosystems from their observed-name seed lists, sequentially (each
     * ecosystem's own {@link com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter}
     * pacing already serializes that ecosystem's own requests; running ecosystems one after another
     * rather than concurrently keeps this service's own logic simple and avoids adding a new
     * concurrency surface for what is, today, a background/off-hours operation). Callers must only
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

    private SyncOutcome syncAll() {
        int totalSynced = 0;
        int totalUnresolved = 0;
        Map<String, Integer> observedNameCountByEcosystem = new LinkedHashMap<>();

        int[] result;

        result = syncEcosystem("crates.io", names -> {
            CratesIoMirrorSyncService.SyncOutcome o = cratesIoMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("crates.io", result[2]);

        result = syncEcosystem("rubygems", names -> {
            RubyGemsMirrorSyncService.SyncOutcome o = rubyGemsMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("rubygems", result[2]);

        result = syncEcosystem("packagist", names -> {
            PackagistMirrorSyncService.SyncOutcome o = packagistMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("packagist", result[2]);

        result = syncEcosystem("hex", names -> {
            HexMirrorSyncService.SyncOutcome o = hexMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("hex", result[2]);

        result = syncEcosystem("npm", names -> {
            NpmMirrorSyncService.SyncOutcome o = npmMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("npm", result[2]);

        result = syncEcosystem("pypi", names -> {
            PyPiMirrorSyncService.SyncOutcome o = pyPiMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("pypi", result[2]);

        result = syncEcosystem("nuget", names -> {
            NuGetMirrorSyncService.SyncOutcome o = nuGetMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("nuget", result[2]);

        result = syncEcosystem("go", names -> {
            GoMirrorSyncService.SyncOutcome o = goMirrorSyncService.syncModules(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("go", result[2]);

        result = syncEcosystem("pub", names -> {
            PubMirrorSyncService.SyncOutcome o = pubMirrorSyncService.syncPackages(names);
            return new int[] {o.synced(), o.unresolved()};
        });
        totalSynced += result[0];
        totalUnresolved += result[1];
        observedNameCountByEcosystem.put("pub", result[2]);

        log.info("Registry mirror sync (all ecosystems): {} synced, {} unresolved, observed name counts: {}",
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
     * Union of this ecosystem's two seed sources — see the class javadoc's "Seed source" section.
     * A {@link LinkedHashSet} both de-duplicates (a name present in both sources must not be synced
     * twice) and keeps a stable, deterministic iteration order (identified_products names first,
     * then any operator-uploaded names not already covered) rather than depending on whatever order
     * two separate SQL queries happen to return rows in.
     */
    private List<String> collectSeedNames(String ecosystem) {
        Set<String> names = new LinkedHashSet<>(identifiedProductRepository.findDistinctPackageNamesByEcosystem(ecosystem));
        names.addAll(registryMirrorSeedNameRepository.findDistinctPackageNames(ecosystem));
        return List.copyOf(names);
    }

    private static List<List<String>> chunk(List<String> names, int chunkSize) {
        List<List<String>> chunks = new ArrayList<>();
        for (int i = 0; i < names.size(); i += chunkSize) {
            chunks.add(names.subList(i, Math.min(i + chunkSize, names.size())));
        }
        return chunks;
    }
}
