package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.IdentifiedProductRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
 * <p><b>Seed source (the design decision this item flagged as needing a choice)</b>: the distinct
 * (ecosystem, package_name) pairs already recorded in {@code identified_products} — i.e. every
 * package this app has previously resolved via a live registry lookup, across every job any user
 * has ever run. This was chosen over implementing a true full-registry bulk crawl (e.g. npm's
 * {@code _changes} feed, PyPI's Simple API index, NuGet's Catalog) for three reasons: (1) each
 * {@code *MirrorSyncService} was already built, deliberately, as a per-name fetcher — see e.g.
 * {@link CratesIoMirrorSyncService}'s own class javadoc, which explicitly names "names actually
 * seen in real job CSVs" as the intended seed source for anything beyond its hand-picked pilot
 * list — not a bulk-enumeration consumer, so this reuses the existing per-service contract exactly
 * as designed rather than rewriting all 9 of them; (2) it requires no new schema or new external
 * calls — {@code identified_products.ecosystem}/{@code package_name} are populated for every
 * registry-trusted match today (see {@code Stage1IdentificationService#resolveCandidates}); and
 * (3) it grows the mirror exactly where it matters most for this app's own workload (packages real
 * users have actually asked about) rather than paying the multi-GB/multi-day bulk-crawl cost of
 * §5-6 for ecosystems/packages nobody here has ever queried. The tradeoff: a package this app has
 * never resolved live stays unmirrored until it's looked up live at least once — acceptable while
 * the live registry paths still exist (today), but something Phase B3 (removing those live paths)
 * must account for when it lands (see the closed-mode-backlog item 183 entry for the current
 * status of that follow-up).
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

    private final IdentifiedProductRepository identifiedProductRepository;
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
     * @param observedNameCountByEcosystem how many distinct package names were pulled from {@code
     *                                     identified_products} for each ecosystem, before syncing —
     *                                     kept separate from {@code totalSynced} so a caller can
     *                                     tell "nothing to sync yet" (0 observed) apart from "synced
     *                                     0 of N" (every observed name failed to resolve).
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
     * Pulls this ecosystem's observed-name seed list from {@code identified_products}, chunks it,
     * and hands each chunk to {@code syncOneChunk}, accumulating the {@code (synced, unresolved)}
     * totals a {@code *MirrorSyncService}'s own {@code SyncOutcome} record carries (each ecosystem
     * has its own distinct nested record type, so this method takes a plain {@code int[]} rather
     * than trying to unify them behind a shared interface those 9 classes never declared).
     *
     * @return {@code [synced, unresolved, observedNameCount]}
     */
    private int[] syncEcosystem(String ecosystem, Function<List<String>, int[]> syncOneChunk) {
        List<String> observedNames = identifiedProductRepository.findDistinctPackageNamesByEcosystem(ecosystem);
        int synced = 0;
        int unresolved = 0;
        for (List<String> batch : chunk(observedNames, chunkSize)) {
            int[] batchOutcome = syncOneChunk.apply(batch);
            synced += batchOutcome[0];
            unresolved += batchOutcome[1];
        }
        log.info("Registry mirror sync ({}): {} package names observed in identified_products, {} synced, "
                + "{} unresolved", ecosystem, observedNames.size(), synced, unresolved);
        return new int[] {synced, unresolved, observedNames.size()};
    }

    private static List<List<String>> chunk(List<String> names, int chunkSize) {
        List<List<String>> chunks = new ArrayList<>();
        for (int i = 0; i < names.size(); i += chunkSize) {
            chunks.add(names.subList(i, Math.min(i + chunkSize, names.size())));
        }
        return chunks;
    }
}
