package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.RegistryMirrorSeedNameRepository;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Executor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link RegistryMirrorSyncService} — the seed source union (closed-mode backlog
 * items 183/185: {@code identified_products} and {@code registry_mirror_seed_name}), the
 * per-ecosystem chunking, the aggregate totals, and the concurrency guard. Every {@code
 * *MirrorSyncService} is mocked: its own sync/parse behavior is covered by its own dedicated test
 * (e.g. {@code CratesIoMirrorSyncServiceTest}), so this class only needs to verify that the
 * orchestrator calls each one correctly and aggregates what it returns.
 */
class RegistryMirrorSyncServiceTest {

    private final IdentifiedProductRepository identifiedProductRepository = mock(IdentifiedProductRepository.class);
    private final RegistryMirrorSeedNameRepository registryMirrorSeedNameRepository = mock(RegistryMirrorSeedNameRepository.class);
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository = mock(RegistryPackageMirrorRepository.class);
    // Runs each ecosystem's sync synchronously on the calling (test) thread instead of a real pool
    // -- exercises the real CompletableFuture-based fan-out in syncAll without introducing timing
    // nondeterminism into these tests' verify()/assertThat() calls.
    private final Executor directExecutor = Runnable::run;
    private final CratesIoMirrorSyncService cratesIoMirrorSyncService = mock(CratesIoMirrorSyncService.class);
    private final RubyGemsMirrorSyncService rubyGemsMirrorSyncService = mock(RubyGemsMirrorSyncService.class);
    private final PackagistMirrorSyncService packagistMirrorSyncService = mock(PackagistMirrorSyncService.class);
    private final HexMirrorSyncService hexMirrorSyncService = mock(HexMirrorSyncService.class);
    private final NpmMirrorSyncService npmMirrorSyncService = mock(NpmMirrorSyncService.class);
    private final PyPiMirrorSyncService pyPiMirrorSyncService = mock(PyPiMirrorSyncService.class);
    private final NuGetMirrorSyncService nuGetMirrorSyncService = mock(NuGetMirrorSyncService.class);
    private final GoMirrorSyncService goMirrorSyncService = mock(GoMirrorSyncService.class);
    private final PubMirrorSyncService pubMirrorSyncService = mock(PubMirrorSyncService.class);

    private RegistryMirrorSyncService service;

    @BeforeEach
    void setUp() {
        service = new RegistryMirrorSyncService(identifiedProductRepository, registryMirrorSeedNameRepository,
                registryPackageMirrorRepository, cratesIoMirrorSyncService, rubyGemsMirrorSyncService,
                packagistMirrorSyncService, hexMirrorSyncService, npmMirrorSyncService, pyPiMirrorSyncService,
                nuGetMirrorSyncService, goMirrorSyncService, pubMirrorSyncService, directExecutor);
        ReflectionTestUtils.setField(service, "chunkSize", 200);
        ReflectionTestUtils.setField(service, "freshnessDays", 7);

        // Every ecosystem defaults to "nothing observed yet" unless a test overrides it.
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(List.of());
        when(registryMirrorSeedNameRepository.findDistinctPackageNames(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(List.of());
        // No name is "freshly synced" by default -- every observed name in a test that doesn't
        // override this is a sync candidate, matching this suite's pre-existing behavior/expectations.
        when(registryPackageMirrorRepository.findFreshlySyncedNormalizedPackageNames(anyString(), any()))
                .thenReturn(Set.of());
        when(cratesIoMirrorSyncService.syncPackages(anyList())).thenReturn(new CratesIoMirrorSyncService.SyncOutcome(0, 0));
        when(rubyGemsMirrorSyncService.syncPackages(anyList())).thenReturn(new RubyGemsMirrorSyncService.SyncOutcome(0, 0));
        when(packagistMirrorSyncService.syncPackages(anyList())).thenReturn(new PackagistMirrorSyncService.SyncOutcome(0, 0));
        when(hexMirrorSyncService.syncPackages(anyList())).thenReturn(new HexMirrorSyncService.SyncOutcome(0, 0));
        when(npmMirrorSyncService.syncPackages(anyList())).thenReturn(new NpmMirrorSyncService.SyncOutcome(0, 0));
        when(pyPiMirrorSyncService.syncPackages(anyList())).thenReturn(new PyPiMirrorSyncService.SyncOutcome(0, 0));
        when(nuGetMirrorSyncService.syncPackages(anyList())).thenReturn(new NuGetMirrorSyncService.SyncOutcome(0, 0));
        when(goMirrorSyncService.syncModules(anyList())).thenReturn(new GoMirrorSyncService.SyncOutcome(0, 0));
        when(pubMirrorSyncService.syncPackages(anyList())).thenReturn(new PubMirrorSyncService.SyncOutcome(0, 0));
    }

    @Test
    void tryBeginFullSyncWinsOnlyOnce() {
        assertThat(service.tryBeginFullSync()).isTrue();
        assertThat(service.tryBeginFullSync()).isFalse();

        service.releaseFullSyncGuard();

        assertThat(service.tryBeginFullSync()).isTrue();
    }

    @Test
    void syncAllAndReleaseReleasesTheGuardEvenWhenAnEcosystemSyncThrows() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("crates.io"))
                .thenReturn(List.of("serde"));
        when(cratesIoMirrorSyncService.syncPackages(anyList())).thenThrow(new RuntimeException("crates.io unreachable"));

        assertThat(service.tryBeginFullSync()).isTrue();
        service.syncAllAndRelease();

        assertThat(service.tryBeginFullSync())
                .as("guard must be released even though the sync threw")
                .isTrue();
    }

    /**
     * Senior review, PR #145 REVISE (closed-mode backlog item 186): before this fix, {@code
     * syncAll} collected each ecosystem's future with {@code .join()} in task order, so the first
     * ecosystem to fail threw immediately and left the other 8 ecosystems' futures un-awaited (and
     * whatever they themselves logged/threw silently discarded) while {@code syncAllAndRelease}'s
     * {@code finally} had already released the guard — a real race for a second sync to start while
     * those 8 were still running. A per-ecosystem failure must now be isolated: the other 8
     * ecosystems still get synced, {@code syncAllAndRelease} returns normally (never throws) rather
     * than propagating the failing ecosystem's exception, and the guard is available again only
     * once every ecosystem's task has actually finished.
     */
    @Test
    void syncAllAndReleaseIsolatesAPerEcosystemFailureFromTheOther8Ecosystems() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("crates.io"))
                .thenReturn(List.of("serde"));
        when(cratesIoMirrorSyncService.syncPackages(anyList())).thenThrow(new RuntimeException("crates.io unreachable"));
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm")).thenReturn(List.of("lodash"));
        when(npmMirrorSyncService.syncPackages(List.of("lodash")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        assertThat(service.tryBeginFullSync()).isTrue();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(npmMirrorSyncService).syncPackages(List.of("lodash"));
        assertThat(outcome.totalSynced())
                .as("the failing ecosystem contributes 0, but npm's 1 still counts")
                .isEqualTo(1);
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("npm", 1);
        assertThat(service.tryBeginFullSync())
                .as("guard must be released once every ecosystem's task (including the failing one) has finished")
                .isTrue();
    }

    @Test
    void syncAllAndReleasePullsObservedNamesPerEcosystemAndCallsEachEcosystemsSyncMethod() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("crates.io")).thenReturn(List.of("serde"));
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm")).thenReturn(List.of("lodash", "react"));
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("go")).thenReturn(List.of("github.com/gin-gonic/gin"));
        when(cratesIoMirrorSyncService.syncPackages(List.of("serde")))
                .thenReturn(new CratesIoMirrorSyncService.SyncOutcome(1, 0));
        when(npmMirrorSyncService.syncPackages(List.of("lodash", "react")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(2, 0));
        when(goMirrorSyncService.syncModules(List.of("github.com/gin-gonic/gin")))
                .thenReturn(new GoMirrorSyncService.SyncOutcome(0, 1));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        assertThat(outcome.totalSynced()).isEqualTo(3);
        assertThat(outcome.totalUnresolved()).isEqualTo(1);
        assertThat(outcome.observedNameCountByEcosystem())
                .containsEntry("crates.io", 1)
                .containsEntry("npm", 2)
                .containsEntry("go", 1)
                .containsEntry("rubygems", 0)
                .containsEntry("pub", 0);
        verify(cratesIoMirrorSyncService).syncPackages(List.of("serde"));
        verify(npmMirrorSyncService).syncPackages(List.of("lodash", "react"));
        verify(goMirrorSyncService).syncModules(List.of("github.com/gin-gonic/gin"));
        verify(rubyGemsMirrorSyncService, never()).syncPackages(anyList());
    }

    @Test
    void syncAllAndReleaseChunksALargeObservedNameListRatherThanSendingItAllInOneCall() {
        ReflectionTestUtils.setField(service, "chunkSize", 2);
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .thenReturn(List.of("a", "b", "c", "d", "e"));
        when(npmMirrorSyncService.syncPackages(List.of("a", "b")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(2, 0));
        when(npmMirrorSyncService.syncPackages(List.of("c", "d")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 1));
        when(npmMirrorSyncService.syncPackages(List.of("e")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("a", "b"));
        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("c", "d"));
        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("e"));
        assertThat(outcome.totalSynced()).isEqualTo(4);
        assertThat(outcome.totalUnresolved()).isEqualTo(1);
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("npm", 5);
    }

    /**
     * Regression test for senior review, PR #122 REVISE: {@code chunkSize=0} used to turn {@code
     * chunk}'s {@code i += chunkSize} into an infinite loop (unbounded empty-sublist accumulation,
     * eventual OOM, guard never released since {@code syncAllAndRelease}'s {@code finally} is never
     * reached). {@code assertTimeoutPreemptively} fails the test on a timeout instead of hanging
     * the whole build if this regresses.
     */
    @Test
    void syncEcosystemFallsBackToDefaultChunkSizeWhenConfiguredZeroRatherThanHanging() {
        ReflectionTestUtils.setField(service, "chunkSize", 0);
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .thenReturn(List.of("a", "b", "c"));
        when(npmMirrorSyncService.syncPackages(List.of("a", "b", "c")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(3, 0));

        assertThat(service.tryBeginFullSync()).isTrue();
        RegistryMirrorSyncService.SyncOutcome outcome = assertTimeoutPreemptively(Duration.ofSeconds(5),
                () -> service.syncAllAndRelease());

        // Falls back to DEFAULT_CHUNK_SIZE (200) -- 3 names all fit in a single chunk/call.
        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("a", "b", "c"));
        assertThat(outcome.totalSynced()).isEqualTo(3);
        // The finally block in syncAllAndRelease was actually reached (not stuck in an infinite
        // chunk() loop before ever returning).
        assertThat(service.tryBeginFullSync())
                .as("guard must be released once the (non-hanging) sync completes")
                .isTrue();
    }

    /**
     * Same regression coverage as the {@code chunkSize=0} case above, for a negative value —
     * before the fix this threw {@code IndexOutOfBoundsException} from {@code List#subList}
     * instead of hanging, but was equally an unvalidated bad value driving loop/slicing logic.
     */
    @Test
    void syncEcosystemFallsBackToDefaultChunkSizeWhenConfiguredNegative() {
        ReflectionTestUtils.setField(service, "chunkSize", -1);
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .thenReturn(List.of("a", "b", "c"));
        when(npmMirrorSyncService.syncPackages(List.of("a", "b", "c")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(3, 0));

        assertThat(service.tryBeginFullSync()).isTrue();
        RegistryMirrorSyncService.SyncOutcome outcome = assertTimeoutPreemptively(Duration.ofSeconds(5),
                () -> service.syncAllAndRelease());

        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("a", "b", "c"));
        assertThat(outcome.totalSynced()).isEqualTo(3);
        assertThat(service.tryBeginFullSync())
                .as("guard must be released once the (non-throwing) sync completes")
                .isTrue();
    }

    /**
     * Closed-mode backlog item 185: a package name only present in {@code
     * registry_mirror_seed_name} (never resolved live, so absent from {@code identified_products})
     * must still be picked up by a sync — this is the whole point of the new seed source.
     */
    @Test
    void syncAllAndReleaseIncludesOperatorSuppliedSeedNamesNotYetInIdentifiedProducts() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm")).thenReturn(List.of());
        when(registryMirrorSeedNameRepository.findDistinctPackageNames("npm")).thenReturn(List.of("left-pad"));
        when(npmMirrorSyncService.syncPackages(List.of("left-pad")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(npmMirrorSyncService).syncPackages(List.of("left-pad"));
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("npm", 1);
    }

    /**
     * A name present in both sources must be synced exactly once, not twice.
     */
    @Test
    void syncAllAndReleaseDeduplicatesANameObservedInBothSeedSources() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm")).thenReturn(List.of("lodash"));
        when(registryMirrorSeedNameRepository.findDistinctPackageNames("npm")).thenReturn(List.of("lodash"));
        when(npmMirrorSyncService.syncPackages(List.of("lodash")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(npmMirrorSyncService, times(1)).syncPackages(List.of("lodash"));
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("npm", 1);
    }

    /**
     * Closed-mode backlog item 186: every one of the 9 per-ecosystem syncs must still run when
     * fanned out onto a real (not synchronous) {@link Executor} — the point of parallelizing
     * {@code syncAll} is that all 9 can genuinely be in flight at once, not just that the
     * synchronous test double used elsewhere in this suite happens to work.
     */
    @Test
    void syncAllAndReleaseRunsEveryEcosystemOnAGenuinelyConcurrentExecutor() {
        java.util.concurrent.ExecutorService realPool = java.util.concurrent.Executors.newFixedThreadPool(9);
        RegistryMirrorSyncService concurrentService = new RegistryMirrorSyncService(identifiedProductRepository,
                registryMirrorSeedNameRepository, registryPackageMirrorRepository, cratesIoMirrorSyncService,
                rubyGemsMirrorSyncService, packagistMirrorSyncService, hexMirrorSyncService, npmMirrorSyncService,
                pyPiMirrorSyncService, nuGetMirrorSyncService, goMirrorSyncService, pubMirrorSyncService, realPool);
        ReflectionTestUtils.setField(concurrentService, "chunkSize", 200);
        ReflectionTestUtils.setField(concurrentService, "freshnessDays", 7);
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("crates.io")).thenReturn(List.of("serde"));
        when(cratesIoMirrorSyncService.syncPackages(List.of("serde")))
                .thenReturn(new CratesIoMirrorSyncService.SyncOutcome(1, 0));

        try {
            assertThat(concurrentService.tryBeginFullSync()).isTrue();
            RegistryMirrorSyncService.SyncOutcome outcome = assertTimeoutPreemptively(Duration.ofSeconds(10),
                    concurrentService::syncAllAndRelease);

            assertThat(outcome.totalSynced()).isEqualTo(1);
            verify(cratesIoMirrorSyncService).syncPackages(List.of("serde"));
            verify(npmMirrorSyncService, never()).syncPackages(anyList());
        } finally {
            realPool.shutdownNow();
        }
    }

    /**
     * Closed-mode backlog item 186: a name whose {@code registry_package_mirror.last_synced_at} is
     * already within the freshness window must be skipped rather than re-synced.
     */
    @Test
    void syncAllAndReleaseSkipsANameAlreadySyncedWithinTheFreshnessWindow() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .thenReturn(List.of("lodash", "left-pad"));
        when(registryPackageMirrorRepository.findFreshlySyncedNormalizedPackageNames(
                org.mockito.ArgumentMatchers.eq("npm"), any()))
                .thenReturn(Set.of("lodash"));
        when(npmMirrorSyncService.syncPackages(List.of("left-pad")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(npmMirrorSyncService).syncPackages(List.of("left-pad"));
        verify(npmMirrorSyncService, never()).syncPackages(List.of("lodash", "left-pad"));
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("npm", 1);
    }

    /**
     * A name never synced before (no {@code registry_package_mirror} row) must never be filtered
     * out by the freshness check, regardless of what the mirror repository reports as "fresh" for
     * other names.
     */
    @Test
    void syncAllAndReleaseNeverFiltersOutANameWithNoPriorMirrorRow() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm"))
                .thenReturn(List.of("brand-new-package"));
        when(registryPackageMirrorRepository.findFreshlySyncedNormalizedPackageNames(
                org.mockito.ArgumentMatchers.eq("npm"), any()))
                .thenReturn(Set.of("some-other-already-mirrored-package"));
        when(npmMirrorSyncService.syncPackages(List.of("brand-new-package")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        service.syncAllAndRelease();

        verify(npmMirrorSyncService).syncPackages(List.of("brand-new-package"));
    }

    /**
     * Closed-mode backlog item 186 (senior review, PR #145 REVISE): the freshness check must
     * compare *normalized* names (see {@link com.vulncheck.app.service.vuln.
     * OsvPackageNameNormalizer#normalize}), not raw ones — crates.io folds {@code -}/{@code _}
     * together, so a seed name spelled {@code Serde_Json} must still be recognized as fresh when
     * {@code registry_package_mirror} has it recorded (normalized) as {@code serde-json}. The other
     * freshness tests in this class all use npm, whose normalization is a plain lowercase fold and
     * so never actually exercises the crates.io-specific {@code -}/{@code _} folding rule.
     */
    @Test
    void syncAllAndReleaseSkipsACratesIoNameAlreadySyncedUnderItsNormalizedSpelling() {
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("crates.io"))
                .thenReturn(List.of("Serde_Json"));
        when(registryPackageMirrorRepository.findFreshlySyncedNormalizedPackageNames(
                org.mockito.ArgumentMatchers.eq("crates.io"), any()))
                .thenReturn(Set.of("serde-json"));

        service.tryBeginFullSync();
        RegistryMirrorSyncService.SyncOutcome outcome = service.syncAllAndRelease();

        verify(cratesIoMirrorSyncService, never()).syncPackages(anyList());
        assertThat(outcome.observedNameCountByEcosystem()).containsEntry("crates.io", 0);
    }

    /**
     * {@code app.registry-mirror-sync-freshness-days} <= 0 disables the filter entirely — same
     * escape-hatch convention as {@code chunkSize}'s own non-positive fallback.
     */
    @Test
    void syncAllAndReleaseDoesNotFilterAtAllWhenFreshnessDaysIsNonPositive() {
        ReflectionTestUtils.setField(service, "freshnessDays", 0);
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem("npm")).thenReturn(List.of("lodash"));
        when(npmMirrorSyncService.syncPackages(List.of("lodash")))
                .thenReturn(new NpmMirrorSyncService.SyncOutcome(1, 0));

        service.tryBeginFullSync();
        service.syncAllAndRelease();

        verify(npmMirrorSyncService).syncPackages(List.of("lodash"));
        verifyNoInteractions(registryPackageMirrorRepository);
    }

    @Test
    void addOperatorSuppliedNamesRejectsAnUnknownEcosystem() {
        assertThatThrownBy(() -> service.addOperatorSuppliedNames("maven", List.of("com.example:widget")))
                .isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(registryMirrorSeedNameRepository);
    }

    @Test
    void addOperatorSuppliedNamesTrimsBlanksAndDeduplicatesBeforeInserting() {
        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome = service.addOperatorSuppliedNames("npm",
                List.of(" left-pad ", "left-pad", "", "  ", "is-odd"));

        assertThat(outcome.accepted()).isEqualTo(2);
        assertThat(outcome.rejected()).isEqualTo(0);
        verify(registryMirrorSeedNameRepository).insertBatch("npm", List.of("left-pad", "is-odd"));
    }

    @Test
    void addOperatorSuppliedNamesIsANoOpForAnAllBlankList() {
        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome =
                service.addOperatorSuppliedNames("npm", List.of("", "   ", "\n"));

        assertThat(outcome.accepted()).isEqualTo(0);
        assertThat(outcome.rejected()).isEqualTo(0);
        verifyNoInteractions(registryMirrorSeedNameRepository);
    }

    /**
     * Senior review, PR #126 REVISE (closed-mode backlog item 185): a {@code ..} path segment must
     * be rejected and must never reach {@code insertBatch}, since a name that leaks through would
     * flow straight into {@code CratesIoMirrorSyncService}/{@code PackagistMirrorSyncService}'s
     * un-encoded URL assembly (closed-mode backlog item 184).
     */
    @Test
    void addOperatorSuppliedNamesRejectsATraversalSegmentAndNeverReachesInsertBatch() {
        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome =
                service.addOperatorSuppliedNames("npm", List.of("../../etc/passwd", "left-pad"));

        assertThat(outcome.accepted()).isEqualTo(1);
        assertThat(outcome.rejected()).isEqualTo(1);
        verify(registryMirrorSeedNameRepository).insertBatch("npm", List.of("left-pad"));
    }

    /** Same REVISE item: a name over 200 characters must be rejected. */
    @Test
    void addOperatorSuppliedNamesRejectsANameOver200Characters() {
        String tooLong = "a".repeat(201);
        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome =
                service.addOperatorSuppliedNames("npm", List.of(tooLong, "left-pad"));

        assertThat(outcome.accepted()).isEqualTo(1);
        assertThat(outcome.rejected()).isEqualTo(1);
        verify(registryMirrorSeedNameRepository).insertBatch("npm", List.of("left-pad"));
    }

    /**
     * Same REVISE item: every legitimate name shape across the 9 mirrored ecosystems must pass —
     * see {@link RegistryMirrorSyncService}'s {@code SEED_NAME_ALLOWED_CHARS} javadoc.
     */
    @Test
    void addOperatorSuppliedNamesAcceptsLegitimateNamesFromEveryEcosystemShape() {
        List<String> legitimateNames = List.of("github.com/foo/bar", "@scope/pkg", "vendor/pkg", "Newtonsoft.Json");

        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome =
                service.addOperatorSuppliedNames("npm", legitimateNames);

        assertThat(outcome.accepted()).isEqualTo(4);
        assertThat(outcome.rejected()).isEqualTo(0);
        verify(registryMirrorSeedNameRepository).insertBatch("npm", legitimateNames);
    }

    /** Same REVISE item: a mixed valid/invalid list inserts only the valid names and reports both counts. */
    @Test
    void addOperatorSuppliedNamesInsertsOnlyValidNamesAndReportsBothCountsForAMixedList() {
        RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome = service.addOperatorSuppliedNames("npm",
                List.of("left-pad", "..", "is-odd", "//double-slash", "chalk"));

        assertThat(outcome.accepted()).isEqualTo(3);
        assertThat(outcome.rejected()).isEqualTo(2);
        verify(registryMirrorSeedNameRepository).insertBatch("npm", List.of("left-pad", "is-odd", "chalk"));
    }

    /**
     * Senior review, PR #126 REVISE (closed-mode backlog item 185): a submission whose cleaned-up
     * name count exceeds the 10,000-name cap must be rejected in full — no partial insert, and the
     * repository must never be touched.
     */
    @Test
    void addOperatorSuppliedNamesRejectsTheWholeBatchWhenOver10000NamesRatherThanTouchingTheRepository() {
        List<String> tooManyNames = java.util.stream.IntStream.range(0, 10_001)
                .mapToObj(i -> "package-" + i)
                .toList();

        assertThatThrownBy(() -> service.addOperatorSuppliedNames("npm", tooManyNames))
                .isInstanceOf(RegistryMirrorSyncService.SeedNameBatchTooLargeException.class);
        verifyNoInteractions(registryMirrorSeedNameRepository);
    }
}
