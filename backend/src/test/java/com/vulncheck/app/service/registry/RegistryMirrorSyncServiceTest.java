package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.repository.IdentifiedProductRepository;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Unit coverage for {@link RegistryMirrorSyncService} — the observed-name seed source (closed-mode
 * backlog item 183), the per-ecosystem chunking, the aggregate totals, and the concurrency guard.
 * Every {@code *MirrorSyncService} is mocked: its own sync/parse behavior is covered by its own
 * dedicated test (e.g. {@code CratesIoMirrorSyncServiceTest}), so this class only needs to verify
 * that the orchestrator calls each one correctly and aggregates what it returns.
 */
class RegistryMirrorSyncServiceTest {

    private final IdentifiedProductRepository identifiedProductRepository = mock(IdentifiedProductRepository.class);
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
        service = new RegistryMirrorSyncService(identifiedProductRepository, cratesIoMirrorSyncService,
                rubyGemsMirrorSyncService, packagistMirrorSyncService, hexMirrorSyncService, npmMirrorSyncService,
                pyPiMirrorSyncService, nuGetMirrorSyncService, goMirrorSyncService, pubMirrorSyncService);
        ReflectionTestUtils.setField(service, "chunkSize", 200);

        // Every ecosystem defaults to "nothing observed yet" unless a test overrides it.
        when(identifiedProductRepository.findDistinctPackageNamesByEcosystem(org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(List.of());
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
        try {
            service.syncAllAndRelease();
        } catch (RuntimeException expected) {
            // propagates — the point of this test is only that the guard is released regardless.
        }

        assertThat(service.tryBeginFullSync())
                .as("guard must be released even though the sync threw")
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
}
