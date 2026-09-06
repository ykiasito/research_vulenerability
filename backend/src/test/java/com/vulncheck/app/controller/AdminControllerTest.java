package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.CpeDictionarySyncStateRepository;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.NvdCveSyncService;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.osv.OsvSyncService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.ui.ExtendedModelMap;
import org.springframework.ui.Model;
import org.springframework.web.client.RestClient;

/**
 * {@link AdminController#cpeFullSync} — plain Mockito unit test invoking the controller method
 * directly (this codebase has no MockMvc/@WebMvcTest infrastructure elsewhere; see {@link
 * JobControllerTest} for the same convention). {@code CountDownLatch}es make the background
 * sync's in-flight window deterministic instead of relying on sleeps.
 */
@ExtendWith(MockitoExtension.class)
class AdminControllerTest {

    @Mock
    private NvdCpeSyncService nvdCpeSyncService;
    @Mock
    private UserApiKeyService userApiKeyService;
    @Mock
    private UserRepository userRepository;
    @Mock
    private CveOrgSyncService cveOrgSyncService;
    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;
    @Mock
    private SiemensCsafSyncService siemensCsafSyncService;
    @Mock
    private RedHatCsafSyncService redHatCsafSyncService;
    @Mock
    private CsafSyncStateRepository csafSyncStateRepository;
    @Mock
    private GhsaSyncService ghsaSyncService;
    @Mock
    private GhsaSyncStateRepository ghsaSyncStateRepository;
    @Mock
    private GhsaSyncFailureRepository ghsaSyncFailureRepository;
    @Mock
    private OsvSyncService osvSyncService;
    @Mock
    private OsvSyncStateRepository osvSyncStateRepository;
    @Mock
    private OsvSyncFailureRepository osvSyncFailureRepository;
    @Mock
    private RegistryMirrorSyncService registryMirrorSyncService;
    @Mock
    private NvdCveSyncService nvdCveSyncService;
    @Mock
    private NvdCveSyncStateRepository nvdCveSyncStateRepository;
    @Mock
    private CpeDictionarySyncStateRepository cpeDictionarySyncStateRepository;

    private AdminController newController() {
        return new AdminController(nvdCpeSyncService, userApiKeyService, userRepository, cveOrgSyncService,
                cveOrgSyncStateRepository, siemensCsafSyncService, redHatCsafSyncService, csafSyncStateRepository,
                ghsaSyncService, ghsaSyncStateRepository, ghsaSyncFailureRepository, osvSyncService,
                osvSyncStateRepository, osvSyncFailureRepository, registryMirrorSyncService, nvdCveSyncService,
                nvdCveSyncStateRepository, cpeDictionarySyncStateRepository);
    }

    @Test
    void cpeFullSyncStartsAnUnfilteredBackgroundSyncAndReturnsImmediately() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return new SyncOutcome(42, true);
        });

        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.cpeFullSync(model);

        // The controller call itself must return right away, without waiting for the (multi-hour
        // in production) sync to finish.
        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("開始しました");
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("background thread should have invoked syncAllAndRelease(Optional.empty()) by now")
                .isTrue();
        verify(nvdCpeSyncService).syncAllAndRelease(Optional.empty());

        release.countDown();
    }

    @Test
    void cpeFullSyncReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        // Regression test for task-backlog item 136: if starting the worker thread itself throws
        // (e.g. native-thread exhaustion) after tryBeginFullSync() already won the slot,
        // syncAllAndRelease()'s own finally-release never runs — cpeFullSync() must release the
        // guard itself instead of leaving fullSyncRunning stuck true until a restart.
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true);
        AdminController controller = spy(newController());
        doThrow(new RuntimeException("unable to create native thread")).when(controller).startFullSyncWorker();
        Model model = new ExtendedModelMap();

        String view = controller.cpeFullSync(model);

        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("失敗しました");
        verify(nvdCpeSyncService, times(1)).releaseFullSyncGuard();
        verify(nvdCpeSyncService, never()).syncAllAndRelease(Optional.empty());
    }

    @Test
    void cpeFullSyncRejectsASecondStartWhileOneIsAlreadyRunning() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        // The real service's tryBeginFullSync/syncAllAndRelease pair is itself the guard (an
        // AtomicBoolean CAS in the service), so this test exercises the controller's contract
        // with that guard: the second call must see tryBeginFullSync() return false and must
        // never reach syncAllAndRelease at all.
        when(nvdCpeSyncService.tryBeginFullSync()).thenReturn(true, false);
        when(nvdCpeSyncService.syncAllAndRelease(Optional.empty())).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return new SyncOutcome(1, true);
        });

        AdminController controller = newController();
        controller.cpeFullSync(new ExtendedModelMap());
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("first call's background thread should have entered syncAllAndRelease by now")
                .isTrue();

        Model secondModel = new ExtendedModelMap();
        String secondView = controller.cpeFullSync(secondModel);

        assertThat(secondView).isEqualTo("admin/cpe-dictionary");
        assertThat(secondModel.getAttribute("result")).asString().contains("既に実行中");
        // Only the first call's background thread ever reached the service — the second call
        // must have been rejected by tryBeginFullSync() before starting a competing thread.
        verify(nvdCpeSyncService, times(1)).syncAllAndRelease(Optional.empty());

        release.countDown();
    }

    @Test
    void cpeFullSyncSeesAlreadyRunningWhenAnotherCallerHoldsTheSlotOnTheSameSharedServiceInstance() {
        // Regression case from the task brief: a real (non-mocked) NvdCpeSyncService instance
        // shared between two independent callers — here, a call standing in for
        // CpeDictionaryBootstrapSync's startup-triggered sync grabbing the slot first, then
        // AdminController#cpeFullSync trying to start a second, concurrent full sync against that
        // same instance. Before this fix each caller had its own separate guard (the controller's
        // own AtomicBoolean field vs. no guard at all in CpeDictionaryBootstrapSync), so this
        // exact scenario would have let both syncs run at once.
        CpeDictionaryRepository sharedRepository = mock(CpeDictionaryRepository.class);
        NvdCpeSyncService sharedService = new NvdCpeSyncService(
                mock(RestClient.class), mock(RestClient.class), sharedRepository, new NvdRateLimiter(),
                mock(CpeDictionarySyncStateRepository.class));

        // Stand-in for CpeDictionaryBootstrapSync.run() winning the race and starting first.
        assertThat(sharedService.tryBeginFullSync()).isTrue();

        AdminController controller = new AdminController(sharedService, userApiKeyService, userRepository,
                cveOrgSyncService, cveOrgSyncStateRepository, siemensCsafSyncService, redHatCsafSyncService,
                csafSyncStateRepository, ghsaSyncService, ghsaSyncStateRepository, ghsaSyncFailureRepository,
                osvSyncService, osvSyncStateRepository, osvSyncFailureRepository, registryMirrorSyncService,
                nvdCveSyncService, nvdCveSyncStateRepository, cpeDictionarySyncStateRepository);
        Model model = new ExtendedModelMap();

        String view = controller.cpeFullSync(model);

        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("既に実行中");
        // The controller's attempt must never have reached syncAllAndRelease at all, let alone
        // made a network call or touched the repository, once the slot was denied.
        verifyNoInteractions(sharedRepository);
    }

    // --- closed-mode backlog item 330 (A): blank keyword must never reach NvdCpeSyncService -----

    @Test
    void syncRejectsBlankKeywordWithoutCallingTheServiceOrLookingUpTheUser() {
        AdminController controller = newController();
        Model model = new ExtendedModelMap();
        UserDetails userDetails = mock(UserDetails.class);

        String view = controller.sync("   ", userDetails, model);

        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("空欄");
        verifyNoInteractions(nvdCpeSyncService, userRepository, userDetails);
    }

    @Test
    void registryMirrorFullSyncStartsABackgroundSyncAndReturnsImmediately() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(true);
        when(registryMirrorSyncService.syncAllAndRelease()).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return new RegistryMirrorSyncService.SyncOutcome(10, 2, Map.of("npm", 12));
        });

        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorFullSync(model);

        // The controller call itself must return right away, without waiting for the sync to finish.
        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("開始しました");
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("background thread should have invoked syncAllAndRelease() by now")
                .isTrue();
        verify(registryMirrorSyncService).syncAllAndRelease();

        release.countDown();
    }

    @Test
    void registryMirrorFullSyncReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(true);
        AdminController controller = spy(newController());
        doThrow(new RuntimeException("unable to create native thread")).when(controller).startRegistryMirrorSyncWorker();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorFullSync(model);

        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("失敗しました");
        verify(registryMirrorSyncService, times(1)).releaseFullSyncGuard();
        verify(registryMirrorSyncService, never()).syncAllAndRelease();
    }

    @Test
    void registryMirrorFullSyncRejectsASecondStartWhileOneIsAlreadyRunning() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(registryMirrorSyncService.tryBeginFullSync()).thenReturn(true, false);
        when(registryMirrorSyncService.syncAllAndRelease()).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return new RegistryMirrorSyncService.SyncOutcome(1, 0, Map.of());
        });

        AdminController controller = newController();
        controller.registryMirrorFullSync(new ExtendedModelMap());
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("first call's background thread should have entered syncAllAndRelease by now")
                .isTrue();

        Model secondModel = new ExtendedModelMap();
        String secondView = controller.registryMirrorFullSync(secondModel);

        assertThat(secondView).isEqualTo("admin/registry-mirror");
        assertThat(secondModel.getAttribute("result")).asString().contains("既に実行中");
        verify(registryMirrorSyncService, times(1)).syncAllAndRelease();

        release.countDown();
    }

    @Test
    void registryMirrorAddSeedNamesSplitsOnNewlinesAndCommasAndReportsTheSubmittedCount() {
        when(registryMirrorSyncService.addOperatorSuppliedNames("npm", List.of("left-pad", "is-odd", "chalk")))
                .thenReturn(new RegistryMirrorSyncService.SeedNameSubmissionOutcome(3, 0));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorAddSeedNames("npm", "left-pad\nis-odd,chalk", model);

        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("3件");
        verify(registryMirrorSyncService).addOperatorSuppliedNames("npm", List.of("left-pad", "is-odd", "chalk"));
    }

    /**
     * Senior review, PR #126 REVISE (closed-mode backlog item 185): both the accepted count and the
     * rejected count must reach the operator, since a silently-skipped invalid name would otherwise
     * be indistinguishable from one that was never submitted.
     */
    @Test
    void registryMirrorAddSeedNamesReportsBothTheAcceptedAndRejectedCounts() {
        when(registryMirrorSyncService.addOperatorSuppliedNames("npm", List.of("left-pad", "..")))
                .thenReturn(new RegistryMirrorSyncService.SeedNameSubmissionOutcome(1, 1));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorAddSeedNames("npm", "left-pad\n..", model);

        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("1件").contains("却下");
    }

    @Test
    void registryMirrorAddSeedNamesReportsAnErrorForAnUnknownEcosystemRatherThanPropagating() {
        when(registryMirrorSyncService.addOperatorSuppliedNames("maven", List.of("com.example:widget")))
                .thenThrow(new IllegalArgumentException("Unknown registry mirror ecosystem: maven"));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorAddSeedNames("maven", "com.example:widget", model);

        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("不正");
    }

    /**
     * Senior review, PR #126 REVISE (closed-mode backlog item 185): an over-10,000-name submission
     * must surface a clear rejection message to the operator rather than propagating a raw 500 (this
     * app has no {@code @ControllerAdvice}/{@code @ExceptionHandler}).
     */
    @Test
    void registryMirrorAddSeedNamesReportsAClearMessageWhenTheBatchIsTooLarge() {
        when(registryMirrorSyncService.addOperatorSuppliedNames("npm", List.of("left-pad")))
                .thenThrow(new RegistryMirrorSyncService.SeedNameBatchTooLargeException(
                        "シード名の投稿を却下しました（npm）: クリーンアップ後 10001 件が上限（10000件）を超えています。"));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.registryMirrorAddSeedNames("npm", "left-pad", model);

        assertThat(view).isEqualTo("admin/registry-mirror");
        assertThat(model.getAttribute("result")).asString().contains("上限");
    }

    @Test
    void nvdCveSyncNowStartsABackgroundTickAndReturnsImmediately() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        when(nvdCveSyncService.runBackfillTickAndRelease(eq(Optional.empty()), any())).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return new NvdCveSyncService.SyncOutcome(120, false);
        });

        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.nvdCveSyncNow(model);

        assertThat(view).isEqualTo("admin/nvd-cve");
        assertThat(model.getAttribute("result")).asString().contains("開始しました");
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("background thread should have invoked runBackfillTickAndRelease() by now")
                .isTrue();
        verify(nvdCveSyncService).runBackfillTickAndRelease(eq(Optional.empty()), any());

        release.countDown();
    }

    @Test
    void nvdCveSyncNowRejectsASecondStartWhileOneIsAlreadyRunning() {
        when(nvdCveSyncService.tryBeginRun()).thenReturn(false);
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.nvdCveSyncNow(model);

        assertThat(view).isEqualTo("admin/nvd-cve");
        assertThat(model.getAttribute("result")).asString().contains("既に実行中");
        verify(nvdCveSyncService, never()).runBackfillTickAndRelease(any(), any());
    }

    @Test
    void nvdCveSyncNowReleasesTheGuardWhenTheWorkerThreadFailsToStart() {
        when(nvdCveSyncService.tryBeginRun()).thenReturn(true);
        AdminController controller = spy(newController());
        doThrow(new RuntimeException("unable to create native thread")).when(controller).startNvdCveBackfillWorker();
        Model model = new ExtendedModelMap();

        String view = controller.nvdCveSyncNow(model);

        assertThat(view).isEqualTo("admin/nvd-cve");
        assertThat(model.getAttribute("result")).asString().contains("失敗しました");
        verify(nvdCveSyncService, times(1)).releaseRunGuard();
        verify(nvdCveSyncService, never()).runBackfillTickAndRelease(any(), any());
    }

    @Test
    void nvdCveFormExposesTheSyncStateToTheModel() {
        com.vulncheck.app.entity.NvdCveSyncState state = new com.vulncheck.app.entity.NvdCveSyncState();
        when(nvdCveSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.nvdCveForm(model);

        assertThat(view).isEqualTo("admin/nvd-cve");
        assertThat(model.getAttribute("syncState")).isSameAs(state);
    }

    /** Closed-mode backlog item 332: {@code GET /admin/cpe-dictionary} follows the same
     *  syncState-exposure pattern as {@link #nvdCveFormExposesTheSyncStateToTheModel}. */
    @Test
    void formExposesTheCpeDictionarySyncStateToTheModel() {
        com.vulncheck.app.entity.CpeDictionarySyncState state = new com.vulncheck.app.entity.CpeDictionarySyncState();
        when(cpeDictionarySyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.form(model);

        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("syncState")).isSameAs(state);
    }

    // --- closed-mode backlog item 379 follow-up (senior review on PR #278): /admin/cve-org must
    // actually surface CveOrgSyncState (including last_sync_error), or item 379's own point --
    // making a silently-stuck CVE.org sync visible -- is not actually achieved -----------------

    /** Same syncState-exposure pattern as {@link #nvdCveFormExposesTheSyncStateToTheModel}. */
    @Test
    void cveOrgFormExposesTheSyncStateToTheModel() {
        CveOrgSyncState state = new CveOrgSyncState();
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.cveOrgForm(model);

        assertThat(view).isEqualTo("admin/cve-org");
        assertThat(model.getAttribute("syncState")).isSameAs(state);
    }

    /**
     * The whole point of item 379: a failed sync (however many records it upserted before failing)
     * must never look like a plain green success on this page. {@link
     * CveOrgSyncService#syncDelta} itself returns a plain {@code int}, so the controller cannot
     * tell success from failure from that return value alone -- it must re-read the state {@code
     * CveOrgSyncService} just wrote.
     */
    @Test
    void cveOrgSyncDeltaShowsTheFailureInsteadOfAMisleadingSuccessMessage() {
        when(cveOrgSyncService.syncDelta()).thenReturn(0);
        CveOrgSyncState failedState = new CveOrgSyncState();
        failedState.setLastSyncError("delta sync failed after upserting 0 records (IOException)");
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(failedState));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.cveOrgSyncDelta(model);

        assertThat(view).isEqualTo("admin/cve-org");
        assertThat(model.getAttribute("result")).isNull();
        assertThat(model.getAttribute("syncFailureMessage")).asString()
                .contains("失敗").contains("delta sync failed after upserting 0 records");
        assertThat(model.getAttribute("syncState")).isSameAs(failedState);
    }

    /** A genuinely successful (even if zero-upsert, e.g. "nothing new today") run must still show
     *  the plain green success message, not the failure branch. */
    @Test
    void cveOrgSyncDeltaShowsTheSuccessMessageWhenThereIsNoError() {
        when(cveOrgSyncService.syncDelta()).thenReturn(0);
        CveOrgSyncState healthyState = new CveOrgSyncState();
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(healthyState));
        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.cveOrgSyncDelta(model);

        assertThat(view).isEqualTo("admin/cve-org");
        assertThat(model.getAttribute("result")).asString().contains("差分同期しました");
        assertThat(model.getAttribute("syncFailureMessage")).isNull();
    }
}
