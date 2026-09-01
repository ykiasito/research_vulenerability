package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.osv.OsvSyncService;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
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

    private AdminController newController() {
        return new AdminController(nvdCpeSyncService, userApiKeyService, userRepository, cveOrgSyncService,
                siemensCsafSyncService, redHatCsafSyncService, csafSyncStateRepository, ghsaSyncService,
                ghsaSyncStateRepository, ghsaSyncFailureRepository, osvSyncService, osvSyncStateRepository,
                osvSyncFailureRepository);
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
                mock(RestClient.class), mock(RestClient.class), sharedRepository, new NvdRateLimiter());

        // Stand-in for CpeDictionaryBootstrapSync.run() winning the race and starting first.
        assertThat(sharedService.tryBeginFullSync()).isTrue();

        AdminController controller = new AdminController(sharedService, userApiKeyService, userRepository,
                cveOrgSyncService, siemensCsafSyncService, redHatCsafSyncService, csafSyncStateRepository,
                ghsaSyncService, ghsaSyncStateRepository, ghsaSyncFailureRepository, osvSyncService,
                osvSyncStateRepository, osvSyncFailureRepository);
        Model model = new ExtendedModelMap();

        String view = controller.cpeFullSync(model);

        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("既に実行中");
        // The controller's attempt must never have reached syncAllAndRelease at all, let alone
        // made a network call or touched the repository, once the slot was denied.
        verifyNoInteractions(sharedRepository);
    }
}
