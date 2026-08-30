package com.vulncheck.app.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
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
        when(nvdCpeSyncService.syncAll(Optional.empty())).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return 42;
        });

        AdminController controller = newController();
        Model model = new ExtendedModelMap();

        String view = controller.cpeFullSync(model);

        // The controller call itself must return right away, without waiting for the (multi-hour
        // in production) sync to finish.
        assertThat(view).isEqualTo("admin/cpe-dictionary");
        assertThat(model.getAttribute("result")).asString().contains("開始しました");
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("background thread should have invoked syncAll(Optional.empty()) by now")
                .isTrue();
        verify(nvdCpeSyncService).syncAll(Optional.empty());

        release.countDown();
    }

    @Test
    void cpeFullSyncRejectsASecondStartWhileOneIsAlreadyRunning() throws InterruptedException {
        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        when(nvdCpeSyncService.syncAll(Optional.empty())).thenAnswer(invocation -> {
            started.countDown();
            release.await(5, TimeUnit.SECONDS);
            return 1;
        });

        AdminController controller = newController();
        controller.cpeFullSync(new ExtendedModelMap());
        assertThat(started.await(2, TimeUnit.SECONDS))
                .as("first call's background thread should have entered syncAll by now")
                .isTrue();

        Model secondModel = new ExtendedModelMap();
        String secondView = controller.cpeFullSync(secondModel);

        assertThat(secondView).isEqualTo("admin/cpe-dictionary");
        assertThat(secondModel.getAttribute("result")).asString().contains("既に実行中");
        // Only the first call's background thread ever reached the service — the second call
        // must have been rejected by the AtomicBoolean guard before starting a competing thread.
        verify(nvdCpeSyncService, times(1)).syncAll(Optional.empty());

        release.countDown();
    }
}
