package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * {@link NvdCpeSyncService#tryBeginFullSync} / {@link NvdCpeSyncService#syncAllAndRelease} — the
 * shared full-sync "already running" guard added so {@code AdminController}'s admin-triggered
 * sync and {@code CpeDictionaryBootstrapSync}'s startup-triggered sync can't run concurrently
 * against the same NVD rate limit and {@code cpe_dictionary} table (task-backlog item 68 REVISE).
 */
class NvdCpeSyncServiceTest {

    private MockRestServiceServer syncServer;
    private CpeDictionaryRepository cpeDictionaryRepository;
    private NvdCpeSyncService service;

    @BeforeEach
    void setUp() {
        RestClient externalApiRestClient = RestClient.builder().build();
        RestClient.Builder syncClientBuilder = RestClient.builder();
        syncServer = MockRestServiceServer.bindTo(syncClientBuilder).build();
        cpeDictionaryRepository = mock(CpeDictionaryRepository.class);
        service = new NvdCpeSyncService(externalApiRestClient, syncClientBuilder.build(), cpeDictionaryRepository,
                new NvdRateLimiter());
    }

    @Test
    void tryBeginFullSyncReturnsFalseWhileASlotIsAlreadyHeld() {
        assertThat(service.tryBeginFullSync()).isTrue();
        assertThat(service.tryBeginFullSync())
                .as("a second caller must not be able to acquire the slot while the first still holds it")
                .isFalse();
    }

    @Test
    void syncAllAndReleaseFreesTheSlotOnNormalCompletion() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncAllAndRelease(Optional.empty());

        assertThat(upserted).isZero();
        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again after a normal completion")
                .isTrue();
        syncServer.verify();
    }

    @Test
    void syncAllAndReleaseFreesTheSlotEvenWhenTheSyncThrows() {
        assertThat(service.tryBeginFullSync()).isTrue();
        syncServer.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(
                        "{\"totalResults\":1,\"products\":[{\"cpe\":{\"cpeName\":"
                                + "\"cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*\",\"titles\":[]}}]}",
                        MediaType.APPLICATION_JSON));
        doThrow(new RuntimeException("db down")).when(cpeDictionaryRepository).upsertBatch(anyList());

        assertThatThrownBy(() -> service.syncAllAndRelease(Optional.empty()))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("db down");

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again even when the sync itself throws")
                .isTrue();
        syncServer.verify();
    }
}
