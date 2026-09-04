package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.queryParam;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import java.util.Optional;
import org.hamcrest.Matchers;
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
 * against the same NVD rate limit and {@code cpe_dictionary} table, and {@link
 * NvdCpeSyncService.SyncOutcome#completed}, which lets callers tell a clean finish from an early
 * abort instead of logging both as "finished" (task-backlog item 68 REVISE).
 */
class NvdCpeSyncServiceTest {

    private MockRestServiceServer syncServer;
    private CpeDictionaryRepository cpeDictionaryRepository;
    private NvdCpeSyncService service;

    @BeforeEach
    void setUp() {
        RestClient.Builder syncClientBuilder = RestClient.builder();
        syncServer = MockRestServiceServer.bindTo(syncClientBuilder).build();
        cpeDictionaryRepository = mock(CpeDictionaryRepository.class);
        service = new NvdCpeSyncService(syncClientBuilder.build(), cpeDictionaryRepository,
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

        SyncOutcome outcome = service.syncAllAndRelease(Optional.empty());

        assertThat(outcome.upserted()).isZero();
        assertThat(outcome.completed()).isTrue();
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

    @Test
    void releaseFullSyncGuardFreesTheSlotWithoutRunningASync() {
        // Stand-in for a caller whose worker-thread spawn/start itself failed after winning the
        // slot: syncAllAndRelease() (and its own finally-release) never runs, so this method is
        // the only way the slot gets freed again (task-backlog items 81/136/141).
        assertThat(service.tryBeginFullSync()).isTrue();

        service.releaseFullSyncGuard();

        assertThat(service.tryBeginFullSync())
                .as("the slot must be free again after an explicit release")
                .isTrue();
    }

    @Test
    void encodesCsvSuppliedKeywordCharactersInTheQueryStringToPreventParameterInjection() {
        // Backlog item 253 (senior review, 2026-09-03, PR#158 follow-up): keyword is the
        // CSV-supplied product name (see AdminController#syncByKeyword), and fetchPage() used to
        // build the query string without
        // UriComponentsBuilder#encode() -- a product cell containing "&resultsPerPage=1" would
        // inject its own resultsPerPage ahead of the real one. Same class of bug as
        // NvdVulnerabilitySource's cpeName case (PR#163); confirms the "&" stays percent-encoded
        // (%26) and resultsPerPage keeps the app's real value.
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("%26")))
                .andExpect(queryParam("resultsPerPage", "10000"))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncByKeyword("apache&resultsPerPage=1", Optional.empty());

        assertThat(upserted).isZero();
        syncServer.verify();
    }

    @Test
    void balancedBraceKeywordIsPercentEncodedInsteadOfThrowing() {
        // Backlog item 254 (senior review of PR#166, 2026-09-03): the item-253 fix above switched
        // fetchPage() to builder.encode(), which is URI *template* encoding -- "{"/"}" are left
        // alone as template-variable delimiters, not percent-encoded. A keyword with a balanced
        // brace pair (e.g. an MSI ProductCode GUID like "{90160000-008C}", which shows up verbatim
        // in Windows installed-software listings) then survives .encode() untouched and trips the
        // single-arg java.net.URI constructor inside build().toUri() with "Illegal character in
        // query", silently discarding the whole Stage1 identification for that item. Confirms the
        // expand-then-encode fix instead percent-encodes the literal braces and completes normally.
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("%7B")))
                .andExpect(requestTo(Matchers.containsString("%7D")))
                .andExpect(queryParam("resultsPerPage", "10000"))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncByKeyword("Office {90160000-008C}", Optional.empty());

        assertThat(upserted).isZero();
        syncServer.verify();
    }

    @Test
    void unbalancedBraceKeywordIsPercentEncodedInsteadOfThrowing() {
        // Closed-mode backlog item 259 (senior review, 2026-09-03, PR#166 final review): the
        // balanced-brace test above ("{90160000-008C}") only fixes the pair. A keyword can just as
        // easily carry an unbalanced brace on its own (e.g. "Office {90160000", a truncated MSI
        // ProductCode GUID column) -- expand() substitutes the whole keyword value for the
        // "{keywordSearch}" template placeholder in one shot, so the value's own internal braces
        // never need to be balanced for that substitution to work; encode() then percent-encodes
        // whatever literal "{" survived, same as the balanced case.
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("%7B")))
                .andExpect(requestTo(Matchers.not(Matchers.containsString("{"))))
                .andExpect(queryParam("resultsPerPage", "10000"))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncByKeyword("Office {90160000", Optional.empty());

        assertThat(upserted).isZero();
        syncServer.verify();
    }

    @Test
    void literalPercentSignKeywordIsPercentEncodedInsteadOfThrowing() {
        // Closed-mode backlog item 259: a keyword can contain a literal "%" (e.g. a free-text
        // product cell like "Foo 50% Off Edition") -- since expand-then-encode runs encode() on the
        // fully-substituted value, "%" itself gets percent-encoded like any other reserved character
        // (to "%25") rather than being misread as the start of an existing percent-escape.
        syncServer.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("%25")))
                .andExpect(queryParam("resultsPerPage", "10000"))
                .andRespond(withSuccess("{\"totalResults\":0,\"products\":[]}", MediaType.APPLICATION_JSON));

        int upserted = service.syncByKeyword("Foo 50%", Optional.empty());

        assertThat(upserted).isZero();
        syncServer.verify();
    }

    @Test
    void syncReportsIncompleteWhenAPageFetchFailsPartWayThrough() {
        // fetchPage() treats a failed HTTP request as an empty result (caught, logged, returns
        // null) rather than throwing — sync() must not report that as a clean finish, since the
        // dictionary is then only partially synced (the bug this fix addresses: both a clean
        // finish and an early abort used to log identically as "finished").
        syncServer.expect(method(HttpMethod.GET)).andRespond(withServerError());

        SyncOutcome outcome = service.syncAllAndRelease(Optional.empty());

        assertThat(outcome.completed()).isFalse();
        syncServer.verify();
    }
}
