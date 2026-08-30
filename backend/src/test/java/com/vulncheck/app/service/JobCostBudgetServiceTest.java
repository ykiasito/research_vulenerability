package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import com.vulncheck.app.repository.JobCostLedgerRepository;
import java.math.BigDecimal;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.test.util.ReflectionTestUtils;

class JobCostBudgetServiceTest {

    private JobCostBudgetService newService() {
        return newService(mock(JobCostLedgerRepository.class));
    }

    private JobCostBudgetService newService(JobCostLedgerRepository repository) {
        JobCostBudgetService service = new JobCostBudgetService(repository);
        // costCapPerItemUsd is @Value-injected in production (application.yml's
        // app.cost-cap-per-item-usd, default 0.005) — this constructor call bypasses Spring, so set
        // it directly to that same default, matching HighConfidenceVerificationServiceTest's
        // ReflectionTestUtils pattern for its own @Value fields.
        ReflectionTestUtils.setField(service, "costCapPerItemUsd", new BigDecimal("0.005"));
        // verificationCostCapPerItemUsd is likewise @Value-injected in production
        // (app.high-confidence-verification.cost-cap-per-item-usd, default 0) — set to that same
        // default here; tests that need a real (non-zero) cap override it explicitly.
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", BigDecimal.ZERO);
        return service;
    }

    @Test
    void aNeverStartedJobIdFailsOpenSoAMissingStartJobBudgetCallDoesNotBlockEveryAiCall() {
        JobCostBudgetService service = newService();

        assertThat(service.tryReserve(999L, new BigDecimal("5.00"))).isTrue();
    }

    @Test
    void aTombstonedEndedJobIdFailsClosedRatherThanFallingBackToUnlimitedSpend() {
        // The bug this guards against: an item task still in flight after processJobAsync's
        // finally block calls endJobBudget (e.g. after a queue-overrun exception aborted the
        // submission loop early) must not get unlimited Claude API spend just because its job's
        // cap entry was removed.
        JobCostBudgetService service = newService();
        service.startJobBudget(1L, 100);
        service.endJobBudget(1L);

        assertThat(service.tryReserve(1L, new BigDecimal("0.001"))).isFalse();
    }

    @Test
    void reservingWithinTheCapSucceedsAndTracksSpend() {
        JobCostBudgetService service = newService();
        service.startJobBudget(2L, 100); // cap = 100 * 0.005 = 0.50

        assertThat(service.tryReserve(2L, new BigDecimal("0.30"))).isTrue();
        assertThat(service.tryReserve(2L, new BigDecimal("0.20"))).isTrue();
    }

    @Test
    void reservingPastTheCapFails() {
        JobCostBudgetService service = newService();
        service.startJobBudget(3L, 100); // cap = 0.50

        assertThat(service.tryReserve(3L, new BigDecimal("0.30"))).isTrue();
        assertThat(service.tryReserve(3L, new BigDecimal("0.30"))).isFalse();
    }

    @Test
    void reReservingAfterAJobIsRestartedClearsTheOldTombstone() {
        // StuckJobResumer can re-run processJobAsync for a job resumed after a crash/redeploy —
        // startJobBudget must un-tombstone the id so the fresh budget isn't immediately rejected
        // by the leftover "ended" state from its previous (interrupted) run.
        JobCostBudgetService service = newService();
        service.startJobBudget(4L, 100);
        service.endJobBudget(4L);
        assertThat(service.tryReserve(4L, new BigDecimal("0.001"))).isFalse();

        service.startJobBudget(4L, 100);

        assertThat(service.tryReserve(4L, new BigDecimal("0.001"))).isTrue();
    }

    // --- REVISE item 7 (senior review 2026-08-26): the bundled-component ledger's own safety-
    // critical behavior, including its deliberately-inverted fail-closed semantics, had zero direct
    // test coverage before this ------------------------------------------------------------------

    @Test
    void bundledComponentReservationFailsClosedForANeverStartedJobIdUnlikeTheAlwaysOnLedger() {
        // tryReserveBundledComponent deliberately fails CLOSED for a never-started id, the opposite
        // of tryReserve's fail-open default — see startBundledComponentBudget's javadoc: there is
        // no legitimate "forgot to call start" scenario for an opt-in-only budget.
        JobCostBudgetService service = newService();

        assertThat(service.tryReserveBundledComponent(999L, new BigDecimal("0.01"))).isFalse();
    }

    @Test
    void bundledComponentReservationFailsClosedAfterEndBundledComponentBudget() {
        JobCostBudgetService service = newService();
        service.startBundledComponentBudget(5L, 100);
        service.endBundledComponentBudget(5L);

        assertThat(service.tryReserveBundledComponent(5L, new BigDecimal("0.01"))).isFalse();
    }

    @Test
    void startBundledComponentBudgetClearsTheTombstoneOnAResumedJobId() {
        JobCostBudgetService service = newService();
        service.startBundledComponentBudget(6L, 100);
        service.endBundledComponentBudget(6L);
        assertThat(service.tryReserveBundledComponent(6L, new BigDecimal("0.001"))).isFalse();

        service.startBundledComponentBudget(6L, 100);

        assertThat(service.tryReserveBundledComponent(6L, new BigDecimal("0.001"))).isTrue();
    }

    @Test
    void bundledComponentBudgetEnforcesTheDollarZeroTwoPerItemCap() {
        JobCostBudgetService service = newService();
        service.startBundledComponentBudget(7L, 10); // cap = 10 * 0.02 = 0.20

        assertThat(service.tryReserveBundledComponent(7L, new BigDecimal("0.15"))).isTrue();
        assertThat(service.tryReserveBundledComponent(7L, new BigDecimal("0.05"))).isTrue(); // exactly at cap
        assertThat(service.tryReserveBundledComponent(7L, new BigDecimal("0.01"))).isFalse(); // over cap
    }

    @Test
    void exhaustingTheBundledComponentBudgetLeavesTheAlwaysOnLedgerUnaffected() {
        JobCostBudgetService service = newService();
        service.startJobBudget(8L, 100); // always-on cap = 100 * 0.005 = 0.50
        service.startBundledComponentBudget(8L, 1); // bundled cap = 1 * 0.02 = 0.02

        assertThat(service.tryReserveBundledComponent(8L, new BigDecimal("0.02"))).isTrue();
        assertThat(service.tryReserveBundledComponent(8L, new BigDecimal("0.01"))).isFalse(); // bundled exhausted

        // The always-on ledger is a completely separate ledger and still has its own full budget.
        assertThat(service.tryReserve(8L, new BigDecimal("0.30"))).isTrue();
    }

    @Test
    void exhaustingTheAlwaysOnBudgetLeavesTheBundledComponentLedgerUnaffected() {
        JobCostBudgetService service = newService();
        service.startJobBudget(9L, 1); // always-on cap = 1 * 0.005 = 0.005
        service.startBundledComponentBudget(9L, 100); // bundled cap = 100 * 0.02 = 2.00

        assertThat(service.tryReserve(9L, new BigDecimal("0.005"))).isTrue();
        assertThat(service.tryReserve(9L, new BigDecimal("0.001"))).isFalse(); // always-on exhausted

        // The bundled-component ledger is a completely separate ledger and still has its own full budget.
        assertThat(service.tryReserveBundledComponent(9L, new BigDecimal("1.00"))).isTrue();
    }

    // --- REVISE item 1 (senior review 2026-08-29, round 1): the high-confidence verification backstop's own
    // ledger, split out of the always-on MAIN ledger so enabling that feature can never silently
    // starve every other AI tier's budget in the same job (job 191: 108/300 eligible items, $3.78
    // demand vs. a $1.50 MAIN cap) — same fail-closed/tombstone/cap-isolation shape as the bundled-
    // component ledger above -----------------------------------------------------------------------

    @Test
    void verificationReservationFailsClosedForANeverStartedJobIdUnlikeTheAlwaysOnLedger() {
        JobCostBudgetService service = newService();

        assertThat(service.tryReserveVerification(999L, new BigDecimal("0.035"))).isFalse();
    }

    @Test
    void verificationReservationFailsClosedAfterEndVerificationBudget() {
        JobCostBudgetService service = newService();
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", new BigDecimal("0.05"));
        service.startVerificationBudget(19L, 100);
        service.endVerificationBudget(19L);

        assertThat(service.tryReserveVerification(19L, new BigDecimal("0.035"))).isFalse();
    }

    @Test
    void startVerificationBudgetClearsTheTombstoneOnAResumedJobId() {
        JobCostBudgetService service = newService();
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", new BigDecimal("0.05"));
        service.startVerificationBudget(20L, 100);
        service.endVerificationBudget(20L);
        assertThat(service.tryReserveVerification(20L, new BigDecimal("0.001"))).isFalse();

        service.startVerificationBudget(20L, 100);

        assertThat(service.tryReserveVerification(20L, new BigDecimal("0.001"))).isTrue();
    }

    @Test
    void verificationBudgetDefaultsToZeroSoItIsANoOpUntilExplicitlyConfigured() {
        // verificationCostCapPerItemUsd defaults to 0 (see its own javadoc) — even a single
        // near-zero reservation must fail until an operator explicitly sets a real cap alongside
        // app.high-confidence-verification.enabled.
        JobCostBudgetService service = newService();
        service.startVerificationBudget(21L, 1000);

        assertThat(service.tryReserveVerification(21L, new BigDecimal("0.001"))).isFalse();
    }

    @Test
    void exhaustingTheVerificationBudgetLeavesTheAlwaysOnLedgerUnaffected() {
        JobCostBudgetService service = newService();
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", new BigDecimal("0.035"));
        service.startJobBudget(22L, 100); // always-on cap = 100 * 0.005 = 0.50
        service.startVerificationBudget(22L, 1); // verification cap = 1 * 0.035 = 0.035

        assertThat(service.tryReserveVerification(22L, new BigDecimal("0.035"))).isTrue();
        assertThat(service.tryReserveVerification(22L, new BigDecimal("0.001"))).isFalse(); // verification exhausted

        // The always-on ledger is a completely separate ledger and still has its own full budget —
        // this is exactly the job 191 scenario the split fixes: verification running out must never
        // block Tier2/Tier3's own reservations against MAIN.
        assertThat(service.tryReserve(22L, new BigDecimal("0.30"))).isTrue();
    }

    @Test
    void exhaustingTheAlwaysOnBudgetLeavesTheVerificationLedgerUnaffected() {
        JobCostBudgetService service = newService();
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", new BigDecimal("0.035"));
        service.startJobBudget(23L, 1); // always-on cap = 1 * 0.005 = 0.005
        service.startVerificationBudget(23L, 100); // verification cap = 100 * 0.035 = 3.50

        assertThat(service.tryReserve(23L, new BigDecimal("0.005"))).isTrue();
        assertThat(service.tryReserve(23L, new BigDecimal("0.001"))).isFalse(); // always-on exhausted

        // The verification ledger is a completely separate ledger and still has its own full budget.
        assertThat(service.tryReserveVerification(23L, new BigDecimal("1.00"))).isTrue();
    }

    @Test
    void reconcileVerificationPersistsALedgerEntryTaggedWithTheVerificationLedger() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        ReflectionTestUtils.setField(service, "verificationCostCapPerItemUsd", new BigDecimal("0.035"));
        service.startVerificationBudget(24L, 10);
        service.tryReserveVerification(24L, new BigDecimal("0.035"));

        service.reconcileVerification(24L, 93L, new BigDecimal("0.035"), new BigDecimal("0.0233"));

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getJobId()).isEqualTo(24L);
        assertThat(saved.getJobItemId()).isEqualTo(93L);
        assertThat(saved.getLedger()).isEqualTo(JobCostLedgerEntry.LEDGER_VERIFICATION);
        assertThat(saved.getReservedCostUsd()).isEqualByComparingTo("0.035");
        assertThat(saved.getActualCostUsd()).isEqualByComparingTo("0.0233");
    }

    // --- Cost persistence (docs/spec/infra-rollout-plan.md item 5): reconcile now writes a
    // JobCostLedgerEntry row via JobCostLedgerRepository in addition to the in-memory bookkeeping
    // exercised above -------------------------------------------------------------------------

    @Test
    void reconcilePersistsALedgerEntryTaggedWithTheMainLedgerAndTheGivenJobAndItemIds() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(10L, 100);
        service.tryReserve(10L, new BigDecimal("0.003"));

        service.reconcile(10L, 55L, new BigDecimal("0.003"), new BigDecimal("0.0021"));

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getJobId()).isEqualTo(10L);
        assertThat(saved.getJobItemId()).isEqualTo(55L);
        assertThat(saved.getLedger()).isEqualTo(JobCostLedgerEntry.LEDGER_MAIN);
        assertThat(saved.getReservedCostUsd()).isEqualByComparingTo("0.003");
        assertThat(saved.getActualCostUsd()).isEqualByComparingTo("0.0021");
    }

    @Test
    void reconcileBundledComponentPersistsALedgerEntryTaggedWithTheBundledComponentLedger() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startBundledComponentBudget(11L, 10);
        service.tryReserveBundledComponent(11L, new BigDecimal("0.015"));

        service.reconcileBundledComponent(11L, 66L, new BigDecimal("0.015"), new BigDecimal("0.009"));

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getJobId()).isEqualTo(11L);
        assertThat(saved.getJobItemId()).isEqualTo(66L);
        assertThat(saved.getLedger()).isEqualTo(JobCostLedgerEntry.LEDGER_BUNDLED_COMPONENT);
        assertThat(saved.getReservedCostUsd()).isEqualByComparingTo("0.015");
        assertThat(saved.getActualCostUsd()).isEqualByComparingTo("0.009");
    }

    @Test
    void reconcileStillPersistsALedgerEntryForAJobWhoseInMemoryBudgetWasAlreadyTornDown() {
        // A late reconcile for an item still in flight after endJobBudget's tombstone must not
        // silently drop the real dollars that were actually spent — see the class javadoc on why
        // persistence happens unconditionally, unlike the in-memory spent-tracking it sits beside.
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(12L, 100);
        service.endJobBudget(12L);

        service.reconcile(12L, 77L, new BigDecimal("0.003"), new BigDecimal("0.002"));

        verify(repository, times(1)).save(any(JobCostLedgerEntry.class));
    }

    @Test
    void reconcileWithANullJobItemIdStillPersistsTheOtherFields() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(13L, 100);

        service.reconcile(13L, null, new BigDecimal("0.003"), BigDecimal.ZERO);

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository).save(captor.capture());
        assertThat(captor.getValue().getJobItemId()).isNull();
    }

    // --- REVISE item 1/2 (senior review 2026-08-28): a DB failure while persisting the ledger row
    // must never propagate out of reconcile() — see JobCostBudgetService#persistLedgerEntry's
    // javadoc for why an escaped DataAccessException here would otherwise blow past
    // LlmServiceClient's finally block and discard an already-billed Claude response upstream ------

    @Test
    void reconcileDoesNotThrowWhenLedgerPersistenceFails() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        doThrow(new DataAccessResourceFailureException("DB unavailable")).when(repository).save(any(JobCostLedgerEntry.class));
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(14L, 100);
        service.tryReserve(14L, new BigDecimal("0.003"));

        assertThatCode(() -> service.reconcile(14L, 88L, new BigDecimal("0.003"), new BigDecimal("0.0021")))
                .doesNotThrowAnyException();
    }

    // --- V27: reconcile/reconcileBundledComponent overloads that additionally record callSite and
    // the raw input/output token + web_search_requests breakdown behind actualCostUsd -------------

    @Test
    void reconcileWithBreakdownPersistsCallSiteAndTokenCounts() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(16L, 100);
        service.tryReserve(16L, new BigDecimal("0.035"));

        service.reconcile(
                16L, 90L, JobCostLedgerEntry.CALL_SITE_STAGE4, new BigDecimal("0.035"), new BigDecimal("0.0233"),
                1850, 500, 1);

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getCallSite()).isEqualTo(JobCostLedgerEntry.CALL_SITE_STAGE4);
        assertThat(saved.getInputTokens()).isEqualTo(1850);
        assertThat(saved.getOutputTokens()).isEqualTo(500);
        assertThat(saved.getWebSearchRequests()).isEqualTo(1);
    }

    @Test
    void reconcileBundledComponentWithBreakdownPersistsCallSiteAndTokenCounts() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startBundledComponentBudget(17L, 10);
        service.tryReserveBundledComponent(17L, new BigDecimal("0.015"));

        service.reconcileBundledComponent(
                17L, 91L, JobCostLedgerEntry.CALL_SITE_BUNDLED_CHANGELOG, new BigDecimal("0.015"),
                new BigDecimal("0.009"), 1200, 300, 1);

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getCallSite()).isEqualTo(JobCostLedgerEntry.CALL_SITE_BUNDLED_CHANGELOG);
        assertThat(saved.getInputTokens()).isEqualTo(1200);
        assertThat(saved.getOutputTokens()).isEqualTo(300);
        assertThat(saved.getWebSearchRequests()).isEqualTo(1);
    }

    @Test
    void reconcileWithoutBreakdownLeavesCallSiteAndTokenFieldsNull() {
        // The original 4-arg overload (still used directly by a couple of tests above) must keep
        // persisting a valid row with the new columns simply left null, not fail.
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(18L, 100);

        service.reconcile(18L, 92L, new BigDecimal("0.003"), new BigDecimal("0.002"));

        ArgumentCaptor<JobCostLedgerEntry> captor = ArgumentCaptor.forClass(JobCostLedgerEntry.class);
        verify(repository, times(1)).save(captor.capture());
        JobCostLedgerEntry saved = captor.getValue();
        assertThat(saved.getCallSite()).isNull();
        assertThat(saved.getInputTokens()).isNull();
        assertThat(saved.getOutputTokens()).isNull();
        assertThat(saved.getWebSearchRequests()).isNull();
    }

    @Test
    void reconcileStillRefundsTheInMemoryReservationWhenLedgerPersistenceFails() {
        JobCostLedgerRepository repository = mock(JobCostLedgerRepository.class);
        doThrow(new DataAccessResourceFailureException("DB unavailable")).when(repository).save(any(JobCostLedgerEntry.class));
        JobCostBudgetService service = newService(repository);
        service.startJobBudget(15L, 100); // cap = 100 * 0.005 = 0.50
        assertThat(service.tryReserve(15L, new BigDecimal("0.50"))).isTrue(); // exhausts the cap
        assertThat(service.tryReserve(15L, new BigDecimal("0.001"))).isFalse(); // confirm exhausted

        // Reconcile with actualCostUsd ZERO refunds the whole 0.50 reservation, even though the
        // ledger save() throws.
        service.reconcile(15L, 89L, new BigDecimal("0.50"), BigDecimal.ZERO);

        assertThat(service.tryReserve(15L, new BigDecimal("0.50"))).isTrue();
    }
}
