package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * One realized (reconciled) Claude API cost event, persisted so a job's actual spend survives past
 * this process's lifetime and can be aggregated in SQL — see {@code
 * com.vulncheck.app.service.JobCostBudgetService}, which is the sole writer of this table (via
 * {@code JobCostLedgerRepository}). Written once per {@code reconcile}/{@code
 * reconcileBundledComponent} call, i.e. once per AI call whose outcome (success or failure) is
 * known; never written at reservation time, since a reservation still in flight has no actual cost
 * yet.
 */
@Entity
@Table(name = "job_cost_ledger")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class JobCostLedgerEntry {

    /** {@link #ledger} value for the always-on per-item budget ({@code tryReserve}/{@code
     *  reconcile}). */
    public static final String LEDGER_MAIN = "MAIN";

    /** {@link #ledger} value for the separate opt-in bundled-package-detection budget ({@code
     *  tryReserveBundledComponent}/{@code reconcileBundledComponent}). */
    public static final String LEDGER_BUNDLED_COMPONENT = "BUNDLED_COMPONENT";

    /** {@link #ledger} value for the separate high-confidence verification backstop budget ({@code
     *  tryReserveVerification}/{@code reconcileVerification}) — REVISE item 1, senior review
     *  2026-08-29: split out of {@link #LEDGER_MAIN} because sharing the always-on per-item budget
     *  let verification silently starve every other AI tier's budget in the same job (see
     *  {@code JobCostBudgetService#verificationCostCapPerItemUsd}'s javadoc for the job 191 numbers
     *  behind this). */
    public static final String LEDGER_VERIFICATION = "VERIFICATION";

    /** {@link #callSite} values — one per llm-service endpoint, matching V27's CHECK constraint.
     *  Distinct from {@link #ledger} (which budget a call drew against): {@code TIER2}/{@code
     *  TIER3}/{@code STAGE4} all use {@link #LEDGER_MAIN}; {@code BUNDLED_CHANGELOG}/{@code
     *  BUNDLED_EXTRACT} both use {@link #LEDGER_BUNDLED_COMPONENT}; {@code VERIFICATION} uses
     *  {@link #LEDGER_VERIFICATION}. */
    public static final String CALL_SITE_TIER2 = "TIER2";

    public static final String CALL_SITE_TIER3 = "TIER3";
    public static final String CALL_SITE_STAGE4 = "STAGE4";
    public static final String CALL_SITE_BUNDLED_CHANGELOG = "BUNDLED_CHANGELOG";
    public static final String CALL_SITE_BUNDLED_EXTRACT = "BUNDLED_EXTRACT";

    /** High-confidence AI verification backstop ({@code HighConfidenceVerificationService}) — the
     *  {@link #callSite} value for its one llm-service endpoint. Originally shared {@link
     *  #LEDGER_MAIN} (V28); split onto its own {@link #LEDGER_VERIFICATION} ledger (REVISE item 1,
     *  senior review 2026-08-29) since sharing the always-on per-item budget let this feature starve
     *  every other AI tier's budget in the same job — see {@code
     *  JobCostBudgetService#verificationCostCapPerItemUsd}'s javadoc. */
    public static final String CALL_SITE_VERIFICATION = "VERIFICATION";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "job_id", nullable = false)
    private Long jobId;

    @Column(name = "job_item_id")
    private Long jobItemId;

    @Column(nullable = false)
    private String ledger;

    @Column(name = "reserved_cost_usd", nullable = false)
    private BigDecimal reservedCostUsd;

    @Column(name = "actual_cost_usd", nullable = false)
    private BigDecimal actualCostUsd;

    // V27: raw breakdown behind actualCostUsd, so JobCostBudgetService's per-tier reservation
    // constants can be re-derived straight from SQL (e.g. percentile input/output tokens and
    // web_search_requests per callSite) instead of grepping llm-service log files — see V27's own
    // migration comment for why this matters (job 185 cost investigation, 2026-08-29). Nullable:
    // rows written before this column existed have no breakdown to backfill.
    @Column(name = "input_tokens")
    private Integer inputTokens;

    @Column(name = "output_tokens")
    private Integer outputTokens;

    @Column(name = "web_search_requests")
    private Integer webSearchRequests;

    /** Which llm-service endpoint made this call — see the {@code CALL_SITE_*} constants above. */
    @Column(name = "call_site")
    private String callSite;

    @Column(name = "recorded_at", insertable = false, updatable = false)
    private OffsetDateTime recordedAt;
}
