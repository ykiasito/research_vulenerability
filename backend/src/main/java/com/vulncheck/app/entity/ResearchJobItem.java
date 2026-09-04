package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "research_job_items")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResearchJobItem {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_IDENTIFIED = "IDENTIFIED";
    public static final String STATUS_UNIDENTIFIED = "UNIDENTIFIED";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "job_id", nullable = false)
    private Long jobId;

    /** Cleaned (annotation-stripped) product name Stage1 identification actually searches
     *  against — see {@link com.vulncheck.app.service.ProductNameAnnotationStripper}. Not
     *  necessarily what the user typed; see {@link #rawProductName} for that. */
    @Column(name = "product_name", nullable = false)
    private String productName;

    /** The user's original CSV product-name cell, annotation noise (e.g. {@code "(補足)"}/
     *  {@code "※備考"}) and all — set at CSV ingest time alongside {@link #productName} (see
     *  {@code ResearchJobService#createJob}), for display/export where the user wants to see what
     *  they actually typed rather than the cleaned-up identification value. {@code null} only for
     *  rows created before V26 added this column (no raw text was persisted at the time); use
     *  {@link #getDisplayProductName()} rather than reading this field directly to get the
     *  legacy-row fallback for free. */
    @Column(name = "raw_product_name")
    private String rawProductName;

    @Column(nullable = false)
    private String version;

    private String vendor;

    @Column(name = "usage_text", nullable = false)
    private String usageText;

    @Column(name = "install_url")
    private String installUrl;

    @Column(nullable = false)
    private String status;

    /** Set when Tier3 couldn't produce a queryable ecosystem/CPE match but the AI still
     *  recognized a platform-specific identifier (e.g. a VS Code Marketplace extension id) a
     *  person could use to verify/install this manually. Null otherwise. */
    @Column(name = "identification_hint")
    private String identificationHint;

    /** Structured form of the same hint (platform name / exact identifier), used to run a
     *  Stage4-style AI vulnerability investigation for products with no queryable ecosystem/CPE
     *  at all. Null whenever {@link #identificationHint} is null. */
    @Column(name = "hint_platform")
    private String hintPlatform;

    @Column(name = "hint_identifier")
    private String hintIdentifier;

    /** Set when Stage2 was run for this item but every {@code VulnerabilitySource} failed
     *  (rate limit, network error, ...) — i.e. {@code Stage2Result#anySourceSucceeded()} was
     *  {@code false} — so this item's {@link com.vulncheck.app.repository.JobItemVulnerabilityRepository}
     *  rows (or lack thereof) reflect "nothing was actually checked", not a genuine zero-findings
     *  result. */
    public static final String INCOMPLETE_REASON_SOURCES_FAILED = "SOURCES_FAILED";

    /** Set when {@code NvdVulnerabilitySource}'s mirror-backed lookup (closed-mode backlog item 251,
     *  B4) genuinely found more distinct CVEs applicable to this item than its own write-safety cap
     *  allows persisting (see that class's {@code MAX_FINDINGS_PER_ITEM} javadoc) -- the CVSS-ranked
     *  top slice was written, but some lower-priority findings were deliberately not persisted at
     *  all, not merely hidden by the display cap (see {@link #INCOMPLETE_REASON_SOURCES_FAILED}'s
     *  distinction from a genuine zero-findings result for the same "don't render this identically
     *  to a fully-verified result" rationale). Distinct from every other {@code INCOMPLETE_REASON_*}
     *  here: this item DID get real findings, some of them just didn't make the cut, so this is not
     *  reported as "nothing was checked". Only the write-time truncation sets this -- the read-time
     *  display cap (top 10 in the HTML detail view / top 200 in the CSV export, see {@code
     *  JobItemVulnerabilityRepository}) never touches this field, since every persisted row is still
     *  reachable, just not all rendered in one place. */
    public static final String INCOMPLETE_REASON_FINDINGS_TRUNCATED = "FINDINGS_TRUNCATED";

    /** Set when Stage2 genuinely found zero (every source that ran succeeded) but Stage4's AI
     *  web-search fallback was deliberately skipped because this item's {@link IdentifiedProduct
     *  #getConfidence()} was at/below {@code ResearchJobProcessingService#STAGE4_MIN_IDENTIFICATION_CONFIDENCE}
     *  — i.e. the product match itself is a weak guess, so there was nothing solid enough to run an
     *  AI verification pass against. Distinct from {@link #INCOMPLETE_REASON_SOURCES_FAILED}: this is
     *  a deliberate precision tradeoff, not an infrastructure failure, and should read differently to
     *  the end user. */
    public static final String INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK = "IDENTIFICATION_TOO_WEAK";

    /** Set when Stage2 genuinely found zero (every source that ran succeeded) but Stage4's AI
     *  web-search fallback never actually ran because this job's owner has no Claude API key
     *  registered — see {@code Stage4WebSearchResearchService#research}'s no-key early return.
     *  Distinct from {@link #INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK}: the identification itself
     *  may be perfectly solid, there is simply no AI verification pass available to run. Without
     *  this, an unconfigured API key (the default state for most jobs) made every such item render
     *  identically to a genuine, fully-verified all-clear. */
    public static final String INCOMPLETE_REASON_AI_NOT_AVAILABLE = "AI_NOT_AVAILABLE";

    /** Set when Stage2 genuinely found zero but Stage4's AI web-search fallback was skipped because
     *  the job's AI cost budget was already exhausted — see {@code Stage4WebSearchResearchService
     *  #research}'s budget-exhausted early return. Distinct from {@link #INCOMPLETE_REASON_AI_NOT_AVAILABLE}:
     *  a key is configured, spending on this item just wasn't possible within the job's remaining
     *  budget. */
    public static final String INCOMPLETE_REASON_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED";

    /** Set when Stage2 genuinely found zero and Stage4's AI web-search fallback was attempted (a key
     *  is configured and budget was available) but did not run to completion — either {@code
     *  LlmServiceClient#webSearchResearch} itself reports the call failed (LLM service outage,
     *  timeout, network error, etc. — see its {@code Optional.empty()} contract, turned into this
     *  reason by {@code Stage4WebSearchResearchService#research}), or an exception was thrown
     *  elsewhere around the attempt (API key resolution, budget reservation, finding persistence —
     *  see {@code ResearchJobProcessingService}'s Stage4 {@code catch (Exception e)} block). This
     *  reason means "Stage4 was attempted but did not finish", not "spent the job's AI budget without
     *  result": the reservation made for the attempt is refunded in full either way — {@code
     *  JobCostBudgetService#reconcile} treats a failed call's actual cost as $0 and refunds the whole
     *  reservation (see its own javadoc). Distinct from {@link #INCOMPLETE_REASON_AI_NOT_AVAILABLE}
     *  and {@link #INCOMPLETE_REASON_BUDGET_EXHAUSTED}: those are deliberate, orderly skips before any
     *  attempt was even made; this is an attempt that started but didn't finish. In practice more
     *  common than a fully exhausted budget, since it covers every transient failure of the LLM
     *  microservice itself, not just a rare cap. Without this, such a failure left {@code
     *  researchIncompleteReason} at the {@code null} Stage2 already set, rendering identically to a
     *  genuine, fully-verified all-clear — same class of bug as the one {@link
     *  #INCOMPLETE_REASON_AI_NOT_AVAILABLE}/{@link #INCOMPLETE_REASON_BUDGET_EXHAUSTED} fixed. */
    public static final String INCOMPLETE_REASON_AI_CALL_FAILED = "AI_CALL_FAILED";

    /** Reason this item's vulnerability research isn't fully verified, or {@code null} when it is
     *  (a genuine zero-findings result with no verification gap, or an item that hasn't reached
     *  Stage2 yet). See {@link #INCOMPLETE_REASON_SOURCES_FAILED}, {@link #INCOMPLETE_REASON_FINDINGS_TRUNCATED},
     *  {@link #INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK},
     *  {@link #INCOMPLETE_REASON_AI_NOT_AVAILABLE}, {@link #INCOMPLETE_REASON_BUDGET_EXHAUSTED} and
     *  {@link #INCOMPLETE_REASON_AI_CALL_FAILED} for the distinct causes this can hold. Left set once set
     *  until this item is reprocessed (there is
     *  no automatic retry yet — see {@code ResearchJobProcessingService}). Replaces the old {@code
     *  vulnerability_research_incomplete} boolean (V11), which could only represent one such cause and
     *  collapsed the other (deliberately-skipped AI verification on a weak identification) into an
     *  indistinguishable-from-clean result — see V12's migration comment. */
    @Column(name = "research_incomplete_reason")
    private String researchIncompleteReason;

    /** Highest recommended-upgrade version across this item's own Stage2 findings (V40, closed-mode
     *  backlog item 251 REVISE item 5) -- computed once by {@code
     *  Stage2VulnerabilityResearchService#research} from its own in-memory, pre-persistence {@code
     *  VulnFinding} union (NVD/OSV/GHSA/CVE.org, never CSAF or bundled-component findings — see that
     *  method's javadoc for why those two are excluded structurally rather than via an explicit
     *  filter). {@code null} when Stage2 hasn't run yet or none of its findings carry a fixedVersion.
     *  Replaces the old {@code JobController#highestFixedVersion}, which re-derived this at render
     *  time from the persisted, globally-shared {@code vulnerabilities.fixed_version} column (a
     *  cross-item contamination risk this field's compute-once-from-this-item's-own-findings
     *  approach avoids) and would have needed to scan every one of an item's findings even after the
     *  read-side display cap (backlog items 245/251) capped what {@code JobController} loads. */
    @Column(name = "max_fixed_version")
    private String maxFixedVersion;

    /** Convenience view of {@link #researchIncompleteReason}: {@code true} whenever this item's
     *  vulnerability research isn't fully verified, regardless of which specific reason. */
    public boolean isResearchIncomplete() {
        return researchIncompleteReason != null;
    }

    /** What display/export should show as "the product name": the user's original raw CSV text
     *  when available, falling back to {@link #productName} for rows created before V26 (whose
     *  {@link #rawProductName} is {@code null}). */
    public String getDisplayProductName() {
        return rawProductName != null ? rawProductName : productName;
    }
}
