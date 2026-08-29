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

    /** Set when Stage2 genuinely found zero (every source that ran succeeded) but Stage4's AI
     *  web-search fallback was deliberately skipped because this item's {@link IdentifiedProduct
     *  #getConfidence()} was at/below {@code ResearchJobProcessingService#STAGE4_MIN_IDENTIFICATION_CONFIDENCE}
     *  — i.e. the product match itself is a weak guess, so there was nothing solid enough to run an
     *  AI verification pass against. Distinct from {@link #INCOMPLETE_REASON_SOURCES_FAILED}: this is
     *  a deliberate precision tradeoff, not an infrastructure failure, and should read differently to
     *  the end user. */
    public static final String INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK = "IDENTIFICATION_TOO_WEAK";

    /** Reason this item's vulnerability research isn't fully verified, or {@code null} when it is
     *  (a genuine zero-findings result with no verification gap, or an item that hasn't reached
     *  Stage2 yet). See {@link #INCOMPLETE_REASON_SOURCES_FAILED} and
     *  {@link #INCOMPLETE_REASON_IDENTIFICATION_TOO_WEAK} for the distinct causes this can hold.
     *  Left set once set until this item is reprocessed (there is no automatic retry yet — see
     *  {@code ResearchJobProcessingService}). Replaces the old {@code vulnerability_research_incomplete}
     *  boolean (V11), which could only represent one such cause and collapsed the other
     *  (deliberately-skipped AI verification on a weak identification) into an indistinguishable-
     *  from-clean result — see V12's migration comment. */
    @Column(name = "research_incomplete_reason")
    private String researchIncompleteReason;

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
