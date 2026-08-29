package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "identified_products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class IdentifiedProduct {

    public static final String METHOD_STATIC = "static";
    public static final String METHOD_LLM_DISAMBIGUATE = "llm_disambiguate";
    public static final String METHOD_LLM_WEB_SEARCH = "llm_web_search";

    /** {@link #verificationStatus} values — see {@code HighConfidenceVerificationService} and
     *  V28's migration comment for what each means. */
    public static final String VERIFICATION_CONFIRMED = "CONFIRMED";
    public static final String VERIFICATION_INCORRECT = "INCORRECT";
    public static final String VERIFICATION_AMBIGUOUS = "AMBIGUOUS";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "job_item_id", nullable = false)
    private Long jobItemId;

    private String ecosystem;

    @Column(name = "package_name")
    private String packageName;

    private String cpe;

    private String purl;

    private BigDecimal confidence;

    @Column(nullable = false)
    private String method;

    /** true = a registry confirmed this exact version is a real published release; false = a
     *  registry was checked but this exact version wasn't found there (possible typo or
     *  unreleased/future version); null = no registry signal available (e.g. CPE-only
     *  identification, which never validates the version at all). */
    @Column(name = "version_confirmed")
    private Boolean versionConfirmed;

    /** Outcome of {@code HighConfidenceVerificationService}'s AI+web_search backstop check, or
     *  {@code null} when it never ran for this item (feature disabled, not eligible, no Claude
     *  key, budget exhausted, or the call itself failed — all degrade to "leave the static match
     *  untouched", same as every other AI tier in this app). See the {@code VERIFICATION_*}
     *  constants above. */
    @Column(name = "verification_status")
    private String verificationStatus;

    /** Free-text reasoning (CONFIRMED/INCORRECT) or candidate-variant list (AMBIGUOUS) behind
     *  {@link #verificationStatus} — {@code null} whenever that field is {@code null}. */
    @Column(name = "verification_note")
    private String verificationNote;
}
