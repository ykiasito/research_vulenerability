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

/** One (vulnerability, product) applicability row — see V17's migration comment. */
@Entity
@Table(name = "csaf_product_status")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CsafProductStatus {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String vendor;

    @Column(name = "advisory_id")
    private String advisoryId;

    @Column(name = "cve_id")
    private String cveId;

    @Column(name = "csaf_product_id")
    private String csafProductId;

    /** 'fixed' | 'known_affected' | 'known_not_affected' | 'under_investigation' — verbatim CSAF
     *  {@code product_status} category name, see V17's migration comment. */
    private String status;

    @Column(name = "fixed_version")
    private String fixedVersion;

    @Column(name = "remediation_url")
    private String remediationUrl;
}
