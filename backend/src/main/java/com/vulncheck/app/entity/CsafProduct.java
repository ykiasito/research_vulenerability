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

/** One distinct resolved product per advisory (see {@code CsafProductTreeWalker}) — V17's migration
 *  comment has the schema rationale, including why architecture-only variants are folded into one
 *  row here rather than kept separate. */
@Entity
@Table(name = "csaf_products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CsafProduct {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String vendor;

    @Column(name = "advisory_id")
    private String advisoryId;

    @Column(name = "csaf_product_id")
    private String csafProductId;

    @Column(name = "component_name")
    private String componentName;

    @Column(name = "component_version")
    private String componentVersion;

    @Column(name = "platform_name")
    private String platformName;

    private String cpe;

    private String purl;

    /** Raw, un-derived CSAF leaf {@code product.name} — e.g. the full NEVRA string for an RPM
     *  ({@code openssl-1:3.0.7-24.el9_2.x86_64}). Kept purely for debugging/display (V20); {@link
     *  #componentName} — purl-derived when a purl is present — is always what matching queries. */
    @Column(name = "raw_leaf_name")
    private String rawLeafName;
}
