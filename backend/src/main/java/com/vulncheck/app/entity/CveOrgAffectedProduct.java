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

/** One flattened {@code affected[]} entry from a CVE.org record — mirrors {@code CpeDictionaryEntry}'s
 *  pg_trgm fuzzy-searchable shape so Stage2 can look up candidate CVEs by vendor/product text. */
@Entity
@Table(name = "cve_org_affected_products")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CveOrgAffectedProduct {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cve_id", nullable = false)
    private String cveId;

    private String vendor;

    private String product;

    @Column(name = "package_name")
    private String packageName;
}
