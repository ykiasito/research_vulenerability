package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One row per non-GHSA OSV.dev advisory (PYSEC/GO/RUSTSEC/DRUPAL-CONTRIB/EEF-CVE/OSV-*, restricted
 *  to the 10 supported ecosystems) — see V25's migration comment for the schema rationale. */
@Entity
@Table(name = "osv_advisories")
@Getter
@Setter
@NoArgsConstructor
public class OsvAdvisory {

    @Id
    @Column(name = "osv_id")
    private String osvId;

    @Column(name = "cve_id")
    private String cveId;

    @Column(name = "ghsa_id")
    private String ghsaId;

    private String summary;

    private String details;

    private String severity;

    @Column(name = "cvss_score")
    private BigDecimal cvssScore;

    @Column(name = "withdrawn_at")
    private OffsetDateTime withdrawnAt;

    @Column(name = "published_at")
    private OffsetDateTime publishedAt;

    @Column(name = "updated_at", nullable = false)
    private OffsetDateTime updatedAt;

    @Column(name = "html_url")
    private String htmlUrl;

    @Column(name = "last_synced_at", nullable = false)
    private OffsetDateTime lastSyncedAt;
}
