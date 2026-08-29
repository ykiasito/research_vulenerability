package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "cve_org_records")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CveOrgRecord {

    @Id
    @Column(name = "cve_id", nullable = false)
    private String cveId;

    private String title;

    private String description;

    @Column(name = "cvss_score")
    private BigDecimal cvssScore;

    @Column(name = "cvss_severity")
    private String cvssSeverity;

    private String state;

    @Column(name = "date_published")
    private OffsetDateTime datePublished;

    @Column(name = "date_updated")
    private OffsetDateTime dateUpdated;

    /** The full CVE JSON 5.x record, kept verbatim so affected-version-range parsing (done at
     *  query time by {@code CveOrgVulnerabilitySource}) always has the complete data, not just
     *  whatever fields this entity chose to flatten out. */
    @Column(name = "raw_json", nullable = false)
    private String rawJson;

    @Column(name = "last_synced_at", nullable = false)
    private OffsetDateTime lastSyncedAt;
}
