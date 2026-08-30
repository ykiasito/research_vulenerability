package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One row per CSAF advisory document — see V17's migration comment for the schema rationale. */
@Entity
@Table(name = "csaf_advisories")
@IdClass(CsafAdvisoryId.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CsafAdvisory {

    @Id
    private String vendor;

    @Id
    @Column(name = "tracking_id")
    private String trackingId;

    @Column(name = "tracking_status", nullable = false)
    private String trackingStatus;

    private String revision;

    private String title;

    @Column(name = "tlp_label")
    private String tlpLabel;

    @Column(name = "cvss_score")
    private BigDecimal cvssScore;

    @Column(name = "cvss_severity")
    private String cvssSeverity;

    @Column(name = "date_published")
    private OffsetDateTime datePublished;

    @Column(name = "date_updated")
    private OffsetDateTime dateUpdated;

    @Column(name = "raw_json", nullable = false)
    private String rawJson;

    @Column(name = "last_synced_at", nullable = false)
    private OffsetDateTime lastSyncedAt;
}
