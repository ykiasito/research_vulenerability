package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** One independent vulnerable-version range for one {@link OsvAffectedPackage} — see V25's
 *  migration comment for the range_type/fixed_version/last_affected_version semantics. */
@Entity
@Table(name = "osv_affected_ranges")
@Getter
@Setter
@NoArgsConstructor
public class OsvAffectedRange {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "affected_package_id", nullable = false)
    private Long affectedPackageId;

    @Column(name = "range_type", nullable = false)
    private String rangeType;

    @Column(name = "introduced_version")
    private String introducedVersion;

    @Column(name = "fixed_version")
    private String fixedVersion;

    @Column(name = "last_affected_version")
    private String lastAffectedVersion;
}
