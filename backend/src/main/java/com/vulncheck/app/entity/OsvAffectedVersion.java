package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** OSV's {@code affected[].versions[]} — an exact version enumeration independent of range
 *  evaluation. See V25's migration comment for why {@code OsvVulnerabilitySource} must check this
 *  separately from {@link OsvAffectedRange}. */
@Entity
@Table(name = "osv_affected_versions")
@IdClass(OsvAffectedVersionId.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class OsvAffectedVersion {

    @Id
    @Column(name = "affected_package_id")
    private Long affectedPackageId;

    @Id
    private String version;
}
