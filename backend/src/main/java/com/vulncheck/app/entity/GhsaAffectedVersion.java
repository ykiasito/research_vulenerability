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
 *  evaluation. See V19's migration comment for why {@code GhsaVulnerabilitySource} must check this
 *  separately from {@link GhsaAffectedRange}. */
@Entity
@Table(name = "ghsa_affected_versions")
@IdClass(GhsaAffectedVersionId.class)
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class GhsaAffectedVersion {

    @Id
    @Column(name = "affected_package_id")
    private Long affectedPackageId;

    @Id
    private String version;
}
