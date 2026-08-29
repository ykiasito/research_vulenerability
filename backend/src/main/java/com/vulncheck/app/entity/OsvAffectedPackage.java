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

/** One row per (advisory, ecosystem, package) triple — see V25's migration comment. */
@Entity
@Table(name = "osv_affected_packages")
@Getter
@Setter
@NoArgsConstructor
public class OsvAffectedPackage {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "osv_id", nullable = false)
    private String osvId;

    @Column(nullable = false)
    private String ecosystem;

    @Column(name = "package_name", nullable = false)
    private String packageName;

    @Column(name = "package_name_normalized", nullable = false)
    private String packageNameNormalized;
}
