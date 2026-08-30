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

@Entity
@Table(name = "ecosystem_registries")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class EcosystemRegistry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String ecosystem;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "lookup_base_url", nullable = false)
    private String lookupBaseUrl;

    @Column(nullable = false)
    private boolean enabled;
}
