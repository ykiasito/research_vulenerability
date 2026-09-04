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

/**
 * Closed-mode backlog item 262 (Phase B6, {@code docs/spec/closed-mode-plan.md} §3-2): the
 * {@code ecosystem_registries} table this maps to is kept permanently empty on the {@code
 * closed-mode} branch by {@code R__closed_mode_strip.sql} (a repeatable migration, so any row that
 * somehow reappears — a stray insert, a future master-branch merge reintroducing seed data — is
 * stripped again on the next build/deploy). The type/repository stay, unlike the data: {@link
 * com.vulncheck.app.controller.GuideController} still queries this table (it simply renders zero
 * rows now), and keeping the JPA mapping avoids carving this class out of every place that would
 * otherwise need conditional closed-mode-only code just to compile.
 */
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
