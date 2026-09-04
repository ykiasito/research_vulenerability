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
 * {@code ecosystem_registries} table this maps to is emptied on the {@code closed-mode} branch by
 * {@code R__closed_mode_strip.sql} — a repeatable migration that runs once on a brand-new database
 * (guaranteeing a fresh DB starts empty) but, per Flyway's own repeatable-migration semantics,
 * re-runs only when that file's own checksum changes, NOT automatically on every build/deploy. A
 * row that reappears on an already-migrated database (a stray insert, a future master-branch merge
 * reintroducing seed data) is therefore only stripped again once that migration file's content is
 * itself edited in the same change (see its own header comment for the maintenance procedure) —
 * see {@code known-limitations.md} item 285 for the shared-test-database Flyway-collision failure
 * mode this distinction matters for.
 *
 * <p>The type/repository stay, unlike the data: keeping the JPA mapping avoids carving this class
 * out of every place that would otherwise need conditional closed-mode-only code just to compile.
 * {@link com.vulncheck.app.controller.GuideController} no longer queries this table (senior-reviewer
 * REVISE, item 262/PR#200) — its registry-list guide page section is a static list now, since an
 * always-empty DB-driven table misleadingly implied this deployment does no registry matching at
 * all, when in fact all 10 registry clients still serve Tier1 lookups from their local mirror.
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
