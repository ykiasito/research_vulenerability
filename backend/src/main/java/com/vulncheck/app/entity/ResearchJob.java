package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.OffsetDateTime;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "research_jobs")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class ResearchJob {

    public static final String STATUS_PENDING = "PENDING";
    public static final String STATUS_PROCESSING = "PROCESSING";
    public static final String STATUS_COMPLETED = "COMPLETED";
    public static final String STATUS_FAILED = "FAILED";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "csv_filename", nullable = false)
    private String csvFilename;

    @Column(nullable = false)
    private String status;

    @Column(name = "created_at", insertable = false, updatable = false)
    private OffsetDateTime createdAt;

    @Column(name = "completed_at")
    private OffsetDateTime completedAt;

    /** Set at job completion (see {@code ResearchJobProcessingService}) when at least 30 of this
     *  job's items resolved to a registry (ecosystem+purl both present) but fewer than half of
     *  those had their exact version confirmed as a real published release there — a signal the
     *  uploaded CSV's version column may not reflect actual releases, so results should be treated
     *  cautiously. Purely informational: never blocks job completion or represents a failure. */
    @Column(name = "version_plausibility_warning", nullable = false)
    private boolean versionPlausibilityWarning;

    /** Per-job opt-in for bundled-package (formerly "Stage 3.5") vulnerability detection — see
     *  {@code BundledComponentResearchService} and {@code docs/spec/bundled-package-detection-plan.md}.
     *  Off by default: this feature adds an LLM changelog-discovery web_search call plus an
     *  extraction call per eligible item, roughly matching Stage4's own cost, so it only runs (and
     *  only draws down its own separate {@link com.vulncheck.app.service.JobCostBudgetService}
     *  allotment) for a job whose owner explicitly checked the box on the upload form. */
    @Column(name = "bundled_component_check_enabled", nullable = false)
    private boolean bundledComponentCheckEnabled;
}
