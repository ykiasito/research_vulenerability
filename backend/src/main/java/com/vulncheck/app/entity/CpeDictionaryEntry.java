package com.vulncheck.app.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import java.time.OffsetDateTime;
import java.util.Set;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "cpe_dictionary")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CpeDictionaryEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "cpe_string", nullable = false)
    private String cpeString;

    private String title;

    private String vendor;

    private String product;

    @Column(name = "last_synced_at", nullable = false)
    private OffsetDateTime lastSyncedAt;

    /**
     * The full set of distinct {@code target_sw} values (CPE 2.3 segment 11, 1-indexed — segment
     * index 10 in a 0-indexed {@code split(":")} array, matching {@link
     * com.vulncheck.app.service.nvd.CpeUtils}'s own vendor/product segment convention) across every
     * row sharing this entry's vendor/product pair, not just this one row's own version — see
     * {@link com.vulncheck.app.repository.CpeDictionaryRepositoryImpl#findFuzzyMatches} for how
     * this gets populated. Not a persisted column: populated in Java from a per-query aggregate,
     * hence {@link Transient}. Null/empty whenever a candidate wasn't sourced from that query (e.g.
     * the name-variant search), which {@link com.vulncheck.app.service.Stage1IdentificationService}
     * treats as "no target_sw signal to gate on" rather than a hard reject.
     */
    @Transient
    private Set<String> targetSwValues;

    /**
     * The highest major version number (leading digit run of CPE 2.3 segment 6, 1-indexed) across
     * every row sharing this entry's vendor/product pair, not just this one row's own version — a
     * single scalar rather than the full per-(vendor, product) set of catalogued version strings,
     * since {@link com.vulncheck.app.service.Stage1IdentificationService}'s {@code
     * versionCoverageIsPlausible} tie-break only ever needs the highest one and real (vendor,
     * product) pairs can have thousands of distinct catalogued versions (see {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryImpl#findFuzzyMatches} for how this gets
     * populated and computed). Not a persisted column: populated in Java from a per-query aggregate,
     * hence {@link Transient}. Null whenever a candidate wasn't sourced from that query (e.g. the
     * name-variant search) or none of the pair's catalogued versions had a numeric leading run,
     * which {@link com.vulncheck.app.service.Stage1IdentificationService} treats as "no version
     * coverage evidence" (never a hard reject — see that class's {@code versionCoverageIsPlausible}).
     */
    @Transient
    private Integer maxCatalogedMajor;

    /**
     * The number of rows sharing this entry's vendor/product pair in the {@code cpe_dictionary}
     * table (every catalogued version, not just this one row's own) — backlog item 89's K3 ranking
     * tie-break: {@link com.vulncheck.app.service.Stage1IdentificationService#rankCpeCandidates}
     * uses it, descending, as the last tie-break among candidates that are otherwise indistinguishable
     * (e.g. Greenshot 1.3.290 against both {@code getgreenshot:greenshot} (80 catalogued rows) and
     * {@code greenshot:greenshot} (1 row) — the row-count-richer pair is far more likely to be NVD's
     * real, actively-maintained tracking entry for the product). Computed the same unconditional,
     * whole-partition way as {@link #maxCatalogedMajor} (see {@link
     * com.vulncheck.app.repository.CpeDictionaryRepositoryImpl#collect} for how this gets populated).
     * Not a persisted column: populated in Java from a per-query aggregate, hence {@link Transient}.
     * Null whenever a candidate wasn't sourced from that query (e.g. the name-variant search), which
     * {@link com.vulncheck.app.service.Stage1IdentificationService} treats as "no evidence" (lowest
     * tie-break priority, same as a literal 0).
     */
    @Transient
    private Integer catalogedRowCount;
}
