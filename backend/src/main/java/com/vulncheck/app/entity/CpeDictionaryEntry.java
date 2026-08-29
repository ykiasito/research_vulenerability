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
}
