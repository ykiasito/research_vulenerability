package com.vulncheck.app.repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * CRUD surface for the {@code registry_package_mirror} table (closed-mode backlog item 176 pilot).
 * Plain JdbcTemplate-backed (see {@link RegistryPackageMirrorRepositoryImpl}), same shape as {@code
 * CpeDictionaryRepositoryCustom} -- no Spring Data JPA repository/entity for this table, since every
 * access here is either a single-row upsert/lookup or a batch upsert, none of which benefit from
 * JPA's query-derivation machinery, and a JPA entity would need extra Hibernate array-type wiring
 * for the {@code versions text[]} column that a plain {@code java.sql.Array} read/write avoids.
 */
public interface RegistryPackageMirrorRepository {

    /**
     * Whether this ecosystem has been synced at all (any row, regardless of package). Callers use
     * this to distinguish "the mirror is enabled but nobody has run the initial sync yet" (fall back
     * to live) from "the mirror is enabled and populated, but this specific package isn't in it"
     * (a real, confident negative -- see {@link #findVersions}).
     */
    boolean hasAnyEntries(String ecosystem);

    /**
     * The published version list for one (ecosystem, normalized package name), or an empty list if
     * this exact package has no mirrored row -- deliberately not {@code Optional}: an absent row and
     * a row with an empty {@code versions} array mean the same thing to every caller (no evidence
     * this package/version exists in the mirror), so there is nothing for a caller to do differently
     * between the two.
     *
     * @param normalizedPackageName must already be normalized the same way {@link
     *                              com.vulncheck.app.service.vuln.OsvPackageNameNormalizer#normalize}
     *                              would produce for this ecosystem -- this method does not
     *                              normalize its input itself.
     */
    List<String> findVersions(String ecosystem, String normalizedPackageName);

    /**
     * Upserts one batch of (normalized package name -> version list) rows for a single ecosystem.
     * Idempotent -- re-running with the same or updated data is exactly what "differential sync"
     * means for this mirror (see {@code CratesIoMirrorSyncService}'s class javadoc), there being no
     * separate delta/changelog endpoint on the crates.io sparse index to consume instead.
     */
    void upsertBatch(String ecosystem, Map<String, List<String>> versionsByNormalizedPackageName);

    /**
     * Normalized package names for this ecosystem whose {@code last_synced_at} is at or after
     * {@code cutoff} -- used by {@link com.vulncheck.app.service.registry.RegistryMirrorSyncService}
     * (closed-mode backlog item 186) to skip re-fetching a name this ecosystem's mirror already
     * refreshed recently, rather than unconditionally re-syncing every observed name on every run.
     * A name absent from {@code registry_package_mirror} entirely (never synced) is never in the
     * returned set, regardless of {@code cutoff} -- there is no {@code last_synced_at} to compare.
     */
    Set<String> findFreshlySyncedNormalizedPackageNames(String ecosystem, Instant cutoff);
}
