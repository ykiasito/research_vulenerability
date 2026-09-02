package com.vulncheck.app.repository;

import java.util.List;

/**
 * CRUD surface for the {@code registry_mirror_seed_name} table (closed-mode backlog item 185).
 * Plain JdbcTemplate-backed (see {@link RegistryMirrorSeedNameRepositoryImpl}), same shape as
 * {@link RegistryPackageMirrorRepository} -- no Spring Data JPA entity, since every access here is
 * either a distinct-name read or a batch insert, neither of which benefit from JPA's
 * query-derivation machinery.
 */
public interface RegistryMirrorSeedNameRepository {

    /**
     * Distinct package names an admin has uploaded for this ecosystem via {@code
     * /admin/registry-mirror/seed-names} -- unioned with {@code identified_products}' own
     * distinct-name query by {@code RegistryMirrorSyncService#collectSeedNames}, not a replacement
     * for it.
     */
    List<String> findDistinctPackageNames(String ecosystem);

    /**
     * Inserts one batch of package names for a single ecosystem, ignoring names already present
     * (re-uploading the same list, or a list overlapping a previous one, is always safe). No-op for
     * an empty list.
     */
    void insertBatch(String ecosystem, List<String> packageNames);
}
