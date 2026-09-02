package com.vulncheck.app.architecture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.FileSystemResource;

/**
 * Closed-mode backlog item 196 (B7, {@code docs/spec/closed-mode-plan.md} §3-6): mechanical
 * enforcement that {@code closed-mode}'s core invariant (§3-2, "the diff from master is deletions
 * only") hasn't silently regressed — e.g. via a routine {@code master} merge (§9-3) that
 * reintroduces a class this branch deliberately deleted. This class (plus its sibling {@link
 * ClosedModeBeanArchitectureGateTest}, which needs a real {@code ApplicationContext}) covers all
 * five checks from §3-6; each gets its own {@code @Test} method so a failure names exactly which
 * invariant broke.
 *
 * <p>Deliberately no {@code @SpringBootTest} here and no new dependency (ArchUnit was considered
 * but skipped — see PR description) — every check below is answerable with plain reflection or a
 * classpath-relative file read, so this suite stays fast and, unlike most of this module's other
 * tests, never needs {@code --network research_vulenerability_default} or a running postgres.
 *
 * <p><b>Repo-root-relative checks (docker-compose.yml, {@code llm-service/}) and the local {@code
 * mvn test} sandbox</b>: when this module's tests are run by mounting only the {@code backend/}
 * directory into a Maven container (rather than the whole repository checkout), a path one level
 * above the module root (e.g. {@code ../docker-compose.yml}) resolves to nothing inside that
 * container even when the real file exists on the host. Rather than hard-failing the whole suite
 * on an environment limitation that has nothing to do with the invariant being tested, those
 * specific assertions use {@link Assumptions#assumeTrue} to skip (not pass, not fail) when the
 * repo root isn't reachable from the test's working directory — this shows up distinctly as
 * "skipped" in the Surefire summary rather than a false green.
 *
 * <p>The canonical execution path that actually exercises these repo-root-relative checks is
 * {@code .github/workflows/closed-mode-architecture-gate.yml} — it checks out the full repository
 * and passes {@code -Dclosedmode.gate.require-repo-root=true}, which flips a null repo root from a
 * skip into a hard failure (see {@link #REQUIRE_REPO_ROOT_PROPERTY}), so this suite can't silently
 * stop covering them without CI noticing. Running {@code mvn test} locally with only {@code
 * backend/} mounted remains a legitimate reduced/offline way to run the rest of this suite; those
 * two checks are simply expected to skip there.
 */
class ClosedModeArchitectureGateTest {

    /**
     * System property (see {@code .github/workflows/closed-mode-architecture-gate.yml}) that
     * flips {@link #repoRootOrSkip(String)} from skipping (via {@link Assumptions#assumeTrue})
     * to failing outright when the repository root isn't reachable. Locally — e.g. {@code mvn
     * test} with only {@code backend/} mounted into a container — that unreachability is an
     * expected environment limitation, so those specific checks should skip rather than fail.
     * Under CI, the whole repository is checked out, so a null repo root there would mean this
     * suite silently stopped exercising those checks (e.g. because a checkout-path change broke
     * {@link #repoRoot()}'s "one level up from the backend module root" assumption) — that must
     * be a hard failure, not a skip, or the regression could go unnoticed indefinitely.
     */
    private static final String REQUIRE_REPO_ROOT_PROPERTY = "closedmode.gate.require-repo-root";

    private static final String REGISTRY_PACKAGE = "com.vulncheck.app.service.registry";

    /** The 10 Stage1 Tier1 registry clients (§3-8) — every implementor of {@code
     *  PackageRegistryLookup} as of B3 (item 193). Kept as an explicit roster (rather than a
     *  classpath scan) so a class rename/move shows up here as a compile error, not a silently
     *  narrower check. */
    private static final List<String> REGISTRY_CLIENT_CLASSES = List.of(
            REGISTRY_PACKAGE + ".CratesIoRegistryClient",
            REGISTRY_PACKAGE + ".GoProxyRegistryClient",
            REGISTRY_PACKAGE + ".HexRegistryClient",
            REGISTRY_PACKAGE + ".MavenCentralRegistryClient",
            REGISTRY_PACKAGE + ".NpmRegistryClient",
            REGISTRY_PACKAGE + ".NuGetRegistryClient",
            REGISTRY_PACKAGE + ".PackagistRegistryClient",
            REGISTRY_PACKAGE + ".PubRegistryClient",
            REGISTRY_PACKAGE + ".PyPiRegistryClient",
            REGISTRY_PACKAGE + ".RubyGemsRegistryClient");

    // ------------------------------------------------------------------------------------------
    // §3-6 item 1: classpath must not contain anthropic / LlmServiceClient / live *RegistryClient
    // / NvdVulnerabilitySource / OsvLiveQueryClient.
    //
    // Note on "live *RegistryClient": §3-6's original text was written expecting B3 to delete the
    // 10 *RegistryClient classes outright (same treatment as LlmServiceClient for B1). B3 (item
    // 193) instead kept all 10 classes and removed only their live HTTP lookup path once Phase
    // D's registry mirror (§5) became available as a same-quality replacement — a deliberate,
    // documented divergence from the literal plan text (see also
    // ClosedModeBeanArchitectureGateTest's note on this same gap for §3-6 item 4). This is why
    // liveRegistryClientsHaveNoLookupLiveMethod() below checks for classpath presence + no
    // lookupLive method, rather than classpath absence.
    // ------------------------------------------------------------------------------------------

    @Test
    void llmServiceClientIsAbsentFromClasspath() {
        assertThrows(
                ClassNotFoundException.class,
                () -> Class.forName("com.vulncheck.app.service.llm.LlmServiceClient"),
                "LlmServiceClient must not exist on closed-mode's classpath (B1, item 177) — "
                        + "its presence means the Python llm-service's Java-side counterpart came back, "
                        + "most likely via an unreviewed master merge (§9-3).");
    }

    /**
     * Proxy for "the {@code anthropic} pip package is gone" (§3-6 item 1): {@code anthropic} was
     * only ever a dependency of the Python {@code llm-service/} (B1, item 177 deleted it wholesale
     * along with {@code main.py}/{@code requirements.txt}/etc.) — it was never a Java/Maven
     * dependency of this backend module (confirmed: no {@code anthropic} artifact ever appeared in
     * {@code backend/pom.xml}), so there is no Java class to {@code Class.forName} for it. The
     * closest classpath-suite-verifiable proxy is that the {@code llm-service/} directory itself
     * (which is what carried that pip dependency) does not exist in the repository.
     */
    @Test
    void llmServiceDirectoryIsAbsentFromRepository() throws IOException {
        Path repoRoot = repoRootOrSkip(
                "this run cannot verify llm-service/ absence, only LlmServiceClient's");

        Path llmService = repoRoot.resolve("llm-service");
        assertThat(Files.exists(llmService))
                .as("llm-service/ (and with it the anthropic pip dependency, B1/item 177) must not "
                        + "exist in closed-mode")
                .isFalse();
    }

    @Test
    void liveRegistryClientsHaveNoLookupLiveMethod() {
        for (String className : REGISTRY_CLIENT_CLASSES) {
            Class<?> clazz;
            try {
                clazz = Class.forName(className);
            } catch (ClassNotFoundException e) {
                // B3 (item 193, docs/spec/closed-mode-plan.md §3-8) removed the live HTTP lookup
                // *path* from all 10 registry clients, deliberately choosing not to delete the
                // classes themselves — they stay as mirror-only PackageRegistryLookup
                // implementations. So this class disappearing entirely is not "B3 progressing
                // further", it's a coverage loss: this registry's Stage1 identification support
                // is gone outright, not just its live-HTTP fallback. A bare
                // ClassNotFoundException here gives no hint of that, so wrap it.
                throw new AssertionError(className + " is missing from the classpath entirely. "
                        + "B3 (item 193) removed the live lookup path, not the class — if this "
                        + "class genuinely disappeared (e.g. via a master merge, §9-3), that means "
                        + "Stage1 lost this registry's coverage entirely, not just its live-HTTP "
                        + "fallback.", e);
            }
            assertThat(hasMethodNamed(clazz, "lookupLive"))
                    .as("%s must not have a lookupLive method — its live HTTP lookup path was "
                            + "supposed to be removed outright in B3 (item 193), not just made "
                            + "unreachable", className)
                    .isFalse();
        }
    }

    @Test
    @Disabled(
            "NvdVulnerabilitySource/OsvLiveQueryClient are B4 work (docs/spec/closed-mode-plan.md "
                    + "§9-2 Phase B), not yet started as of item 196 — they still legitimately exist on "
                    + "closed-mode today. Re-enable this test as part of implementing B4 (live NVD/live "
                    + "OSV removal), at which point both classes should be gone.")
    void nvdAndOsvLiveClientsAreAbsentFromClasspath() {
        assertThrows(
                ClassNotFoundException.class,
                () -> Class.forName("com.vulncheck.app.service.vuln.NvdVulnerabilitySource"));
        assertThrows(
                ClassNotFoundException.class,
                () -> Class.forName("com.vulncheck.app.service.vuln.OsvLiveQueryClient"));
    }

    // ------------------------------------------------------------------------------------------
    // §3-6 item 3: docker-compose.yml must not define an llm-service service.
    // ------------------------------------------------------------------------------------------

    @Test
    void dockerComposeHasNoLlmServiceService() throws IOException {
        Path repoRoot = repoRootOrSkip("cannot read docker-compose.yml from here");

        Path composeFile = repoRoot.resolve("docker-compose.yml");
        // 2026-09-02 (REVISE R7): this used to be Assumptions.assumeTrue, which meant a
        // renamed/deleted docker-compose.yml made the whole check skip (green) even under CI with
        // -Dclosedmode.gate.require-repo-root=true — the exact "silent skip under CI" failure mode
        // repoRootOrSkip above exists to close, just reopened one level down. Once repoRootOrSkip
        // has confirmed the repo root itself is reachable, the compose file's existence is part of
        // the invariant being asserted, not an environment limitation, so it must be a hard
        // assertion.
        assertThat(Files.exists(composeFile))
                .as("docker-compose.yml must exist at %s (repo root was reachable) — its "
                        + "disappearance/rename must fail this gate, not silently skip it", composeFile)
                .isTrue();

        // Same technique as com.vulncheck.app.config.PoolSizeConfigBindingTest: load the YAML
        // directly with Spring's own loader rather than hand-rolling a parser, then inspect the
        // flattened property keys it produces (e.g. "services.llm-service.image") instead of
        // scanning raw lines, so indentation/quoting differences in the compose file can't fool a
        // naive substring check.
        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        List<PropertySource<?>> loaded = loader.load("docker-compose", new FileSystemResource(composeFile));

        Set<String> propertyNames = loaded.stream()
                .flatMap(source -> streamPropertyNames(source))
                .collect(Collectors.toSet());

        // 2026-09-02 (REVISE R7): guard against a vacuous pass. If the YAML loader (or the
        // compose file's structure) produced zero services.* keys at all, the anyMatch check below
        // would report "no services.llm-service key" — true, but for the wrong reason (nothing was
        // extracted, not "llm-service specifically is absent"). Assert the extraction actually
        // found some services.* keys before trusting its absence of services.llm-service.
        assertThat(propertyNames)
                .as("docker-compose.yml must yield at least one services.* property key once "
                        + "loaded — an empty result here means the YAML loader (or the compose "
                        + "file's structure) is broken, which would make the services.llm-service "
                        + "absence check below vacuously (and wrongly) pass")
                .anyMatch(name -> name.startsWith("services."));

        boolean hasLlmServiceKey = propertyNames.stream()
                .anyMatch(name -> name.startsWith("services.llm-service"));

        assertThat(hasLlmServiceKey)
                .as("docker-compose.yml must not define a services.llm-service entry (B1, item 177)")
                .isFalse();
    }

    private static Stream<String> streamPropertyNames(PropertySource<?> source) {
        if (source.getSource() instanceof java.util.Map<?, ?> map) {
            return map.keySet().stream().map(String::valueOf);
        }
        return Stream.empty();
    }

    // ------------------------------------------------------------------------------------------
    // §3-6 item 5: db/migration's V*__ file set must be byte-for-byte identical to master's
    // (checked both ways: no extra file, and no missing file).
    // ------------------------------------------------------------------------------------------

    /**
     * Snapshot of {@code backend/src/main/resources/db/migration}'s {@code V*__*.sql} filenames on
     * {@code origin/master}, taken 2026-09-02 while implementing item 196 — at that point
     * closed-mode's own migration set was byte-for-byte identical to master's (38 files, V1..V38,
     * no gaps), exactly as §3-2's Flyway invariant requires. There is no git access inside the
     * {@code mvn test} sandbox (only {@code backend/} is mounted, not {@code .git}), so this can't
     * be a live {@code git diff} against {@code origin/master} — this baseline is the closest
     * mechanical substitute.
     *
     * <p><b>Maintenance</b>: update this set in the same commit that merges a {@code master} sync
     * bringing in new {@code V*__} files (§9-3 sync discipline) — that is the one legitimate reason
     * for this test to need a change. If it fails WITHOUT a preceding master-sync merge, that means
     * a {@code V*__} file was added directly on closed-mode, which violates §3-2 and must be
     * reverted, not accommodated by editing this baseline.
     */
    private static final Set<String> MASTER_MIGRATION_BASELINE = Set.of(
            "V1__init.sql",
            "V2__stage1_support.sql",
            "V3__ecosystem_registries.sql",
            "V4__identification_hint.sql",
            "V5__version_confirmed.sql",
            "V6__hint_investigation_fields.sql",
            "V7__fixed_version.sql",
            "V8__cve_org.sql",
            "V9__trgm_query_performance.sql",
            "V10__more_ecosystems.sql",
            "V11__vulnerability_research_incomplete.sql",
            "V12__research_incomplete_reason.sql",
            "V13__backfill_corrupted_cpe_vendor_product.sql",
            "V14__chocolatey_ecosystem.sql",
            "V15__version_plausibility_warning.sql",
            "V16__bundled_component_detection.sql",
            "V17__csaf_vendor_advisories.sql",
            "V18__csaf_product_status_unique.sql",
            "V19__ghsa_advisories.sql",
            "V20__csaf_redhat_support.sql",
            "V21__csaf_redhat_revise_fixes.sql",
            "V22__csaf_redhat_revise_followup.sql",
            "V23__job_cost_ledger.sql",
            "V24__job_cost_ledger_item_index.sql",
            "V25__osv_advisories.sql",
            "V26__research_job_items_raw_product_name.sql",
            "V27__job_cost_ledger_breakdown.sql",
            "V28__high_confidence_verification.sql",
            "V29__verification_ledger.sql",
            "V30__cpe_candidate_provenance.sql",
            "V31__cpe_dictionary_vendor_product_index.sql",
            "V32__remove_chocolatey_ecosystem.sql",
            "V33__research_incomplete_reason_ai_gaps.sql",
            "V34__research_incomplete_reason_ai_call_failed.sql",
            "V35__users_email_lower_unique_index.sql",
            "V36__normalize_users_email_lowercase.sql",
            "V37__registry_package_mirror.sql",
            "V38__registry_mirror_seed_name.sql");

    private static final Pattern VERSIONED_MIGRATION = Pattern.compile("V\\d+__.*\\.sql");

    @Test
    void migrationSetMatchesMasterBaseline() throws IOException {
        Path migrationDir = Path.of("src/main/resources/db/migration");
        assertThat(Files.isDirectory(migrationDir))
                .as("expected %s to exist relative to the backend module root", migrationDir)
                .isTrue();

        try (Stream<Path> files = Files.list(migrationDir)) {
            Set<String> actualVersionedFiles = files
                    .map(path -> path.getFileName().toString())
                    .filter(name -> VERSIONED_MIGRATION.matcher(name).matches())
                    .collect(Collectors.toSet());

            // Compute both directions up front (not just for the failure message, but so the
            // assertion below reports which side of the mismatch it is) — an unexpected addition
            // (§3-2 violation) and a missing baseline file (silently dropped a migration, which
            // this suite must also catch — an isSubsetOf-style check on "unexpected" alone would
            // have missed a deletion entirely) are different problems and shouldn't be conflated
            // into one undifferentiated "not equal" message.
            Set<String> unexpected = actualVersionedFiles.stream()
                    .filter(name -> !MASTER_MIGRATION_BASELINE.contains(name))
                    .collect(Collectors.toSet());
            Set<String> missing = MASTER_MIGRATION_BASELINE.stream()
                    .filter(name -> !actualVersionedFiles.contains(name))
                    .collect(Collectors.toSet());

            assertThat(actualVersionedFiles)
                    .as("db/migration's V*__ file set must match the master baseline exactly "
                            + "(extra, not on master: %s | missing, on master but not here: %s) — "
                            + "either the baseline needs refreshing after a master-sync merge (§9-3), "
                            + "or closed-mode added/removed a migration in violation of §3-2",
                            unexpected, missing)
                    .isEqualTo(MASTER_MIGRATION_BASELINE);
        }
    }

    // ------------------------------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------------------------------

    private static boolean hasMethodNamed(Class<?> clazz, String methodName) {
        for (Class<?> current = clazz; current != null && current != Object.class; current = current.getSuperclass()) {
            if (Arrays.stream(current.getDeclaredMethods())
                    .map(Method::getName)
                    .anyMatch(methodName::equals)) {
                return true;
            }
        }
        return false;
    }

    /**
     * {@code mvn test}'s working directory is the backend module root (see e.g. {@code
     * PoolSizeConfigBindingTest}'s use of {@code "src/main/resources/application.yml"}), so the
     * repository root — when reachable at all, see class javadoc — is exactly one level up.
     * Returns {@code null} (never throws) when it isn't reachable, so callers can {@link
     * Assumptions#assumeTrue} rather than fail on an environment limitation.
     */
    private static Path repoRoot() {
        Path candidate = Path.of("..").toAbsolutePath().normalize();
        if (Files.isDirectory(candidate.resolve("backend")) && Files.isDirectory(candidate.resolve("docs"))) {
            return candidate;
        }
        return null;
    }

    /**
     * Resolves the repository root for a repo-root-relative check, or aborts the test — see
     * {@link #REQUIRE_REPO_ROOT_PROPERTY} for how "aborts" differs between a local run (skip) and
     * {@code .github/workflows/closed-mode-architecture-gate.yml} (hard failure).
     */
    private static Path repoRootOrSkip(String reasonIfUnreachable) {
        Path repoRoot = repoRoot();
        if (repoRoot != null) {
            return repoRoot;
        }
        if (Boolean.getBoolean(REQUIRE_REPO_ROOT_PROPERTY)) {
            throw new AssertionError(
                    "repository root not reachable from this sandbox, but -D" + REQUIRE_REPO_ROOT_PROPERTY
                            + "=true was set (expected under "
                            + ".github/workflows/closed-mode-architecture-gate.yml, which checks out the full "
                            + "repository) — " + reasonIfUnreachable + ". Treating this as a hard failure "
                            + "instead of a skip so a checkout-path regression can't silently stop this check "
                            + "from ever running in CI.");
        }
        Assumptions.assumeTrue(false, "repository root not reachable from this sandbox (see class javadoc) — "
                + reasonIfUnreachable);
        throw new AssertionError("unreachable: assumeTrue(false, ...) always aborts the test");
    }
}
