package com.vulncheck.app.architecture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
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
    // / OsvLiveQueryClient. NvdVulnerabilitySource is a second deliberate divergence from this
    // item's literal wording, alongside the *RegistryClient one below (closed-mode backlog item
    // 264/B4, 2026-09-04): it stays on the classpath as a mirror-only VulnerabilitySource rather
    // than being deleted outright, since (unlike OsvLiveQueryClient, whose sole caller was already
    // gutted to a no-op) it also implements Stage2's real, still-needed NVD CVE mirror lookup —
    // only its live NVD CVE API path (fetchFromNvd) was removed. Item 261 (B7, 2026-09-04)
    // re-enabled the OsvLiveQueryClient half unchanged and added
    // nvdVulnerabilitySourceHasNoEgressCapableMembers() below as the "no live-egress capability"
    // check this class's own field/constructor-parameter scan can express for a class that
    // deliberately still exists (mirroring liveRegistryClientsHaveNoLookupLiveMethod()'s approach
    // for the 10 registry clients) — confirmed today that NvdVulnerabilitySource only holds
    // jdbcTemplate/transactionManager fields, no RestClient or other egress-capable member,
    // now that item 263 deleted RestClientConfig#externalApiRestClient outright.
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
    void osvLiveQueryClientIsAbsentFromClasspath() {
        assertThrows(
                ClassNotFoundException.class,
                () -> Class.forName("com.vulncheck.app.service.vuln.OsvLiveQueryClient"));
    }

    /**
     * The "no live-egress capability" half of §3-6 item 1 for {@code NvdVulnerabilitySource} —
     * deliberately not a classpath-absence check (that class stays, see the section note above).
     * Reuses the same field/constructor-parameter scan as {@link
     * #registryClientsHaveNoEgressCapableMembers()} below rather than a hand-rolled reflection walk,
     * so a future addition to {@link #EGRESS_CAPABLE_TYPES} (e.g. R9's {@code RestClient.Builder}
     * addition) automatically covers this class too.
     */
    @Test
    void nvdVulnerabilitySourceHasNoEgressCapableMembers() {
        Class<?> nvdVulnerabilitySource;
        try {
            nvdVulnerabilitySource = Class.forName("com.vulncheck.app.service.vuln.NvdVulnerabilitySource");
        } catch (ClassNotFoundException e) {
            throw new AssertionError("NvdVulnerabilitySource is missing from the classpath entirely. "
                    + "It was deliberately kept as a mirror-only VulnerabilitySource (B4, item 264) — "
                    + "Stage2's real NVD CVE mirror lookup — not deleted outright; if it genuinely "
                    + "disappeared (e.g. via a master merge, §9-3), Stage2 lost NVD CVE coverage "
                    + "entirely, not just its live-API fallback.", e);
        }

        assertThat(findEgressCapableMembers(nvdVulnerabilitySource))
                .as("NvdVulnerabilitySource holds a field or constructor argument typed as one of "
                        + "%s — B4 (item 264) was supposed to remove the *capability* to make a live "
                        + "HTTP call from this class outright, not just leave its live NVD CVE fetch "
                        + "method (fetchFromNvd) unreachable", EGRESS_CAPABLE_TYPES)
                .isEmpty();
    }

    // ------------------------------------------------------------------------------------------
    // §3-6 item 4 (classpath-only half): registry clients must hold no field/constructor
    // parameter capable of making a network call.
    //
    // Duplicated (not moved, 2026-09-02 REVISE R8) from ClosedModeBeanArchitectureGateTest's
    // registryLookupListIsFullyPopulatedAndMirrorOnly(): that scan is plain java.lang.reflect over
    // a fixed class roster (REGISTRY_CLIENT_CLASSES above) and needs neither Spring nor a running
    // postgres, so parking it exclusively in the @SpringBootTest sibling meant CI (which only runs
    // this class, see the class javadoc) never exercised it. ClosedModeBeanArchitectureGateTest's
    // DI-based scan over List<PackageRegistryLookup> is kept as-is (not deleted): it additionally
    // catches a future PackageRegistryLookup implementation that isn't on REGISTRY_CLIENT_CLASSES
    // but *is* wired into the Spring context, which this classpath-only check cannot see.
    // ------------------------------------------------------------------------------------------

    /**
     * Types that give a class the physical ability to make an outbound HTTP(S)/network call.
     * Shared with {@link ClosedModeBeanArchitectureGateTest}, which reuses this set and {@link
     * #findEgressCapableMembers(Class)} for its DI-based scan — see that class's javadoc for why
     * the two checks both exist.
     *
     * <p>2026-09-02 (REVISE R9): the original list matched by exact type name only, which missed
     * two real cases — {@code RestClient.Builder} (type name {@code
     * org.springframework.web.client.RestClient$Builder}, the idiomatic Spring Boot injection
     * point for building a {@code RestClient} lazily) and {@code HttpURLConnection} (what code
     * actually declares; bare {@code URLConnection} is a supertype nobody writes as a field type,
     * so it was effectively a dead entry) — and was missing {@code java.net.Socket} outright.
     * {@link #isEgressCapableType(Class)} below also now walks the type hierarchy (superclasses
     * and interfaces), so a subtype/implementor of any of these is caught even when it isn't
     * itself in this set.
     */
    static final Set<String> EGRESS_CAPABLE_TYPES = Set.of(
            "org.springframework.web.client.RestClient",
            "org.springframework.web.client.RestClient$Builder",
            "org.springframework.web.client.RestTemplate",
            "org.springframework.web.reactive.function.client.WebClient",
            "java.net.http.HttpClient",
            "java.net.URL",
            "java.net.URLConnection",
            "java.net.HttpURLConnection",
            "java.net.Socket");

    @Test
    void registryClientsHaveNoEgressCapableMembers() {
        List<String> egressCapableFindings = new ArrayList<>();
        for (String className : REGISTRY_CLIENT_CLASSES) {
            egressCapableFindings.addAll(findEgressCapableMembers(loadRegistryClientOrFail(className)));
        }

        assertThat(egressCapableFindings)
                .as("these registry clients hold a field or constructor argument typed as one of "
                        + "%s — B3 (item 193) was supposed to remove the *capability* to make a "
                        + "live HTTP call from every registry client, not just rename or hide the "
                        + "method that used it", EGRESS_CAPABLE_TYPES)
                .isEmpty();
    }

    private static Class<?> loadRegistryClientOrFail(String className) {
        try {
            return Class.forName(className);
        } catch (ClassNotFoundException e) {
            throw new AssertionError(className + " is missing from the classpath entirely. "
                    + "B3 (item 193) removed the live lookup path, not the class — if this "
                    + "class genuinely disappeared (e.g. via a master merge, §9-3), that means "
                    + "Stage1 lost this registry's coverage entirely, not just its live-HTTP "
                    + "fallback.", e);
        }
    }

    /**
     * Scans {@code clazz}'s own declared fields and every declared constructor's parameter types
     * for anything {@link #isEgressCapableType(Class) egress-capable}, returning one
     * human-readable description per hit (class + field/parameter name + offending type) so a
     * failure names exactly what to remove.
     */
    static List<String> findEgressCapableMembers(Class<?> clazz) {
        List<String> findings = new ArrayList<>();
        for (Field field : clazz.getDeclaredFields()) {
            if (isEgressCapableType(field.getType())) {
                findings.add(clazz.getName() + "#" + field.getName() + " (field type "
                        + field.getType().getName() + ")");
            }
        }
        for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
            Class<?>[] parameterTypes = constructor.getParameterTypes();
            for (int i = 0; i < parameterTypes.length; i++) {
                if (isEgressCapableType(parameterTypes[i])) {
                    findings.add(clazz.getName() + " constructor parameter #" + i + " (type "
                            + parameterTypes[i].getName() + ")");
                }
            }
        }
        return findings;
    }

    /**
     * Whether {@code type} is one of {@link #EGRESS_CAPABLE_TYPES}, or (recursively, via
     * superclasses and implemented/extended interfaces) a subtype of one. 2026-09-02 (REVISE
     * R9): recursing rather than a single {@code EGRESS_CAPABLE_TYPES.contains(type.getName())}
     * check means a future subtype we haven't explicitly enumerated (e.g. a wrapper class
     * extending {@code RestTemplate}) is still caught.
     */
    static boolean isEgressCapableType(Class<?> type) {
        if (type == null || type == Object.class) {
            return false;
        }
        if (EGRESS_CAPABLE_TYPES.contains(type.getName())) {
            return true;
        }
        if (isEgressCapableType(type.getSuperclass())) {
            return true;
        }
        for (Class<?> iface : type.getInterfaces()) {
            if (isEgressCapableType(iface)) {
                return true;
            }
        }
        return false;
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
            "V38__registry_mirror_seed_name.sql",
            "V39__nvd_cve_mirror.sql",
            "V40__vulnerabilities_cvss_score_and_max_fixed_version.sql",
            "V41__backfill_max_fixed_version.sql");

    /**
     * SHA-256 (hex-encoded) of every file in {@link #MASTER_MIGRATION_BASELINE}, taken from the
     * same {@code origin/master} snapshot (2026-09-02, item 196) as that filename set.
     *
     * <p>Closed-mode backlog item 205: {@link #migrationSetMatchesMasterBaseline()} only compares
     * the *set of filenames* under {@code db/migration} — it is blind to an existing {@code V*__}
     * file's SQL body being edited in place while its filename stays the same. Flyway migrations
     * are checksum-validated against {@code flyway_schema_history} at application startup, so a
     * content edit to an already-applied migration doesn't show up as a test failure anywhere
     * else in this suite; it shows up as a {@code FlywayValidateException} the next time an
     * environment that already ran the original content starts up — i.e. only in whichever
     * deployment happens to hit it first, potentially production. This map + {@link
     * #migrationContentMatchesMasterBaseline()} close that gap the same way the filename set
     * closes the "extra/missing file" gap.
     *
     * <p><b>Maintenance</b>: same discipline as {@link #MASTER_MIGRATION_BASELINE} — update both
     * together, in the same commit that merges a {@code master} sync bringing in new {@code V*__}
     * files (§9-3). Flyway migrations that have already shipped are not supposed to have their
     * body edited on master, either, after the fact — so if this fails WITHOUT a preceding
     * master-sync merge that plausibly explains it, treat it as a real content-drift bug on
     * closed-mode (§3-2 violation) to investigate and revert, not as a baseline to casually
     * update. Updating only one of the two (e.g. adding a filename to {@link
     * #MASTER_MIGRATION_BASELINE} without adding its hash here) fails {@link
     * #migrationContentBaselineCoversEveryBaselineFile()}, since {@link
     * #migrationContentMatchesMasterBaseline()} only hashes files that already have an entry in
     * this map and would otherwise stay silently unchecked.
     */
    private static final Map<String, String> MASTER_MIGRATION_CONTENT_SHA256 = new LinkedHashMap<>();

    static {
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V1__init.sql", "984ede87065068877d3f7ec73c8d011171642d38e097236e4f7098a811e09d68");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V2__stage1_support.sql", "ab943d9cfaea0a65a3bd58d3c647c6bd2862455562894542b6166d9dc91a6991");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V3__ecosystem_registries.sql", "bd62191c6e214464c88f5df69287a6284368de97ebdb6c7ab0cbb5404b807097");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V4__identification_hint.sql", "b48077a76460ecf504d61e88253055591b9b659dca0c022a907c1902c1d60793");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V5__version_confirmed.sql", "573217955bad4862c088e83d2a30fa294014e3d4b58429db561512ed8e139de9");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V6__hint_investigation_fields.sql", "cc8eddb58b0a3cce3367609b92234fb4a7926bb5348bb303bed3ac1907ea7947");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V7__fixed_version.sql", "029f1c02491eef85ad5073cabc17171b94536e09c84469c23bb6d837afc1efdd");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V8__cve_org.sql", "8ed76db12cf0c8d01cb1c57f2561e03b1a5661bf6ac3d75f020d900f25ff2ef6");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V9__trgm_query_performance.sql", "27cfb51139eb0c451f5adae151a0c5f332a7e754a0692d3a4abdd6e41669a5cb");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V10__more_ecosystems.sql", "55f84f92c7495ec06ecb4e690a8bd0ef7303fcbebe5da403288649f06b4a2b2a");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V11__vulnerability_research_incomplete.sql",
                "de2165ca702a62ecd47ce9db6a4e58a87dd0f7e31daa2c0cc58bef03fc58bc99");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V12__research_incomplete_reason.sql", "85a184d00c306f9224a4e769597cc2791d2eca1b5c34b2a8168eb0e71d05932d");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V13__backfill_corrupted_cpe_vendor_product.sql",
                "c0de09f618a4660fb554802773daf9d267f0811f8c994c358b45e6610bd15b86");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V14__chocolatey_ecosystem.sql", "ee85a5e7566d3e2626df01058c048ea2e72ffc6e33de4fdd2b8777a46624895a");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V15__version_plausibility_warning.sql",
                "2318493eb246ac3fd751db95128a10cf1e1bb1c67450e762fbc2c30cb698b550");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V16__bundled_component_detection.sql",
                "d7ea9d55eb9931d780eabc36c42f155559d0e649629bfa5e69a3294c7289b531");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V17__csaf_vendor_advisories.sql", "f37f5fed12d3f80cc759baaa0b442016f71f0c3f15d86f22c67ed0ef7d4c6dab");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V18__csaf_product_status_unique.sql",
                "e4ca69297ccca27c37a0741af6d2df50a88d0513dedc4dc8ce11681bc445c51b");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V19__ghsa_advisories.sql", "9aca92c39d6548d04a983bbad39588dcae4b3dc904d210ab2d7d15103c29a0ef");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V20__csaf_redhat_support.sql", "81f8d0b25a0e74245d12a11a2d4084cb5e0ff30f7b09ff352eda4b84ba26f711");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V21__csaf_redhat_revise_fixes.sql", "16a7cfff7ae570dd47ba5d62f82d9784f85482ce3ec4eafbdcd35d1c14bff6c3");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V22__csaf_redhat_revise_followup.sql",
                "32ee435a05c934bc8ca3e425c584a5567b695d12e3f646dc2a05326ca061e6be");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V23__job_cost_ledger.sql", "4a45a3937508987108d817070fe26995bab5113cd352c8aef4eb67367d0f3d67");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V24__job_cost_ledger_item_index.sql",
                "2525f4ba786a2aba39aba1685fb4b9b68ff8218dbbbb71c06ae310b0e453cb94");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V25__osv_advisories.sql", "f4cde9d4a9f6b875dab6e3e4576cf542752149f9a6816a29c2c97c0e206e4c39");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V26__research_job_items_raw_product_name.sql",
                "04c3f638ace5fb206b2fe566a82c7f5e8db56408bb2482b10aea090267478a05");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V27__job_cost_ledger_breakdown.sql",
                "735cabd29e42e7d6a9556542d4c6ace418d4e630be2e2900a47f10c0e38d99bd");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V28__high_confidence_verification.sql",
                "9b981fcc50dea00226ec6e731119976fef86efe2ff5da6d3a120c22ffefa0e6e");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V29__verification_ledger.sql", "6867ca4c327aa1051239024cf455bad40b0afd569e7943dcd7664920b8f6783c");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V30__cpe_candidate_provenance.sql",
                "157c82627066f6790e5499af223e0bee3b35a81a933fdde9001e2bb5a165d07b");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V31__cpe_dictionary_vendor_product_index.sql",
                "caebe751e049dd7862b473a817ebb022437f048c2edfa927c7ca9eb3e6d8cd61");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V32__remove_chocolatey_ecosystem.sql",
                "b289d27c7bb06615dddc43c5b14cd584e8dd30a1e73c11db9eaa128a7b076f11");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V33__research_incomplete_reason_ai_gaps.sql",
                "50c0bb55164be06c4d17f7e858c9e9efe9ed010af68e629088437a28b973bad8");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V34__research_incomplete_reason_ai_call_failed.sql",
                "464f920799b68292423bd54aefb49476676e00940f66bce103b37173fadb807e");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V35__users_email_lower_unique_index.sql",
                "433d74aec28aef7d94828604518e141309735e6f6e56ee149f5d4d17b346da67");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V36__normalize_users_email_lowercase.sql",
                "f663ce2f6febb9f7ed02e1fe6335965ea6863955cb83e6353cfba2519089e51b");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V37__registry_package_mirror.sql",
                "fd075f977f6439f12910119b4a8eee2d69a6020fe7927ee4596301554e16a703");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V38__registry_mirror_seed_name.sql",
                "a31d70a275e6556c73e77b7747eb914d619ec9f6e0f36bbba7fbf924c0695736");
        // Closed-mode backlog item 264 (B4, 2026-09-04): refreshed together with
        // MASTER_MIGRATION_BASELINE in the same commit as the master-sync merge that brought
        // V39-V41 in (item 251's NVD CVE mirror + CSV export/pagination fixes), per this map's own
        // maintenance discipline above.
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V39__nvd_cve_mirror.sql",
                "5ce742070aa8e46a7e6e7c5676ede24222af53f85f963a897bd10dd3ddc06d17");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V40__vulnerabilities_cvss_score_and_max_fixed_version.sql",
                "d48f9e027c31c9e8f84aed553b14482b71198b38748a10caec9c660269a0ca19");
        MASTER_MIGRATION_CONTENT_SHA256.put(
                "V41__backfill_max_fixed_version.sql",
                "df81fc55149557542c9f903f33def2ee8d24dc917ddcf25da4b45d667ad34699");
    }

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

    /**
     * Item 205 REVISE (PR#151): {@link #migrationContentMatchesMasterBaseline()} iterates {@link
     * #MASTER_MIGRATION_CONTENT_SHA256}'s entries, not {@link #MASTER_MIGRATION_BASELINE}'s — so a
     * file present in the filename baseline but missing from the hash map is simply never hashed,
     * and both tests stay green while that file's content verification is silently disabled. This
     * asserts the two baselines name exactly the same files, so a future master-sync (§9-3) that
     * updates {@link #MASTER_MIGRATION_BASELINE} but forgets {@link
     * #MASTER_MIGRATION_CONTENT_SHA256} fails loudly here instead of leaving a permanent, invisible
     * gap in content-drift detection.
     */
    @Test
    void migrationContentBaselineCoversEveryBaselineFile() {
        assertThat(MASTER_MIGRATION_CONTENT_SHA256.keySet())
                .as("MASTER_MIGRATION_CONTENT_SHA256 must hold exactly one hash entry per file in "
                        + "MASTER_MIGRATION_BASELINE — migrationContentMatchesMasterBaseline() iterates "
                        + "the hash map, so a file added to the filename baseline during a master-sync "
                        + "refresh (§9-3) but not to the hash map would silently go un-hashed forever "
                        + "instead of failing")
                .isEqualTo(MASTER_MIGRATION_BASELINE);
    }

    /**
     * Item 205: {@link #migrationSetMatchesMasterBaseline()} above only detects filename drift
     * (a {@code V*__} file added or removed). This detects the complementary case — an existing
     * {@code V*__} file whose filename is unchanged but whose SQL body was edited — by comparing
     * each file's SHA-256 against {@link #MASTER_MIGRATION_CONTENT_SHA256}. Only files present in
     * both the baseline and the actual directory are hashed here; a missing/extra filename is
     * already reported (with a more specific message) by {@link #migrationSetMatchesMasterBaseline()},
     * so this test doesn't re-report that case as a spurious "no baseline hash for this file" or
     * "file present in baseline but absent on disk" failure.
     */
    @Test
    void migrationContentMatchesMasterBaseline() throws IOException {
        Path migrationDir = Path.of("src/main/resources/db/migration");
        assertThat(Files.isDirectory(migrationDir))
                .as("expected %s to exist relative to the backend module root", migrationDir)
                .isTrue();

        List<String> mismatches = new ArrayList<>();
        for (Map.Entry<String, String> baselineEntry : MASTER_MIGRATION_CONTENT_SHA256.entrySet()) {
            String fileName = baselineEntry.getKey();
            Path file = migrationDir.resolve(fileName);
            if (!Files.exists(file)) {
                // A missing baseline file is migrationSetMatchesMasterBaseline()'s invariant, not
                // this one — skip it here rather than duplicate that failure less specifically.
                continue;
            }
            String expectedSha256 = baselineEntry.getValue();
            String actualSha256 = sha256Hex(file);
            if (!expectedSha256.equals(actualSha256)) {
                mismatches.add(fileName + " (expected sha256 " + expectedSha256 + ", actual "
                        + actualSha256 + ")");
            }
        }

        assertThat(mismatches)
                .as("these already-applied V*__ migration files have content that no longer "
                        + "matches the master baseline (§3-2's \"byte-for-byte identical to master\" "
                        + "Flyway invariant) — this is exactly the kind of drift that stays invisible "
                        + "until Flyway's checksum validation fails at startup against an environment "
                        + "that already ran the original content, so it must be caught here instead. "
                        + "Refresh MASTER_MIGRATION_CONTENT_SHA256 only if this is a legitimate "
                        + "master-sync merge (§9-3); otherwise revert the content edit")
                .isEmpty();
    }

    // ------------------------------------------------------------------------------------------
    // Closed-mode-only migrations (item 261, found during PR#200/item 262's senior-reviewer
    // review, 2026-09-04): the three tests above only ever look at files matching VERSIONED_MIGRATION
    // (V\d+__*.sql, i.e. files also on master) — a file that ISN'T on master at all, like
    // R__closed_mode_strip.sql (item 262/B6, the one migration that only exists on closed-mode),
    // was invisible to both the filename-set gate and the content-hash gate. That is exactly the
    // blind spot item 205 closed for V*__ files, left open here — and worse for a repeatable
    // migration specifically: Flyway re-runs an R__ file automatically the moment its checksum
    // changes, so an unnoticed edit here doesn't just risk a startup FlywayValidateException
    // (V*__ files' failure mode) -- it risks silently *re-executing* a DELETE against
    // secret-bearing/data tables with different SQL than what was reviewed. The three tests below
    // mirror the V*__ trio above, scoped to the complementary file set (anything under
    // db/migration that ISN'T a V\d+__ file).
    // ------------------------------------------------------------------------------------------

    /**
     * Every {@code closed-mode}-only migration file (i.e. present on this branch but never on
     * {@code master} — R__ repeatable migrations, or any future U__ undo migration) that is
     * expected to exist under {@code db/migration}. Currently just {@code R__closed_mode_strip.sql}
     * (item 262/B6). A future addition here must be a deliberate, reviewed closed-mode-only
     * migration, not a stray file — see {@link #closedModeOnlyMigrationSetMatchesBaseline()}.
     */
    private static final Set<String> CLOSED_MODE_ONLY_MIGRATION_BASELINE =
            Set.of("R__closed_mode_strip.sql");

    /**
     * SHA-256 (hex-encoded) of every file in {@link #CLOSED_MODE_ONLY_MIGRATION_BASELINE}. Same
     * purpose as {@link #MASTER_MIGRATION_CONTENT_SHA256}, but for files that were never on master
     * to begin with, so there is no "master baseline" to diff against — the reference point here is
     * simply "the content this was last reviewed/approved with".
     *
     * <p><b>Maintenance</b>: unlike {@link #MASTER_MIGRATION_CONTENT_SHA256} (refreshed only on a
     * master-sync merge), this hash is refreshed whenever {@code R__closed_mode_strip.sql}'s own
     * content is deliberately, reviewably changed on closed-mode itself (there is no upstream to
     * sync from) — e.g. adding a third DELETE statement for a newly-identified closed-mode-only
     * table. If this fails without such a change, treat it as unreviewed drift to investigate and
     * revert, not as a baseline to casually update.
     */
    private static final Map<String, String> CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256 = new LinkedHashMap<>();

    static {
        CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256.put("R__closed_mode_strip.sql",
                "6a47fd3883917a827e26c2e5f65ea6274cea36d6c064b834636c326fe62dbb03");
    }

    @Test
    void closedModeOnlyMigrationSetMatchesBaseline() throws IOException {
        Path migrationDir = Path.of("src/main/resources/db/migration");
        assertThat(Files.isDirectory(migrationDir))
                .as("expected %s to exist relative to the backend module root", migrationDir)
                .isTrue();

        try (Stream<Path> files = Files.list(migrationDir)) {
            Set<String> actualClosedModeOnlyFiles = files
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.endsWith(".sql") && !VERSIONED_MIGRATION.matcher(name).matches())
                    .collect(Collectors.toSet());

            Set<String> unexpected = actualClosedModeOnlyFiles.stream()
                    .filter(name -> !CLOSED_MODE_ONLY_MIGRATION_BASELINE.contains(name))
                    .collect(Collectors.toSet());
            Set<String> missing = CLOSED_MODE_ONLY_MIGRATION_BASELINE.stream()
                    .filter(name -> !actualClosedModeOnlyFiles.contains(name))
                    .collect(Collectors.toSet());

            assertThat(actualClosedModeOnlyFiles)
                    .as("db/migration's non-V*__ .sql file set must match "
                            + "CLOSED_MODE_ONLY_MIGRATION_BASELINE exactly (extra: %s | missing: %s) — "
                            + "every closed-mode-only migration must be a deliberate, reviewed addition "
                            + "recorded in this baseline, not a silent extra file", unexpected, missing)
                    .isEqualTo(CLOSED_MODE_ONLY_MIGRATION_BASELINE);
        }
    }

    /** Same self-consistency check as {@link #migrationContentBaselineCoversEveryBaselineFile()},
     *  for the closed-mode-only baseline: a file added to {@link #CLOSED_MODE_ONLY_MIGRATION_BASELINE}
     *  without a matching hash entry would otherwise go silently un-hashed by {@link
     *  #closedModeOnlyMigrationContentMatchesBaseline()}. */
    @Test
    void closedModeOnlyMigrationContentBaselineCoversEveryBaselineFile() {
        assertThat(CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256.keySet())
                .as("CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256 must hold exactly one hash entry per "
                        + "file in CLOSED_MODE_ONLY_MIGRATION_BASELINE")
                .isEqualTo(CLOSED_MODE_ONLY_MIGRATION_BASELINE);
    }

    /**
     * Content-drift detection for closed-mode-only migrations — the repeatable-migration analogue
     * of {@link #migrationContentMatchesMasterBaseline()}. Deliberately not folded into that same
     * test/loop: mixing "diverged from master, investigate" (V*__) and "diverged from its own last
     * reviewed content, investigate" (R__, no master to diff against) into one assertion message
     * would blur two different failure meanings.
     */
    @Test
    void closedModeOnlyMigrationContentMatchesBaseline() throws IOException {
        Path migrationDir = Path.of("src/main/resources/db/migration");
        assertThat(Files.isDirectory(migrationDir))
                .as("expected %s to exist relative to the backend module root", migrationDir)
                .isTrue();

        List<String> mismatches = new ArrayList<>();
        for (Map.Entry<String, String> baselineEntry : CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256.entrySet()) {
            String fileName = baselineEntry.getKey();
            Path file = migrationDir.resolve(fileName);
            if (!Files.exists(file)) {
                // A missing baseline file is closedModeOnlyMigrationSetMatchesBaseline()'s
                // invariant, not this one.
                continue;
            }
            String expectedSha256 = baselineEntry.getValue();
            String actualSha256 = sha256Hex(file);
            if (!expectedSha256.equals(actualSha256)) {
                mismatches.add(fileName + " (expected sha256 " + expectedSha256 + ", actual "
                        + actualSha256 + ")");
            }
        }

        assertThat(mismatches)
                .as("these closed-mode-only migration files have content that no longer matches "
                        + "the last-reviewed baseline — for a repeatable (R__) migration this is "
                        + "especially dangerous: Flyway re-runs it automatically the moment its "
                        + "checksum changes, so an unreviewed edit here doesn't just risk a startup "
                        + "validation failure, it risks silently re-executing an unreviewed DELETE "
                        + "against secret-bearing/data tables. Refresh "
                        + "CLOSED_MODE_ONLY_MIGRATION_CONTENT_SHA256 only if this is a deliberate, "
                        + "reviewed content change; otherwise revert it")
                .isEmpty();
    }

    /**
     * Self-test for {@link #migrationContentMatchesMasterBaseline()}'s detection mechanism (item
     * 205): proves {@link #sha256Hex(Path)} actually changes when a migration file's content is
     * mutated, using a tampered copy in a throwaway {@code @TempDir} rather than touching a real
     * {@code V*__} file — mutating a real migration file, even temporarily inside a test, is
     * exactly the kind of drift §3-2 exists to prevent and would be a strange thing for a
     * permanent, always-green test to do on every run.
     */
    @Test
    void sha256HexDetectsContentDrift(@TempDir Path tempDir) throws IOException {
        Map.Entry<String, String> sample = MASTER_MIGRATION_CONTENT_SHA256.entrySet().iterator().next();
        Path realFile = Path.of("src/main/resources/db/migration").resolve(sample.getKey());

        // Sanity check first: today's real file content must actually match the recorded
        // baseline (this is also covered by migrationContentMatchesMasterBaseline(), but
        // asserting it here too means a failure of *this* test always points at sha256Hex()
        // itself or the tampering below, never at an unrelated baseline-vs-disk mismatch).
        assertThat(sha256Hex(realFile)).isEqualTo(sample.getValue());

        byte[] originalBytes = Files.readAllBytes(realFile);
        byte[] tamperedBytes = Arrays.copyOf(originalBytes, originalBytes.length + 1);
        tamperedBytes[originalBytes.length] = (byte) '\n'; // append a trailing byte
        Path tamperedCopy = tempDir.resolve(sample.getKey());
        Files.write(tamperedCopy, tamperedBytes);

        assertThat(sha256Hex(tamperedCopy))
                .as("appending a single byte to %s's content must change its SHA-256 — this is "
                        + "the exact mechanism migrationContentMatchesMasterBaseline() relies on to "
                        + "catch checksum drift (item 205)", sample.getKey())
                .isNotEqualTo(sample.getValue());
    }

    private static String sha256Hex(Path file) throws IOException {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(Files.readAllBytes(file));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a mandatory JDK algorithm (JCA standard names) — this cannot happen in
            // practice, but MessageDigest.getInstance declares it as checked.
            throw new AssertionError("SHA-256 MessageDigest not available", e);
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
