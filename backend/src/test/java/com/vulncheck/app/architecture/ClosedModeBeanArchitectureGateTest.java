package com.vulncheck.app.architecture;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.service.registry.PackageRegistryLookup;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.ApplicationContext;

/**
 * Closed-mode backlog item 196 (B7, {@code docs/spec/closed-mode-plan.md} §3-6) — the two checks
 * (items 2 and 4) that genuinely need a real {@link ApplicationContext} rather than plain
 * reflection over a known class, since what's actually asserted is "Spring's own DI wiring", not
 * just "does this method/class exist somewhere on the classpath" (that half is covered by {@link
 * ClosedModeArchitectureGateTest}). Must run on a network that can reach a running {@code
 * vulncheck_test} postgres (this app's {@code @SpringBootTest} contexts validate their Flyway
 * schema against it on startup) — same requirement as every other {@code @SpringBootTest} in this
 * module (e.g. {@code SessionCookieSecureDefaultTest}/{@code SessionCookieSecureEnabledTest}), not
 * something new this test suite introduces.
 *
 * <p>{@code webEnvironment = WebEnvironment.RANDOM_PORT} matches the only other {@code
 * @SpringBootTest}s actually run in this module ({@code SessionCookieSecureDefaultTest}/{@code
 * SessionCookieSecureEnabledTest}), so this suite reuses Spring's cached application context
 * (Flyway validation and all) instead of starting a second full context from scratch.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class ClosedModeBeanArchitectureGateTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private List<PackageRegistryLookup> registryLookups;

    // ------------------------------------------------------------------------------------------
    // §3-6 item 2: Spring context must not define externalApiRestClient / llmServiceRestClient.
    // ------------------------------------------------------------------------------------------

    @Test
    void llmServiceRestClientBeanDoesNotExist() {
        assertThat(applicationContext.containsBean("llmServiceRestClient"))
                .as("llmServiceRestClient must not be a bean (B1, item 177) — RestClientConfig must "
                        + "not define it and app.llm-service-url must not be referenced anywhere")
                .isFalse();
    }

    @Test
    @Disabled(
            "The Bean definition itself (docs/spec/closed-mode-plan.md §3-4) is still left in "
                    + "RestClientConfig -- deleting it is item 263's own scope, not this task's. As of "
                    + "closed-mode backlog item 273 (2026-09-04), production code has ZERO remaining "
                    + "injectors: NvdVulnerabilitySource's own live NVD CVE call (fetchFromNvd) was "
                    + "already deleted in item 264/B4, and this test's own @Disabled reason previously "
                    + "(incorrectly) named that as the last one -- the actual last production injector "
                    + "was NvdCpeSyncService (its single-page live keyword-search fallback, "
                    + "syncKeywordSinglePage, used by Stage1IdentificationService's live CPE lookup), "
                    + "removed by item 273. The only remaining reference anywhere in this codebase is a "
                    + "test-scope @Autowired field in NvdMirrorAbVerificationRunner (a disabled, "
                    + "*Runner-named diagnostic harness never exercised by `mvn test`; deliberately kept "
                    + "rather than deleted, since its own companion NvdMirrorAbVerificationRunnerTest "
                    + "depends on a pure-logic method it hosts -- see item 273's own PR description). "
                    + "Re-enable this test as part of item 263, once RestClientConfig#externalApiRestClient "
                    + "itself is actually deleted (turning any future re-introduction of a live-egress "
                    + "caller into a startup-time NoSuchBeanDefinitionException rather than a silent "
                    + "no-op).")
    void externalApiRestClientBeanDoesNotExist() {
        assertThat(applicationContext.containsBean("externalApiRestClient")).isFalse();
    }

    // ------------------------------------------------------------------------------------------
    // §3-6 item 4: List<PackageRegistryLookup> DI must be all-mirror (no lookupLive method).
    //
    // Note on the gap between this test and §3-6's original wording: the plan document's item 4
    // literally reads "the injection result is empty" — i.e. it was written expecting B3 to
    // delete the 10 *RegistryClient classes outright, the same way B1 deletes LlmServiceClient.
    // B3 (item 193) instead chose to keep the classes and gut only their live HTTP lookup path,
    // turning them into mirror-only PackageRegistryLookup implementations (§3-8) — a decision
    // made after the original §3-6 text was written, once Phase D's registry mirror (§5) became
    // available as a same-quality replacement for the live path. That is a deliberate, documented
    // divergence from the literal plan text, not a bug in either the plan or this test. The
    // resulting stronger invariant, and what this test (plus
    // ClosedModeArchitectureGateTest#EGRESS_CAPABLE_TYPES, reused below) actually enforces
    // post-B3, is: all 10 clients are present AND none of them has the physical capability to
    // make a live network call.
    //
    // 2026-09-02 (REVISE R8/R9): the egress-capable-type set and the field/constructor scan now
    // live in ClosedModeArchitectureGateTest (duplicated there as its own classpath-only @Test,
    // see that class), and this test reuses that single implementation rather than keeping its
    // own copy — so an EGRESS_CAPABLE_TYPES fix (e.g. R9's RestClient.Builder/HttpURLConnection/
    // Socket additions) only needs to happen in one place. This test's own DI-based traversal
    // (registryLookups, from Spring) is unchanged and stays here — see the class javadoc for why.
    // ------------------------------------------------------------------------------------------

    @Test
    void registryLookupListIsFullyPopulatedAndMirrorOnly() {
        assertThat(registryLookups)
                .as("List<PackageRegistryLookup> should have exactly the 10 Stage1 Tier1 registry "
                        + "clients wired in (§3-8) — an empty or short list would mean Stage1 silently "
                        + "lost registry coverage, not just its live-HTTP fallback")
                .hasSize(10);

        List<String> stillHavingLookupLive = registryLookups.stream()
                .map(AopUtils::getTargetClass)
                .filter(clazz -> hasMethodNamed(clazz, "lookupLive"))
                .map(Class::getName)
                .collect(Collectors.toList());

        assertThat(stillHavingLookupLive)
                .as("these PackageRegistryLookup beans still have a lookupLive method — B3 (item 193) "
                        + "was supposed to remove the live HTTP path from every registry client outright")
                .isEmpty();

        // Reuses ClosedModeArchitectureGateTest's EGRESS_CAPABLE_TYPES set and
        // findEgressCapableMembers scan (package-visible, same package) rather than keeping a
        // second copy here — see the note above this test method.
        List<String> egressCapableFindings = registryLookups.stream()
                .map(AopUtils::getTargetClass)
                .flatMap(clazz -> ClosedModeArchitectureGateTest.findEgressCapableMembers(clazz).stream())
                .collect(Collectors.toList());

        assertThat(egressCapableFindings)
                .as("these PackageRegistryLookup beans hold a field or constructor argument typed as "
                        + "one of (or a subtype of) %s — B3 (item 193) was supposed to remove the "
                        + "*capability* to make a live HTTP call from every registry client, not just "
                        + "rename or hide the method that used it",
                        ClosedModeArchitectureGateTest.EGRESS_CAPABLE_TYPES)
                .isEmpty();
    }

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
}
