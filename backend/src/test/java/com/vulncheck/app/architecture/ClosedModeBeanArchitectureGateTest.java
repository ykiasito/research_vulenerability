package com.vulncheck.app.architecture;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.service.registry.PackageRegistryLookup;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

/**
 * Closed-mode backlog item 196 (B7, {@code docs/spec/closed-mode-plan.md} §3-6) — the two checks
 * (items 2 and 4) that genuinely need a real {@link ApplicationContext} rather than plain
 * reflection over a known class, since what's actually asserted is "Spring's own DI wiring", not
 * just "does this method/class exist somewhere on the classpath" (that half is covered by {@link
 * ClosedModeArchitectureGateTest}). Needs {@code --network research_vulenerability_default} when
 * run via the {@code docker run} command in {@code CLAUDE.md} (this app's {@code
 * @SpringBootTest} contexts validate their Flyway schema against a running {@code vulncheck_test}
 * postgres on startup) — same requirement as every other {@code @SpringBootTest} in this module,
 * not something new this test suite introduces.
 */
@SpringBootTest
class ClosedModeBeanArchitectureGateTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private List<PackageRegistryLookup> registryLookups;

    /**
     * Types that give a class the physical ability to make an outbound HTTP(S)/network call.
     * Checked against every injected {@link PackageRegistryLookup} implementation's declared
     * field types and constructor parameter types (see {@link
     * #registryLookupListIsFullyPopulatedAndMirrorOnly()}) — this is the primary defense for
     * §3-6 item 4, not the {@code lookupLive}-method-name check below. A method-name check only
     * catches a live lookup path that kept that exact name; it says nothing about a future
     * {@code master} merge (§9-3) adding a differently-named live lookup to a class this suite
     * doesn't otherwise touch. Testing for the underlying egress *capability* — "does this class
     * even hold a reference to something that can talk to the network" — closes that gap.
     */
    private static final Set<String> EGRESS_CAPABLE_TYPES = Set.of(
            "org.springframework.web.client.RestClient",
            "org.springframework.web.client.RestTemplate",
            "org.springframework.web.reactive.function.client.WebClient",
            "java.net.http.HttpClient",
            "java.net.URL",
            "java.net.URLConnection");

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
            "externalApiRestClient is still legitimately wired today (docs/spec/closed-mode-plan.md "
                    + "§3-4): NvdVulnerabilitySource and OsvLiveQueryClient — both B4 work, not yet started "
                    + "as of item 196 — inject it for their live HTTP calls. §3-4 calls for deleting this "
                    + "Bean outright (not just its callers) once B4 removes those two classes, turning any "
                    + "future re-introduction of a live-egress caller into a startup-time "
                    + "NoSuchBeanDefinitionException rather than a silent no-op. Re-enable this test as "
                    + "part of B4.")
    void externalApiRestClientBeanDoesNotExist() {
        assertThat(applicationContext.containsBean("externalApiRestClient")).isFalse();
    }

    // ------------------------------------------------------------------------------------------
    // §3-6 item 4: List<PackageRegistryLookup> DI must be all-mirror (no lookupLive method).
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

        List<String> egressCapableFindings = registryLookups.stream()
                .map(AopUtils::getTargetClass)
                .flatMap(clazz -> findEgressCapableMembers(clazz).stream())
                .collect(Collectors.toList());

        assertThat(egressCapableFindings)
                .as("these PackageRegistryLookup beans hold a field or constructor argument typed as "
                        + "one of %s — B3 (item 193) was supposed to remove the *capability* to make a "
                        + "live HTTP call from every registry client, not just rename or hide the method "
                        + "that used it", EGRESS_CAPABLE_TYPES)
                .isEmpty();
    }

    /**
     * Scans {@code clazz}'s own declared fields and every declared constructor's parameter types
     * for anything in {@link #EGRESS_CAPABLE_TYPES}, returning one human-readable description per
     * hit (class + field/parameter name + offending type) so a failure names exactly what to
     * remove.
     */
    private static List<String> findEgressCapableMembers(Class<?> clazz) {
        List<String> findings = new ArrayList<>();
        for (Field field : clazz.getDeclaredFields()) {
            if (EGRESS_CAPABLE_TYPES.contains(field.getType().getName())) {
                findings.add(clazz.getName() + "#" + field.getName() + " (field type "
                        + field.getType().getName() + ")");
            }
        }
        for (Constructor<?> constructor : clazz.getDeclaredConstructors()) {
            Class<?>[] parameterTypes = constructor.getParameterTypes();
            for (int i = 0; i < parameterTypes.length; i++) {
                if (EGRESS_CAPABLE_TYPES.contains(parameterTypes[i].getName())) {
                    findings.add(clazz.getName() + " constructor parameter #" + i + " (type "
                            + parameterTypes[i].getName() + ")");
                }
            }
        }
        return findings;
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
