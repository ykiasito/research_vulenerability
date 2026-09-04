package com.vulncheck.app.architecture;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.service.registry.PackageRegistryLookup;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.core.io.ClassPathResource;

/**
 * Closed-mode backlog item 262 (Phase B6, senior-reviewer REVISE, second round): {@code
 * guide-integrations.html}'s "1. パッケージレジストリ（自動照合対応）" table asserts which
 * ecosystems this deployment can actually auto-match against a local mirror — the first round of
 * this REVISE fixed the table itself listing {@code maven} despite {@code
 * MavenCentralRegistryClient#lookup} being a permanent no-op on this branch ({@code
 * docs/spec/closed-mode-plan.md} §5-4, no closed-mode Maven Central mirror exists). This test pins
 * the invariant that broke: every registered {@link PackageRegistryLookup} bean must be accounted
 * for by the guide page, either listed in the table (works) or named in {@link
 * #KNOWN_MIRRORLESS_ECOSYSTEMS} below (documented exception, currently just {@code maven}) — so
 * the next registry client addition/removal/no-op-ing fails this test unless the guide page is
 * updated in the same change, rather than silently drifting out of sync the way the table did here.
 *
 * <p>{@code webEnvironment = WebEnvironment.RANDOM_PORT} matches {@code
 * ClosedModeBeanArchitectureGateTest}'s own {@code @SpringBootTest} shape, reusing the same cached
 * application context (and its {@code List<PackageRegistryLookup>} DI) rather than starting a
 * second one from scratch. Deliberately its own new file, not added to {@code
 * ClosedModeArchitectureGateTest} — item 261/B7 is editing that file concurrently on a sibling PR,
 * and this needs {@code List<PackageRegistryLookup>} injection anyway (that class is a
 * classpath-only, no-Spring-context suite by design).
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class GuideIntegrationsEcosystemListTest {

    /**
     * Registry ecosystems with a real {@link PackageRegistryLookup} bean that the guide page's
     * table deliberately does NOT list, because the lookup itself is a permanent no-op on this
     * branch. Currently just Maven Central ({@code docs/spec/closed-mode-plan.md} §5-4: unlike the
     * other 9 registries, Maven Central never got a closed-mode mirror, so {@code
     * MavenCentralRegistryClient#lookup} always returns empty) — {@code guide-integrations.html}
     * lists it under "3. 自動照合できない配布チャネル" instead.
     */
    private static final Set<String> KNOWN_MIRRORLESS_ECOSYSTEMS = Set.of("maven");

    /** Bounds extraction to the "1. パッケージレジストリ" section only, up to the next {@code
     *  <h2>} heading -- the "2. 脆弱性データソース" table below it uses the exact same {@code
     *  <tr><td>...</td><td>} row shape, so an unbounded search would wrongly pick up NVD/OSV.dev/
     *  GHSA as if they were registry ecosystems too. {@code DOTALL} since the section spans
     *  multiple lines. */
    private static final Pattern REGISTRY_SECTION =
            Pattern.compile("<h2>1\\. パッケージレジストリ.*?(?=<h2>)", Pattern.DOTALL);

    private static final Pattern REGISTRY_TABLE_ROW = Pattern.compile("<tr><td>([^<]+)</td><td>");

    @Autowired
    private List<PackageRegistryLookup> registryLookups;

    @Test
    void everyListedEcosystemHasARealRegistryLookupBean() {
        Set<String> registeredEcosystems = registryLookups.stream()
                .map(PackageRegistryLookup::ecosystem)
                .collect(Collectors.toSet());

        List<String> ghostRows = extractGuidePageEcosystems().stream()
                .filter(ecosystem -> !registeredEcosystems.contains(ecosystem))
                .collect(Collectors.toList());

        assertThat(ghostRows)
                .as("guide-integrations.html's registry table lists an ecosystem with no matching "
                        + "PackageRegistryLookup bean — this must be a mistake (a typo, or a registry "
                        + "client that was removed without updating the guide page)")
                .isEmpty();
    }

    @Test
    void everyRegistryLookupBeanIsEitherListedOrADocumentedMirrorlessException() {
        Set<String> listedEcosystems = extractGuidePageEcosystems();

        List<String> unaccountedFor = registryLookups.stream()
                .map(PackageRegistryLookup::ecosystem)
                .filter(ecosystem -> !listedEcosystems.contains(ecosystem))
                .filter(ecosystem -> !KNOWN_MIRRORLESS_ECOSYSTEMS.contains(ecosystem))
                .collect(Collectors.toList());

        assertThat(unaccountedFor)
                .as("these PackageRegistryLookup beans are neither listed in guide-integrations.html's "
                        + "table nor in this test's own KNOWN_MIRRORLESS_ECOSYSTEMS exception set -- a "
                        + "registry client was added (or an existing one's mirror was removed) without "
                        + "updating the guide page in the same change")
                .isEmpty();
    }

    @Test
    void everyDocumentedMirrorlessExceptionIsAnActualRegisteredEcosystemNotListedInTheTable() {
        // Guards KNOWN_MIRRORLESS_ECOSYSTEMS itself against going stale in the other direction --
        // an entry that no longer corresponds to a real bean (the client was deleted outright) or
        // that the guide page now DOES list (contradicting its own "mirrorless" claim) would mean
        // this test's exception set is no longer accurate either.
        Set<String> registeredEcosystems = registryLookups.stream()
                .map(PackageRegistryLookup::ecosystem)
                .collect(Collectors.toSet());
        Set<String> listedEcosystems = extractGuidePageEcosystems();

        for (String ecosystem : KNOWN_MIRRORLESS_ECOSYSTEMS) {
            assertThat(registeredEcosystems)
                    .as("KNOWN_MIRRORLESS_ECOSYSTEMS contains '%s', but no PackageRegistryLookup bean "
                            + "reports that ecosystem -- update this test's exception set", ecosystem)
                    .contains(ecosystem);
            assertThat(listedEcosystems)
                    .as("KNOWN_MIRRORLESS_ECOSYSTEMS contains '%s', but the guide page's table also "
                            + "lists it -- it can't be both a working mirror and a documented exception",
                            ecosystem)
                    .doesNotContain(ecosystem);
        }
    }

    /** Extracts the ecosystem key (first {@code <td>}) from every row of {@code
     *  guide-integrations.html}'s "1. パッケージレジストリ" table -- a plain regex over the raw
     *  template text rather than a full HTML parser, matching the template's own single-line-per-row
     *  formatting ({@code <tr><td>ecosystem</td><td>display name</td></tr>}, no extra whitespace). */
    private Set<String> extractGuidePageEcosystems() {
        String html;
        try {
            html = new ClassPathResource("templates/guide-integrations.html").getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to read templates/guide-integrations.html off the classpath", e);
        }

        Matcher sectionMatcher = REGISTRY_SECTION.matcher(html);
        assertThat(sectionMatcher.find())
                .as("sanity check: could not locate the '1. パッケージレジストリ' section (up to the "
                        + "next <h2>) in guide-integrations.html -- the heading text or section "
                        + "structure changed and this test's own REGISTRY_SECTION pattern needs "
                        + "updating")
                .isTrue();
        String registrySection = sectionMatcher.group();

        Set<String> ecosystems = new java.util.LinkedHashSet<>();
        Matcher matcher = REGISTRY_TABLE_ROW.matcher(registrySection);
        while (matcher.find()) {
            ecosystems.add(matcher.group(1));
        }
        assertThat(ecosystems)
                .as("sanity check: the regex above must have matched at least one row -- an empty "
                        + "result almost certainly means guide-integrations.html's table markup shape "
                        + "changed and this test's own extraction regex needs updating, not that the "
                        + "table is genuinely empty")
                .isNotEmpty();
        return ecosystems;
    }
}
