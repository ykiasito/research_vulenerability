package com.vulncheck.app.service.registry;

import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Narrows Stage1's registry fan-out to the registries whose own naming rules could actually admit
 * the name being looked up, before any request is issued.
 *
 * <p>Motivation is rate limits as much as speed. Every one of these registries is a free public
 * service with a published (crates.io: 1 req/s) or enforced-but-unpublished (Maven Central) limit,
 * so a request is a scarce resource — and the previous behaviour spent ten of them per item to get
 * at most one useful answer. Measured across jobs 30-33 (2026-08-25): of 1,429 items, 89 have a
 * space in the product name and matched <em>zero</em> registries — necessarily, since none of the
 * ten permits whitespace in a package name — yet each still cost ten requests.
 *
 * <p>The rules below are deliberately drawn from each registry's own identifier grammar rather
 * than from guesses about what a name "looks like", so a skip here means the request provably
 * could not have matched:
 *
 * <ul>
 *   <li><b>Whitespace</b> — no registry here permits a whitespace-containing package name, so this
 *       is a full skip (asks nothing at all) rather than a narrowing — a name with a space is a
 *       CPE-only case.</li>
 *   <li><b>{@code @scope/name}</b> — npm's scoped-package syntax, which no other registry here
 *       uses.</li>
 *   <li><b>{@code host.tld/path}</b> — a Go module path ({@code github.com/go-redis/redis},
 *       {@code gopkg.in/yaml.v2}). The dot before the first slash is what separates this from
 *       Composer's {@code vendor/package}.</li>
 *   <li><b>{@code vendor/package}</b> (one slash, no dot ahead of it) — Composer/Packagist.</li>
 *   <li><b>{@code /package}</b> (a slash with nothing — an empty vendor segment — ahead of it) —
 *       not a legal Composer identifier (vendor is required) and not a legal Go module path
 *       either (no {@code host.tld} prefix), so this is routed to nothing at all rather than
 *       falling through to "ask everyone".</li>
 *   <li><b>{@code groupId:artifactId}</b> — Maven coordinates; the colon is not legal in any of
 *       the other nine.</li>
 * </ul>
 *
 * <p>The four rules above are checked <em>before</em> the whitespace rule: each of them is some
 * other registry's own unambiguous identifier grammar, so a match (e.g. a Maven coordinate typed
 * with spaces around the colon, or a Go module path whose final segment contains a space) must
 * still route to that real ecosystem rather than being discarded outright just because the name
 * also happens to contain whitespace.
 *
 * <p>Anything else — a bare name like "lodash" or "redis" — stays genuinely ambiguous and is still
 * asked of every registry, because it legitimately could be any of them. That ambiguity is real,
 * not a gap in this policy, and is handled downstream where the collision is arbitrated.
 */
@Component
public class RegistryRoutingPolicy {

    private static final Pattern WHITESPACE = Pattern.compile("\\s");
    private static final Pattern NPM_SCOPED = Pattern.compile("^@[^/]+/[^/]+$");
    private static final Pattern GO_MODULE_PATH = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9.\\-]*\\.[A-Za-z]{2,}/.+");
    private static final Pattern VENDOR_SLASH_PACKAGE = Pattern.compile("^[^/\\s.]+/[^/\\s]+$");
    private static final Pattern EMPTY_VENDOR_SLASH_PACKAGE = Pattern.compile("^/[^/\\s]+$");

    /**
     * @return the subset of {@code allLookups} worth querying for this name — possibly empty, which
     *         means "no package registry can hold this name" and is a result, not a failure.
     */
    public List<PackageRegistryLookup> route(String productName, List<PackageRegistryLookup> allLookups) {
        if (productName == null || productName.isBlank()) {
            return List.of();
        }
        String name = productName.trim();

        // Checked ahead of the whitespace rule below — see class javadoc for why: each of these
        // four shapes is some other registry's own unambiguous grammar, so a match must still
        // route to that real ecosystem regardless of whether the name also contains whitespace.
        if (NPM_SCOPED.matcher(name).matches()) {
            return only(allLookups, "npm");
        }
        if (GO_MODULE_PATH.matcher(name).matches()) {
            return only(allLookups, "go");
        }
        if (EMPTY_VENDOR_SLASH_PACKAGE.matcher(name).matches()) {
            // A slash-package shape with an empty vendor segment: not a legal Composer identifier
            // (vendor is required) and not a legal Go module path either (no host.tld/ prefix) — no
            // current registry's grammar admits this, so there is nothing left worth asking.
            return List.of();
        }
        if (VENDOR_SLASH_PACKAGE.matcher(name).matches()) {
            return only(allLookups, "packagist");
        }
        if (name.indexOf(':') >= 0) {
            return only(allLookups, "maven");
        }
        if (WHITESPACE.matcher(name).find()) {
            // No registry here permits a whitespace-containing package name (see class javadoc) —
            // a provable "ask nothing" rather than falling through to "ask everyone".
            return List.of();
        }
        return allLookups;
    }

    /**
     * @return {@code name} with a leading {@code host.tld/} component stripped, when {@code name}
     *         matches the {@link #GO_MODULE_PATH} shape this class's own routing already detects
     *         (e.g. {@code "github.com/gin-gonic/gin"} -&gt; {@code "gin-gonic/gin"}) — {@code name}
     *         unchanged otherwise. Used by CPE containment matching ({@link
     *         com.vulncheck.app.service.Stage1IdentificationService}) so a Go module path's VCS
     *         host doesn't anchor a match on a near-universal "github"/"gitlab"/etc. CPE vendor
     *         entry instead of the module's real, meaningful path segments.
     */
    public static String stripHostPrefix(String name) {
        if (name == null) {
            return null;
        }
        String trimmed = name.trim();
        if (!GO_MODULE_PATH.matcher(trimmed).matches()) {
            return name;
        }
        return trimmed.substring(trimmed.indexOf('/') + 1);
    }

    private List<PackageRegistryLookup> only(List<PackageRegistryLookup> allLookups, String ecosystem) {
        List<PackageRegistryLookup> targeted = allLookups.stream()
                .filter(lookup -> ecosystem.equals(lookup.ecosystem()))
                .toList();
        // If that registry is disabled/absent, fall back to asking everyone rather than silently
        // identifying nothing — the routing rule is an optimization, not a correctness requirement.
        return targeted.isEmpty() ? allLookups : targeted;
    }
}
