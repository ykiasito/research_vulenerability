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
 *   <li><b>Whitespace</b> — narrows to {@code chocolatey} only, not a full skip. This was "no
 *       registry allows it, it is a CPE case" until {@code ChocolateyRegistryClient} was added
 *       (2026-08-26): Chocolatey's package ids/display names cover exactly the multi-word desktop
 *       product names this used to write off entirely (e.g. "OBS Studio", "Advanced IP Scanner"),
 *       normalized lowercase+hyphenated inside that client. The other nine — all language/library
 *       package managers — still provably can't have a whitespace name, so they're still skipped;
 *       only Chocolatey is asked. Stale reasoning here is exactly how this regressed once before
 *       (this rule silently discarded 89 of 1,429 items' worth of requests, see the class javadoc
 *       history above) — if a future registry is added, re-check this comment against it too.</li>
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
 * <p>The four rules above are checked <em>before</em> the whitespace rule (2026-08-29, following
 * job 167's throughput measurement — see {@code docs/spec/nfr-status-2026-08.md} §3): each of them
 * is some other registry's own unambiguous identifier grammar, none of which Chocolatey's own id
 * grammar ({@code ChocolateyRegistryClient#ID_PATTERN}, which admits none of {@code @}, {@code /},
 * {@code :}) can ever satisfy — so a match rules Chocolatey out with certainty even when the name
 * also happens to contain whitespace (e.g. a Maven coordinate typed with spaces around the colon,
 * or a Go module path whose final segment contains a space). Checking whitespace first, as this
 * class used to, would route exactly this kind of name to Chocolatey only, silently losing the
 * request that should have gone to the real ecosystem — and, at 1,000-item scale, adding one more
 * item competing for Chocolatey's single process-wide, strictly-paced request queue (job 167:
 * ~1,075 Chocolatey requests resolved only 144 items, yet accounted for 68% of the job's total
 * registry rate-limiter wait — see the same nfr-status section) for a name that could never have
 * matched there in the first place.
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

        // Checked ahead of the whitespace/chocolatey rule below — see class javadoc for why: each
        // of these four shapes is some other registry's own unambiguous grammar, which rules out
        // chocolatey with certainty regardless of whether the name also contains whitespace.
        if (NPM_SCOPED.matcher(name).matches()) {
            return only(allLookups, "npm");
        }
        if (GO_MODULE_PATH.matcher(name).matches()) {
            return only(allLookups, "go");
        }
        if (EMPTY_VENDOR_SLASH_PACKAGE.matcher(name).matches()) {
            // A slash-package shape with an empty vendor segment: not a legal Composer identifier
            // (vendor is required), not a legal Go module path (no host.tld/ prefix), and provably
            // not chocolatey either (its id grammar forbids '/' outright, see class javadoc) — no
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
            // Deliberately NOT using the only() helper below: only() falls back to "ask everyone"
            // when its target ecosystem is absent, which is exactly wrong here — the other nine
            // registries provably cannot hold a whitespace-containing name (see class javadoc), so
            // if chocolatey itself isn't wired for some reason this must stay empty, not silently
            // re-open the whitespace request to every HTTP registry.
            return allLookups.stream().filter(lookup -> "chocolatey".equals(lookup.ecosystem())).toList();
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
