package com.vulncheck.app.service.registry;

import java.util.regex.Pattern;

/**
 * Shared, per-registry package-name grammar check used at the point {@link
 * CratesIoMirrorSyncService#syncPackages} / {@link PackagistMirrorSyncService#syncPackages} build
 * the outbound request URL (closed-mode backlog item 184) — defense in depth against a request-path
 * injection risk: both services' {@code fetchVersions} concatenate a caller-supplied package name
 * directly into a fixed-host URL path via {@code UriComponentsBuilder.path(...)} rather than a
 * URI-template placeholder (see each method's own javadoc for why — a placeholder substitution
 * would percent-encode the "/" those two registries' path shapes need to stay literal), which means
 * the raw string reaches the request path unencoded. The host itself is a fixed literal in both
 * services (not attacker-controlled), so this cannot become SSRF, but an unvalidated name containing
 * {@code ../} segments could still redirect the GET to an unintended path under that same host.
 *
 * <p>{@link RegistryMirrorSyncService#isValidSeedName} already gates names at the point an operator
 * uploads them into {@code registry_mirror_seed_name}, but deliberately with a wider,
 * registry-agnostic character set that has to admit every mirrored ecosystem's legitimate name shape
 * at once (see that method's javadoc). Seed names also reach these two services via the other seed
 * source, {@code identified_products}, which has no upload-time gate at all. This class enforces the
 * tighter grammar the URL assembly itself actually needs, so a name that slipped past (or bypassed)
 * the wider upload-time gate still can't reach the HTTP client unvalidated.
 *
 * <p><b>Why crates.io needs a stricter check than "is this whole segment {@code .} or {@code
 * ..}"</b> (closed-mode backlog item 184 REVISE, {@link CratesIoMirrorSyncService#sparseIndexPath}):
 * the sparse-index path crates.io derives from a name is built from <i>substrings</i> of that name,
 * not the name as a single opaque segment — e.g. {@code name="...."} (4 dots) yields {@code
 * path="../../...."} , and {@code name="..ab"} yields {@code path="../ab/..ab"}. Neither of those
 * names equals {@code "."}/{@code ".."} as a whole, so a check that only asks "is the full segment a
 * traversal token" misses both. crates.io's own naming rules don't allow a period in a crate name at
 * all, so {@link #validateSimpleName} excludes {@code .} from its allowed character set entirely
 * (stricter than, and a closer match to, the real crates.io grammar) rather than trying to
 * special-case every substring shape that could fold into {@code ..}. Packagist vendor/package names
 * do legitimately contain periods (Composer's own naming rules allow them), so {@link
 * #validateVendorSlashPackageName} keeps {@code .} in its allowed set — Packagist's path is always
 * exactly {@code p2/{vendor}/{package}.json} with no substring-of-name derivation, so the
 * whole-segment traversal-token check is sufficient there.
 *
 * <p>Both {@link CratesIoMirrorSyncService#syncPackages} and {@link
 * PackagistMirrorSyncService#syncPackages} run this check per package name before {@link
 * com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter#awaitTurn} for that name, so a
 * rejected name never consumes a rate-limit slot at the expense of delaying the next (possibly
 * valid) name in the batch. Both fold the rejection into their {@code SyncOutcome}'s {@code
 * unresolved} count (per-package, so one bad name never aborts the rest of the batch).
 *
 * <p><b>Why {@link PyPiMirrorSyncService#fetchVersions} is deliberately not covered by this
 * class</b>: it also builds its request path via {@code UriComponentsBuilder.path("simple/" +
 * normalizedName + "/")} — the same raw-concatenation shape as the two registries above — but the
 * name it concatenates has already gone through {@link
 * com.vulncheck.app.service.vuln.OsvPackageNameNormalizer#normalize}. That normalization applies
 * PyPI's own PEP 503 rule of folding every run of {@code .}/{@code -}/{@code _} into a single {@code
 * -}, so a {@code .} (or a run of them) can never survive into the normalized name — there is no way
 * for a normalized PyPI name to contain a {@code ..} traversal token, so no equivalent grammar check
 * is needed there. The remaining six mirrors ({@code NpmMirrorSyncService}, {@code
 * GoMirrorSyncService}, {@code HexMirrorSyncService}, {@code NuGetMirrorSyncService}, {@code
 * PubMirrorSyncService}, {@code RubyGemsMirrorSyncService}) all pass the package name through a
 * {@code {name}}/{@code {id}}/{@code {module}} URI-template placeholder instead of raw path
 * concatenation, and {@code RestClient} percent-encodes {@code "/"} (and therefore any {@code ../}
 * shape) inside a single template substitution, so those six are structurally safe regardless of the
 * name's content.
 */
final class RegistryMirrorPackageNameValidator {

    private static final Pattern ALLOWED_SIMPLE_NAME_CHARS = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern ALLOWED_VENDOR_PACKAGE_CHARS = Pattern.compile("[A-Za-z0-9._-]+");

    private RegistryMirrorPackageNameValidator() {
    }

    /**
     * Non-throwing form of {@link #validateSimpleName}, for callers (e.g. {@link
     * CratesIoMirrorSyncService#syncPackages}) that want to skip a bad name — folding it into their
     * own {@code unresolved} counter — without a try/catch at the call site.
     */
    static boolean isValidSimpleName(String name) {
        try {
            validateSimpleName(name);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** Non-throwing form of {@link #validateVendorSlashPackageName}, same rationale as {@link
     *  #isValidSimpleName}. */
    static boolean isValidVendorSlashPackageName(String name) {
        try {
            validateVendorSlashPackageName(name);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Validates a package name with no path separator of its own — crates.io's naming rules (see
     * {@link CratesIoMirrorSyncService#fetchVersions}). Deliberately excludes {@code .} from the
     * allowed character set (crates.io names never legitimately contain one) rather than only
     * checking whether the whole name equals {@code "."}/{@code ".."} — see this class's javadoc for
     * why the substring-derived sparse-index path needs that stricter rule.
     *
     * @throws IllegalArgumentException if {@code name} contains any character outside {@code
     *         [A-Za-z0-9_-]}, or is exactly {@code "."} or {@code ".."}.
     */
    static void validateSimpleName(String name) {
        validateSegment(name, ALLOWED_SIMPLE_NAME_CHARS);
    }

    /**
     * Validates a Packagist-shaped {@code vendor/package} name: exactly one {@code "/"}, with each
     * side individually held to the same allowed-character/traversal rule as {@link
     * #validateSimpleName}, except {@code .} stays allowed (Composer's naming rules permit it — see
     * {@link PackagistMirrorSyncService#fetchVersions}).
     *
     * @throws IllegalArgumentException if {@code name} does not contain exactly one {@code "/"}, or
     *         either side of it fails the per-segment check.
     */
    static void validateVendorSlashPackageName(String name) {
        int firstSlash = name.indexOf('/');
        int lastSlash = name.lastIndexOf('/');
        if (firstSlash < 0 || firstSlash != lastSlash) {
            throw new IllegalArgumentException(
                    "Packagist package name must contain exactly one '/': " + name);
        }
        validateSegment(name.substring(0, firstSlash), ALLOWED_VENDOR_PACKAGE_CHARS);
        validateSegment(name.substring(firstSlash + 1), ALLOWED_VENDOR_PACKAGE_CHARS);
    }

    private static void validateSegment(String segment, Pattern allowedChars) {
        if (segment.equals(".") || segment.equals("..")) {
            throw new IllegalArgumentException("Registry package name segment is a traversal token: " + segment);
        }
        if (!allowedChars.matcher(segment).matches()) {
            throw new IllegalArgumentException("Registry package name contains disallowed characters: " + segment);
        }
    }
}
