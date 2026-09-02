package com.vulncheck.app.service.registry;

import java.util.regex.Pattern;

/**
 * Shared, per-registry package-name grammar check used at the point {@link
 * CratesIoMirrorSyncService#fetchVersions} / {@link PackagistMirrorSyncService#fetchVersions} build
 * the outbound request URL (closed-mode backlog item 184) — defense in depth against a request-path
 * injection risk: both methods concatenate a caller-supplied package name directly into a
 * fixed-host URL path via {@code UriComponentsBuilder.path(...)} rather than a URI-template
 * placeholder (see each method's own javadoc for why — a placeholder substitution would
 * percent-encode the "/" those two registries' path shapes need to stay literal), which means the
 * raw string reaches the request path unencoded. The host itself is a fixed literal in both
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
 * <p>Both {@link CratesIoMirrorSyncService#fetchVersions} and {@link
 * PackagistMirrorSyncService#fetchVersions} already wrap their whole URL-assembly-and-fetch body in
 * a catch-all that logs and folds the failure into their {@code SyncOutcome}'s {@code unresolved}
 * count (per-package, so one bad name never aborts the rest of a {@code syncPackages} batch) —
 * throwing {@link IllegalArgumentException} from here fits that existing "skip + count + log"
 * contract without either caller needing new control flow.
 */
final class RegistryMirrorPackageNameValidator {

    private static final Pattern ALLOWED_SEGMENT_CHARS = Pattern.compile("[A-Za-z0-9._-]+");

    private RegistryMirrorPackageNameValidator() {
    }

    /**
     * Validates a package name with no path separator of its own — crates.io's naming rules (see
     * {@link CratesIoMirrorSyncService#fetchVersions}).
     *
     * @throws IllegalArgumentException if {@code name} contains any character outside {@code
     *         [A-Za-z0-9._-]}, or is exactly {@code "."} or {@code ".."}.
     */
    static void validateSimpleName(String name) {
        validateSegment(name);
    }

    /**
     * Validates a Packagist-shaped {@code vendor/package} name: exactly one {@code "/"}, with each
     * side individually held to the same allowed-character/traversal rule as {@link
     * #validateSimpleName} (see {@link PackagistMirrorSyncService#fetchVersions}).
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
        validateSegment(name.substring(0, firstSlash));
        validateSegment(name.substring(firstSlash + 1));
    }

    private static void validateSegment(String segment) {
        if (segment.equals(".") || segment.equals("..")) {
            throw new IllegalArgumentException("Registry package name segment is a traversal token: " + segment);
        }
        if (!ALLOWED_SEGMENT_CHARS.matcher(segment).matches()) {
            throw new IllegalArgumentException("Registry package name contains disallowed characters: " + segment);
        }
    }
}
