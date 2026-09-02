package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Stage1 Tier1 lookup against the Go module proxy. Only applicable when the product name is
 * already a Go module path (e.g. "github.com/gin-gonic/gin") — unlike npm/PyPI/Maven, Go has no
 * separate "package name" registry to search by short name, so this is best-effort and mostly
 * useful when the CSV's product_name/vendor combination already looks like a module path.
 * https://go.dev/ref/mod#goproxy-protocol
 *
 * <p><b>Live path, confirmed live 2026-09-02</b> (not assumed from {@code
 * docs/spec/closed-mode-plan.md}'s §5-2/§5-3 entries alone — this project has repeatedly been
 * burned by exactly that gap): {@code GET https://proxy.golang.org/{module}/@v/list} returns the
 * module's full published-version list as a plain {@code text/plain} body, one version per line
 * (confirmed against {@code github.com/gin-gonic/gin} — 28 lines, no redirect chain; and a
 * nonexistent module — plain 404, no body). This replaces the previous two-request {@code
 * @v/{version}.info}+{@code @latest} probing: {@code @v/list} is a single-call equivalent that
 * hands back the same version-list shape every other {@link PackageRegistryLookup} implementation
 * already builds its {@link RegistryMatch#versions()} from, which is what {@link #lookupViaMirror}
 * below needs to stay in parity with this live path (see {@code GoMirrorSyncService}, the writer for
 * the mirror this reads from).
 *
 * <p><b>Module path escaping bug fixed in the same pass</b>: the previous implementation lowercased
 * {@code productName} before escaping it, which made {@link #escapeModulePath} a no-op (there are no
 * uppercase characters left to escape by the time it runs) — for a module whose canonical path has
 * uppercase segments (Go's own worked example: {@code BurntSushi/toml} escapes to {@code
 * !burnt!sushi/toml}, confirmed live: the plain-lowercased form {@code burntsushi/toml} happens to
 * also 200 for this particular repo because GitHub owner/repo segments are themselves
 * case-insensitive, but the raw-uppercase form {@code BurntSushi/toml} is rejected outright with a
 * 404/"bad request: invalid escaped module path" — confirming escaping, not lowercasing, is the
 * proxy's actual contract), lowercasing first would silently send the wrong path whenever escaping
 * was actually load-bearing. {@link #escapeModulePath} now runs directly on the caller's
 * {@code productName} instead.
 *
 * <p>Closed-mode backlog item 176 rollout (Go), same pattern as the crates.io/RubyGems/Packagist/
 * Hex/npm/PyPI/NuGet mirrors (see {@code NuGetRegistryClient}'s javadoc): when {@link #mirrorEnabled}
 * and the local {@code registry_package_mirror} table has actually been synced for {@code ecosystem
 * = 'go'} ({@link RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that
 * mirror ({@link #lookupViaMirror}) instead of ever making a live HTTP call. Off by default, and even
 * when on, transparently falls back to the pre-existing live path ({@link #lookupLive}) whenever the
 * mirror hasn't actually been populated yet — see {@code GoMirrorSyncService} for the writer side.
 *
 * <p><b>Case-folding, deliberately over-broad for Go</b> (see {@code
 * docs/spec/known-limitations.md}'s GHSA-mirror entry on this exact tradeoff): {@link
 * OsvPackageNameNormalizer#normalize} plain-lowercases every ecosystem it doesn't special-case,
 * including {@code go} — even though real Go module paths are case-sensitive. The mirror's storage
 * key therefore folds case the same (accepted, pre-existing) way the GHSA mirror does; the {@code
 * purl} this class returns still uses the caller's original-case {@code productName} in both paths
 * (not the folded key) so a caller never sees a lowercased module path it didn't ask about.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class GoProxyRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "go";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.go-mirror-enabled:false}")
    private boolean mirrorEnabled;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || !productName.contains("/") || !productName.contains(".")) {
            return Optional.empty();
        }
        if (mirrorEnabled && registryPackageMirrorRepository.hasAnyEntries(ECOSYSTEM)) {
            return lookupViaMirror(productName, version);
        }
        return lookupLive(productName, version);
    }

    private Optional<RegistryMatch> lookupViaMirror(String productName, String version) {
        String normalizedModule = OsvPackageNameNormalizer.normalize(ECOSYSTEM, productName);
        List<String> versions = registryPackageMirrorRepository.findVersions(ECOSYSTEM, normalizedModule);
        if (versions.isEmpty()) {
            return Optional.empty();
        }
        boolean versionExists = versions.contains(version);
        BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
        String purl = "pkg:golang/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        String module = escapeModulePath(productName);
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            String body = externalApiRestClient.get()
                    .uri("https://proxy.golang.org/{module}/@v/list", module)
                    .retrieve()
                    .body(String.class);

            List<String> versions = parseVersionList(body);
            if (versions.isEmpty()) {
                return Optional.empty();
            }
            boolean versionExists = versions.contains(version);
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:golang/" + productName + "@" + version;
            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("Go proxy lookup failed for module={}", module, e);
            return Optional.empty();
        }
    }

    private static List<String> parseVersionList(String body) {
        List<String> versions = new ArrayList<>();
        if (body == null || body.isBlank()) {
            return versions;
        }
        for (String line : body.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty()) {
                versions.add(trimmed);
            }
        }
        return versions;
    }

    /**
     * Go's module escaping rule: each uppercase letter is replaced by an exclamation mark
     * followed by its lowercase equivalent, so that module paths remain safe on
     * case-insensitive filesystems/URLs.
     */
    private static String escapeModulePath(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append('!').append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
