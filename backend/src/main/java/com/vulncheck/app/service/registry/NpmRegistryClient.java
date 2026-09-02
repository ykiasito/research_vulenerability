package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
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
 * Stage1 Tier1 lookup against the public npm registry.
 * https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
 *
 * <p>Closed-mode backlog item 176 rollout (npm), same pattern as the crates.io/RubyGems/Packagist/Hex
 * mirrors (see {@code PackagistRegistryClient}'s javadoc): when {@link #mirrorEnabled} and the local
 * {@code registry_package_mirror} table has actually been synced for {@code ecosystem = 'npm'}
 * ({@link RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that mirror
 * ({@link #lookupViaMirror}) instead of ever making a live HTTP call. Off by default, and even when
 * on, transparently falls back to the pre-existing live path ({@link #lookupLive}) whenever the
 * mirror hasn't actually been populated yet — see {@code NpmMirrorSyncService} for the writer side.
 *
 * <p>Scoped package names ({@code @scope/name}, e.g. {@code @types/node}) work unchanged in both
 * paths: the single {@code {name}} URI template variable below percent-encodes both the {@code @}
 * and the {@code /} (producing {@code %40types%2Fnode}), and {@code registry.npmjs.org} accepts that
 * fully-percent-encoded form (confirmed live 2026-09-02 against {@code @types/node} — same "verify
 * the real API, not just the write-up" discipline as the other mirror rollouts, especially given the
 * URL-encoding trap the crates.io pilot hit for a similarly shaped path). Unlike Packagist's {@code
 * p2/} provider index, npm's per-package document endpoint treats the whole scoped name as one
 * logical path segment, so this is not the same "must be a raw, unencoded multi-segment path" case
 * {@code PackagistMirrorSyncService#fetchVersions} had to work around with {@code
 * UriComponentsBuilder.path(...)}.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NpmRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "npm";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.npm-mirror-enabled:false}")
    private boolean mirrorEnabled;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (mirrorEnabled && registryPackageMirrorRepository.hasAnyEntries(ECOSYSTEM)) {
            return lookupViaMirror(productName, version);
        }
        return lookupLive(productName, version);
    }

    private Optional<RegistryMatch> lookupViaMirror(String productName, String version) {
        String normalizedName = OsvPackageNameNormalizer.normalize(ECOSYSTEM, productName);
        List<String> versions = registryPackageMirrorRepository.findVersions(ECOSYSTEM, normalizedName);
        if (versions.isEmpty()) {
            return Optional.empty();
        }
        boolean versionExists = versions.contains(version);
        BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
        String purl = "pkg:npm/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://registry.npmjs.org/{name}", productName)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.has("versions")) {
                return Optional.empty();
            }

            String packageName = body.path("name").asText(productName);
            boolean versionExists = body.path("versions").has(version);
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:npm/" + packageName + "@" + version;
            // "versions" is a JSON object keyed by every published version string — already fetched
            // above to check versionExists; capturing the key set costs nothing extra and lets
            // RegistryLookupCache answer a later item asking about a different version of this same
            // package without another request.
            List<String> versions = new ArrayList<>();
            body.path("versions").fieldNames().forEachRemaining(versions::add);

            return Optional.of(new RegistryMatch(ECOSYSTEM, packageName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("npm registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
