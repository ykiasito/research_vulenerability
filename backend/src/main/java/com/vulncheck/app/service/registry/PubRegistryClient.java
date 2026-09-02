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
 * Stage1 Tier1 lookup against the public pub.dev API (Dart/Flutter).
 * https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md
 *
 * <p>Closed-mode backlog item 176 rollout (pub.dev), same pattern as the crates.io/RubyGems/
 * Packagist/Hex/npm/PyPI mirrors (see {@code NpmRegistryClient}'s javadoc): when {@link
 * #mirrorEnabled} and the local {@code registry_package_mirror} table has actually been synced for
 * {@code ecosystem = 'pub'} ({@link RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup}
 * answers from that mirror ({@link #lookupViaMirror}) instead of ever making a live HTTP call. Off
 * by default, and even when on, transparently falls back to the pre-existing live path ({@link
 * #lookupLive}) whenever the mirror hasn't actually been populated yet — see {@code
 * PubMirrorSyncService} for the writer side.
 *
 * <p>Kept the ecosystem key {@code "pub"} (not {@code "pub.dev"}) — this was already the pre-existing
 * live client's key before this rollout, matching {@code IdentifiedProduct#getEcosystem}/{@code
 * RegistryRoutingPolicy}'s existing usage; changing it would be an unrelated, out-of-scope rename.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PubRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "pub";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.pub-mirror-enabled:false}")
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
        String purl = "pkg:pub/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://pub.dev/api/packages/{name}", productName)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.path("versions").isArray() || body.path("versions").isEmpty()) {
                return Optional.empty();
            }

            boolean versionExists = false;
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                String pubVersion = v.path("version").asText();
                versions.add(pubVersion);
                if (version.equals(pubVersion)) {
                    versionExists = true;
                }
            }
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:pub/" + productName + "@" + version;

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("pub.dev registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
