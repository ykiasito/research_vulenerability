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
 * Stage1 Tier1 lookup against the public RubyGems API.
 * https://guides.rubygems.org/rubygems-org-api/#gem-version-methods
 *
 * <p>Closed-mode backlog item 176 pilot, RubyGems rollout (same pattern as the crates.io pilot, see
 * {@code CratesIoRegistryClient}'s javadoc): when {@link #mirrorEnabled} and the local {@code
 * registry_package_mirror} table has actually been synced for {@code ecosystem = 'rubygems'} ({@link
 * RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that mirror ({@link
 * #lookupViaMirror}) instead of ever making a live HTTP call. Off by default, and even when on,
 * transparently falls back to the pre-existing live path ({@link #lookupLive}) whenever the mirror
 * hasn't actually been populated yet (a full sync never having been run) — see {@code
 * RubyGemsMirrorSyncService} for the writer side.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RubyGemsRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "rubygems";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.rubygems-mirror-enabled:false}")
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
        String purl = "pkg:gem/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://rubygems.org/api/v1/versions/{name}.json", productName)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.isArray() || body.isEmpty()) {
                return Optional.empty();
            }

            boolean versionExists = false;
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body) {
                String number = v.path("number").asText();
                versions.add(number);
                if (version.equals(number)) {
                    versionExists = true;
                }
            }
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:gem/" + productName + "@" + version;

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("RubyGems registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
