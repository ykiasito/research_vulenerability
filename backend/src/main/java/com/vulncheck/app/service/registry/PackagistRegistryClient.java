package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.LogSanitizer;
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
 * Stage1 Tier1 lookup against the public Packagist API (PHP/Composer).
 * https://packagist.org/apidoc
 *
 * <p>Unlike every other registry here, Packagist package names are inherently two-part
 * ("vendor/package", e.g. "monolog/monolog") — there is no lookup-by-bare-name endpoint. A CSV row
 * with just "monolog" (not "monolog/monolog") will simply not resolve here; this is a real,
 * structural limitation of this ecosystem, not a bug to work around; the product name must already
 * contain the slash for this client to have anything to query.
 *
 * <p>Closed-mode backlog item 176 rollout (Packagist), same pattern as the crates.io/RubyGems mirrors
 * (see {@code CratesIoRegistryClient}'s javadoc): when {@link #mirrorEnabled} and the local {@code
 * registry_package_mirror} table has actually been synced for {@code ecosystem = 'packagist'} ({@link
 * RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that mirror ({@link
 * #lookupViaMirror}) instead of ever making a live HTTP call. Off by default, and even when on,
 * transparently falls back to the pre-existing live path ({@link #lookupLive}) whenever the mirror
 * hasn't actually been populated yet — see {@code PackagistMirrorSyncService} for the writer side.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PackagistRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "packagist";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.packagist-mirror-enabled:false}")
    private boolean mirrorEnabled;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || !productName.contains("/")) {
            return Optional.empty();
        }
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
        String purl = "pkg:composer/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://packagist.org/packages/{name}.json", productName)
                    .retrieve()
                    .body(JsonNode.class);

            JsonNode versions = body == null ? null : body.path("package").path("versions");
            if (versions == null || !versions.isObject() || versions.isEmpty()) {
                return Optional.empty();
            }

            boolean versionExists = versions.has(version);
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:composer/" + productName + "@" + version;
            List<String> versionList = new ArrayList<>();
            versions.fieldNames().forEachRemaining(versionList::add);

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versionList));
        } catch (Exception e) {
            log.debug("Packagist registry lookup failed for product={}", LogSanitizer.sanitize(productName), e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
