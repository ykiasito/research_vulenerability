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
 * Stage1 Tier1 lookup against the public PyPI JSON API.
 * https://warehouse.pypa.io/api-reference/json.html
 *
 * <p>Closed-mode backlog item 176 rollout (PyPI): when {@link #mirrorEnabled} and the local {@code
 * registry_package_mirror} table has actually been synced for {@code ecosystem = 'pypi'} ({@link
 * RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that mirror ({@link
 * #lookupViaMirror}) instead of ever making a live HTTP call. Off by default, and even when on,
 * transparently falls back to the pre-existing live path ({@link #lookupLive}) whenever the mirror
 * hasn't actually been populated yet — see {@code PyPiMirrorSyncService} for the writer side. Same
 * shape as {@link CratesIoRegistryClient}/{@link RubyGemsRegistryClient}/{@link
 * PackagistRegistryClient}/{@link HexRegistryClient}.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PyPiRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "pypi";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.pypi-mirror-enabled:false}")
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
        String purl = "pkg:pypi/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://pypi.org/pypi/{name}/json", productName)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.has("info")) {
                return Optional.empty();
            }

            String packageName = body.path("info").path("name").asText(productName);
            boolean versionExists = body.path("releases").has(version);
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:pypi/" + packageName + "@" + version;
            // "releases" is a JSON object keyed by every published version string — already fetched
            // above to check versionExists; capturing the key set costs nothing extra (see
            // RegistryMatch#versions()).
            List<String> versions = new ArrayList<>();
            body.path("releases").fieldNames().forEachRemaining(versions::add);

            return Optional.of(new RegistryMatch(ECOSYSTEM, packageName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("PyPI registry lookup failed for product={}", LogSanitizer.sanitize(productName), e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
