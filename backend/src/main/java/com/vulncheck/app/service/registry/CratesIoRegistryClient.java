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
 * Stage1 Tier1 lookup against the public crates.io API (Rust).
 * https://crates.io/data-access#api
 *
 * <p>Closed-mode backlog item 176 pilot: when {@link #mirrorEnabled} and the local {@code
 * registry_package_mirror} table has actually been synced ({@link
 * RegistryPackageMirrorRepository#hasAnyEntries}), {@link #lookup} answers from that mirror instead
 * of ever making a live HTTP call ({@link #lookupViaMirror}) -- the whole point of a closed-mode
 * deployment. Off by default and, even when on, transparently falls back to the pre-existing live
 * path ({@link #lookupLive}) whenever the mirror hasn't actually been populated yet (a full sync
 * never having been run), so flipping this flag on ahead of running {@code
 * CratesIoMirrorSyncService} degrades to today's behavior rather than breaking every crates.io
 * lookup. Once the mirror *is* populated, a package genuinely absent from it is treated as a
 * confident "not found" (no live fallback per package) -- closed mode has no network to fall back
 * to in the first place, so that would just be a guaranteed failure anyway.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CratesIoRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "crates.io";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.crates-io-mirror-enabled:false}")
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
        String purl = "pkg:cargo/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://crates.io/api/v1/crates/{name}/versions", productName)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.path("versions").isArray() || body.path("versions").isEmpty()) {
                return Optional.empty();
            }

            boolean versionExists = false;
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                String num = v.path("num").asText();
                versions.add(num);
                if (version.equals(num)) {
                    versionExists = true;
                }
            }
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:cargo/" + productName + "@" + version;

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("crates.io registry lookup failed for product={}", LogSanitizer.sanitize(productName), e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
