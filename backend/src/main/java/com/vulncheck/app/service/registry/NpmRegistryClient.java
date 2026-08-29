package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Stage1 Tier1 lookup against the public npm registry.
 * https://github.com/npm/registry/blob/main/docs/REGISTRY-API.md
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NpmRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "npm";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
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
