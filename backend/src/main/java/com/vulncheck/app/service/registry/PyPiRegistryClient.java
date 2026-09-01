package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Stage1 Tier1 lookup against the public PyPI JSON API.
 * https://warehouse.pypa.io/api-reference/json.html
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class PyPiRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "pypi";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
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
            log.debug("PyPI registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
