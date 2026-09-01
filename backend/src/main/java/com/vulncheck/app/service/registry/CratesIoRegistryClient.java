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
 * Stage1 Tier1 lookup against the public crates.io API (Rust).
 * https://crates.io/data-access#api
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CratesIoRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "crates.io";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
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
            log.debug("crates.io registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
