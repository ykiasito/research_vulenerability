package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.math.BigDecimal;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Stage1 Tier1 lookup against the Go module proxy. Only applicable when the product name is
 * already a Go module path (e.g. "github.com/gin-gonic/gin") — unlike npm/PyPI/Maven, Go has no
 * separate "package name" registry to search by short name, so this is best-effort and mostly
 * useful when the CSV's product_name/vendor combination already looks like a module path.
 * https://go.dev/ref/mod#goproxy-protocol
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class GoProxyRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "go";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || !productName.contains("/") || !productName.contains(".")) {
            return Optional.empty();
        }

        String module = escapeModulePath(productName.toLowerCase());
        String escapedVersion = escapeModulePath(version);

        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode info = externalApiRestClient.get()
                    .uri("https://proxy.golang.org/{module}/@v/{version}.info", module, escapedVersion)
                    .retrieve()
                    .body(JsonNode.class);

            if (info != null && info.has("Version")) {
                String purl = "pkg:golang/" + productName + "@" + version;
                return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, new BigDecimal("0.95"), true));
            }
        } catch (Exception e) {
            log.debug("Go proxy exact-version lookup failed for module={} version={}", module, version, e);
        }

        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            externalApiRestClient.get()
                    .uri("https://proxy.golang.org/{module}/@latest", module)
                    .retrieve()
                    .body(JsonNode.class);
            // Module exists, but the requested version could not be confirmed.
            String purl = "pkg:golang/" + productName + "@" + version;
            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, new BigDecimal("0.4"), false));
        } catch (Exception e) {
            log.debug("Go proxy module lookup failed for module={}", module, e);
            return Optional.empty();
        }
    }

    /**
     * Go's module escaping rule: each uppercase letter is replaced by an exclamation mark
     * followed by its lowercase equivalent, so that module paths remain safe on
     * case-insensitive filesystems/URLs.
     */
    private String escapeModulePath(String input) {
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
