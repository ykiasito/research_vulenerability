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
 * Stage1 Tier1 lookup against the public NuGet flat-container API. NuGet package ids are
 * case-insensitive but the flat-container URL requires the lowercase form.
 * https://learn.microsoft.com/en-us/nuget/api/package-base-address
 *
 * <p>The flat-container response never echoes back the package's canonically-cased id (just a
 * bare version list), so the persisted {@code packageName} deliberately keeps the caller's
 * original-case {@code productName} rather than the lowercased id used for the URL — confirmed
 * live that both OSV.dev and GitHub Advisories are case-SENSITIVE on the NuGet package name
 * (querying "newtonsoft.json" returns nothing for either; "Newtonsoft.Json" returns real results
 * for the same version), so Stage2's downstream OSV/GHSA lookups need the real casing, not
 * whatever this class happens to use for its own API call.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NuGetRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "nuget";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        String idLower = productName.toLowerCase();
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            JsonNode body = externalApiRestClient.get()
                    .uri("https://api.nuget.org/v3-flatcontainer/{id}/index.json", idLower)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null || !body.has("versions")) {
                return Optional.empty();
            }

            boolean versionExists = false;
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                String published = v.asText("");
                versions.add(published);
                if (published.equalsIgnoreCase(version)) {
                    versionExists = true;
                }
            }
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:nuget/" + idLower + "@" + version;

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("NuGet registry lookup failed for product={}", productName, e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
