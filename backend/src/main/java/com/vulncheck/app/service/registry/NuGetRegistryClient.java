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
 *
 * <p>Closed-mode backlog item 176 rollout (NuGet), same pattern as the crates.io/RubyGems/Hex/
 * Packagist/npm/PyPI mirrors (see {@code PackagistRegistryClient}'s javadoc): when {@link
 * #mirrorEnabled} and the local {@code registry_package_mirror} table has actually been synced for
 * {@code ecosystem = 'nuget'} ({@link RegistryPackageMirrorRepository#hasAnyEntries}), {@link
 * #lookup} answers from that mirror ({@link #lookupViaMirror}) instead of ever making a live HTTP
 * call. Off by default, and even when on, transparently falls back to the pre-existing live path
 * ({@link #lookupLive}) whenever the mirror hasn't actually been populated yet — see {@code
 * NuGetMirrorSyncService} for the writer side. The mirror path keeps the same case-insensitive
 * version match as {@link #lookupLive} ({@link #versionMatches}) and, since the mirror has no
 * canonical case to recover either (same limitation as the live path, see above), builds its
 * {@code purl} from the lowercase-folded storage key rather than the caller's original casing.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class NuGetRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "nuget";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Value("${app.closed-mode.nuget-mirror-enabled:false}")
    private boolean mirrorEnabled;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (mirrorEnabled && registryPackageMirrorRepository.hasAnyEntries(ECOSYSTEM)) {
            return lookupViaMirror(productName, version);
        }
        return lookupLive(productName, version);
    }

    private Optional<RegistryMatch> lookupViaMirror(String productName, String version) {
        String normalizedId = OsvPackageNameNormalizer.normalize(ECOSYSTEM, productName);
        List<String> versions = registryPackageMirrorRepository.findVersions(ECOSYSTEM, normalizedId);
        if (versions.isEmpty()) {
            return Optional.empty();
        }
        boolean versionExists = versionMatches(versions, version);
        BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
        String purl = "pkg:nuget/" + normalizedId + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    private static boolean versionMatches(List<String> versions, String version) {
        for (String published : versions) {
            if (published.equalsIgnoreCase(version)) {
                return true;
            }
        }
        return false;
    }

    private Optional<RegistryMatch> lookupLive(String productName, String version) {
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

            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                versions.add(v.asText(""));
            }
            boolean versionExists = versionMatches(versions, version);
            BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
            String purl = "pkg:nuget/" + idLower + "@" + version;

            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
        } catch (Exception e) {
            log.debug("NuGet registry lookup failed for product={}", LogSanitizer.sanitize(productName), e);
            return Optional.empty();
        }
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
