package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Stage1 Tier1 lookup against the local Packagist (PHP/Composer) registry mirror.
 * https://packagist.org/apidoc
 *
 * <p>Unlike every other registry here, Packagist package names are inherently two-part
 * ("vendor/package", e.g. "monolog/monolog") — there is no lookup-by-bare-name endpoint. A CSV row
 * with just "monolog" (not "monolog/monolog") will simply not resolve here; this is a real,
 * structural limitation of this ecosystem, not a bug to work around; the product name must already
 * contain the slash for this client to have anything to query.
 *
 * <p>Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §3-2): the live HTTP
 * lookup this class used to fall back to ({@code lookupLive}, whenever the mirror wasn't populated
 * or the {@code app.closed-mode.packagist-mirror-enabled} flag was off) has been removed outright —
 * closed mode has no network to make that call over in the first place. {@link #lookup} now always
 * answers from the local {@code registry_package_mirror} table ({@link #lookupViaMirror}); a
 * package genuinely absent from it (including "never synced at all") is a confident "not found",
 * same as the live path's own not-found case used to be. See {@code PackagistMirrorSyncService} for
 * the writer side.
 */
@Component
@RequiredArgsConstructor
public class PackagistRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "packagist";

    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || !productName.contains("/")) {
            return Optional.empty();
        }
        return lookupViaMirror(productName, version);
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

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
