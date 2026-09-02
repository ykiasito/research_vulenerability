package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Stage1 Tier1 lookup against the local pub.dev (Dart/Flutter) registry mirror.
 * https://github.com/dart-lang/pub/blob/master/doc/repository-spec-v2.md
 *
 * <p>Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §3-2): the live HTTP
 * lookup this class used to fall back to ({@code lookupLive}, whenever the mirror wasn't populated
 * or the {@code app.closed-mode.pub-mirror-enabled} flag was off) has been removed outright —
 * closed mode has no network to make that call over in the first place. {@link #lookup} now always
 * answers from the local {@code registry_package_mirror} table ({@link #lookupViaMirror}); a
 * package genuinely absent from it (including "never synced at all") is a confident "not found",
 * same as the live path's own not-found case used to be. See {@code PubMirrorSyncService} for the
 * writer side.
 *
 * <p>Kept the ecosystem key {@code "pub"} (not {@code "pub.dev"}) — this was already the
 * pre-existing live client's key, matching {@code IdentifiedProduct#getEcosystem}/{@code
 * RegistryRoutingPolicy}'s existing usage; changing it would be an unrelated, out-of-scope rename.
 */
@Component
@RequiredArgsConstructor
public class PubRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "pub";

    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
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
        String purl = "pkg:pub/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
