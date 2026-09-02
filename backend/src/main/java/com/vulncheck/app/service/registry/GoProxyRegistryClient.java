package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Stage1 Tier1 lookup against the local Go module proxy mirror. Only applicable when the product
 * name is already a Go module path (e.g. "github.com/gin-gonic/gin") — unlike npm/PyPI/Maven, Go
 * has no separate "package name" registry to search by short name, so this is best-effort and
 * mostly useful when the CSV's product_name/vendor combination already looks like a module path.
 * https://go.dev/ref/mod#goproxy-protocol
 *
 * <p>Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §3-2): the live HTTP
 * lookup this class used to fall back to ({@code lookupLive}, whenever the mirror wasn't populated
 * or the {@code app.closed-mode.go-mirror-enabled} flag was off) has been removed outright —
 * closed mode has no network to make that call over in the first place. {@link #lookup} now always
 * answers from the local {@code registry_package_mirror} table ({@link #lookupViaMirror}); a
 * package genuinely absent from it (including "never synced at all") is a confident "not found",
 * same as the live path's own not-found case used to be. See {@code GoMirrorSyncService} for the
 * writer side.
 *
 * <p><b>Case-folding, deliberately over-broad for Go</b> (see {@code
 * docs/spec/known-limitations.md}'s GHSA-mirror entry on this exact tradeoff): {@link
 * OsvPackageNameNormalizer#normalize} plain-lowercases every ecosystem it doesn't special-case,
 * including {@code go} — even though real Go module paths are case-sensitive. The mirror's storage
 * key therefore folds case the same (accepted, pre-existing) way the GHSA mirror does; the {@code
 * purl} this class returns still uses the caller's original-case {@code productName} (not the
 * folded key) so a caller never sees a lowercased module path it didn't ask about.
 */
@Component
@RequiredArgsConstructor
public class GoProxyRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "go";

    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || !productName.contains("/") || !productName.contains(".")) {
            return Optional.empty();
        }
        return lookupViaMirror(productName, version);
    }

    private Optional<RegistryMatch> lookupViaMirror(String productName, String version) {
        String normalizedModule = OsvPackageNameNormalizer.normalize(ECOSYSTEM, productName);
        List<String> versions = registryPackageMirrorRepository.findVersions(ECOSYSTEM, normalizedModule);
        if (versions.isEmpty()) {
            return Optional.empty();
        }
        boolean versionExists = versions.contains(version);
        BigDecimal confidence = versionExists ? new BigDecimal("0.95") : new BigDecimal("0.5");
        String purl = "pkg:golang/" + productName + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, confidence, versionExists, versions));
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
