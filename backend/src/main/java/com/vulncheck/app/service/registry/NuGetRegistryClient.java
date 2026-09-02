package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Stage1 Tier1 lookup against the local NuGet registry mirror. NuGet package ids are
 * case-insensitive.
 * https://learn.microsoft.com/en-us/nuget/api/package-base-address
 *
 * <p>The mirror has no canonically-cased id to recover (its storage key is lowercase-folded, same
 * as the flat-container URL the removed live path used to query — see below), so the persisted
 * {@code purl} is built from that lowercase-folded storage key rather than the caller's original
 * casing, while the persisted {@code packageName} still keeps the caller's original-case {@code
 * productName} — confirmed live that both OSV.dev and GitHub Advisories are case-SENSITIVE on the
 * NuGet package name (querying "newtonsoft.json" returns nothing for either; "Newtonsoft.Json"
 * returns real results for the same version), so Stage2's downstream OSV/GHSA lookups need the
 * real casing.
 *
 * <p>Closed-mode backlog item 193 (B3, {@code docs/spec/closed-mode-plan.md} §3-2): the live HTTP
 * lookup this class used to fall back to ({@code lookupLive}, whenever the mirror wasn't populated
 * or the {@code app.closed-mode.nuget-mirror-enabled} flag was off) has been removed outright —
 * closed mode has no network to make that call over in the first place. {@link #lookup} now always
 * answers from the local {@code registry_package_mirror} table ({@link #lookupViaMirror}); a
 * package genuinely absent from it (including "never synced at all") is a confident "not found",
 * same as the live path's own not-found case used to be. See {@code NuGetMirrorSyncService} for
 * the writer side.
 */
@Component
@RequiredArgsConstructor
public class NuGetRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "nuget";

    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        return lookupViaMirror(productName, version);
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

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
