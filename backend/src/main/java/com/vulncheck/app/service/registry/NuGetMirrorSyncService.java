package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'nuget'} from
 * NuGet's public flat-container package-base-address API ({@code
 * https://api.nuget.org/v3-flatcontainer/{id}/index.json}) — closed-mode backlog item 176 rollout
 * (NuGet), same pattern as the crates.io/RubyGems/Packagist/Hex/npm/PyPI mirrors (see {@code
 * PackagistMirrorSyncService}'s javadoc). {@link NuGetRegistryClient} reads from that table when
 * {@code app.closed-mode.nuget-mirror-enabled} is on; this service is the only writer.
 *
 * <p><b>Endpoint choice, confirmed live 2026-09-02</b> (not assumed from {@code
 * docs/spec/closed-mode-plan.md}'s §5-2 entry alone — this project has repeatedly been burned by
 * exactly that gap): the plan's §5-2 entry for NuGet points at the V3 Catalog (cursor-based
 * differential sync, modelled on the {@code NuGetMirror} tool) as the mechanism for a true full
 * mirror, but flags its first sync as large (~100-200GB of append-only catalog log since 2015). This
 * pilot rollout does not attempt the Catalog at all — same "reuse the existing per-item live
 * endpoint instead of the unstable/heavy bulk feed" choice the npm rollout made for {@code _changes}.
 * It reuses the exact same {@code GET https://api.nuget.org/v3-flatcontainer/{id}/index.json}
 * endpoint {@link NuGetRegistryClient}'s pre-existing live path already calls — confirmed against
 * {@code newtonsoft.json} (200 OK, plain {@code {"versions": [...]}} array, no redirect chain —
 * served directly off Azure Blob Storage per the response's {@code x-ms-blob-type}/{@code
 * X-CDN-Rewrite} headers) and a nonexistent id (plain 404, no body). Same "per-package request, no
 * bulk listing endpoint" shape and limitation as the other per-package mirrors — this rollout cannot
 * enumerate the entire NuGet gallery on its own, only whichever package ids a caller supplies (e.g.
 * the golden-300 set, or ids actually seen in real job CSVs). A true V3-Catalog-based full mirror
 * remains future work if closed-mode ever needs coverage beyond explicitly-synced ids.
 *
 * <p><b>Case-insensitivity</b>: the flat-container URL requires the package id in lowercase form
 * (confirmed live via the endpoint's own {@code X-CDN-Rewrite: Lowercase blobs in v3-flatcontainer}
 * response header). The response body never echoes back a canonically-cased id, so — same as {@link
 * NuGetRegistryClient}'s live path — this service has no canonical case to recover; it stores the
 * lowercase-folded id ({@link OsvPackageNameNormalizer#normalize}, NuGet gets the same plain
 * case-fold every non-PyPI/crates.io ecosystem gets) as the mirror's lookup key, and {@link
 * NuGetRegistryClient} re-normalizes the caller's product name the same way before querying it.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the other
 * per-package mirrors: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO
 * UPDATE, see {@link RegistryPackageMirrorRepository#upsertBatch}) every package id it's given, so
 * calling it once with a seed list is the bulk ingestion and calling it again later is the
 * differential re-sync.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NuGetMirrorSyncService {

    private static final String ECOSYSTEM = "nuget";

    private final RestClient nugetSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package ids that resolved to at least one published version
     *               and were written to the mirror.
     * @param unresolved number of requested package ids that either don't exist on the NuGet gallery
     *                    (404) or whose fetch/parse failed — see per-package log lines (level varies)
     *                    for which case applied to which id.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package id — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s nuget pacing). Never partially writes a package's row — {@link
     *  #fetchVersions} either returns the package's full version list or nothing for it. */
    public SyncOutcome syncPackages(List<String> packageIds) {
        int synced = 0;
        int unresolved = 0;
        Map<String, List<String>> batch = new LinkedHashMap<>();
        for (String rawId : packageIds) {
            if (rawId == null || rawId.isBlank()) {
                continue;
            }
            String packageId = rawId.trim();
            rateLimiter.awaitTurn(ECOSYSTEM);
            Optional<List<String>> versions = fetchVersions(packageId);
            if (versions.isEmpty()) {
                unresolved++;
                continue;
            }
            batch.put(OsvPackageNameNormalizer.normalize(ECOSYSTEM, packageId), versions.get());
            synced++;
        }
        registryPackageMirrorRepository.upsertBatch(ECOSYSTEM, batch);
        log.info("NuGet mirror sync: {}/{} package ids synced ({} not found on the NuGet gallery or "
                + "fetch/parse failed — see preceding log lines)", synced, packageIds.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the other per-package mirrors. */
    private Optional<List<String>> fetchVersions(String packageId) {
        String idLower = packageId.toLowerCase(Locale.ROOT);
        try {
            JsonNode body = nugetSyncRestClient.get()
                    .uri("https://api.nuget.org/v3-flatcontainer/{id}/index.json", idLower)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null || !body.path("versions").isArray() || body.path("versions").isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                String published = v.asText("");
                if (!published.isBlank()) {
                    versions.add(published);
                }
            }
            if (versions.isEmpty()) {
                log.warn("NuGet flat-container index returned a body with no parseable version "
                        + "entries for id={}", packageId);
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("NuGet flat-container index has no entry for id={}", packageId);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("NuGet flat-container index fetch failed for id={}", packageId, e);
            return Optional.empty();
        }
    }
}
