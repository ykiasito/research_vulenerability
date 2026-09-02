package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'packagist'}
 * from Packagist's public "provider" metadata (the {@code p2/} endpoint) — closed-mode backlog item
 * 176 rollout (Packagist), same pattern as the crates.io/RubyGems mirrors (see {@code
 * CratesIoMirrorSyncService}'s class javadoc). {@link PackagistRegistryClient} reads from that table
 * when {@code app.closed-mode.packagist-mirror-enabled} is on; this service is the only writer.
 *
 * <p><b>p2 endpoint shape</b> (confirmed live 2026-09-02 against real packages — monolog/monolog,
 * symfony/console — rather than assumed from documentation alone, per this project's own repeated
 * "verify the actual API, not just the write-up" lesson): {@code GET
 * https://repo.packagist.org/p2/{vendor}/{package}.json} returns JSON shaped {@code
 * {"packages":{"vendor/package":[{"version":"...", ...}, ...]}}}, one array entry per published
 * (tagged) release, newest first. A package that doesn't exist returns a plain 404 with a small text
 * body ({@code "404 not found, no packages here"}), not JSON. Unlike crates.io's sparse index, the
 * path has no name-length-dependent directory nesting — it is always exactly {@code p2/{vendor}/
 * {package}.json}, mirroring the CSV's own "vendor/package" product-name shape.
 *
 * <p>This pilot deliberately mirrors only the stable/tagged {@code p2/{vendor}/{package}.json} file,
 * not the separate {@code p2/{vendor}/{package}~dev.json} dev-branch file Packagist also publishes
 * (confirmed live: monolog/monolog's dev file adds only {@code dev-main}/{@code 2.x-dev} on top of the
 * 87 tagged releases in the stable file) — a CSV-supplied dependency version is a released tag in the
 * overwhelming common case, and {@link PackagistRegistryClient}'s pre-existing live path (the legacy
 * {@code packages/{name}.json} endpoint) already has the same "no dev-branch versions" behavior today
 * (that endpoint's {@code versions} map is a superset that happens to include the same tagged releases
 * this pilot captures, not the dev branches either), so this is not a mirror-vs-live behavior change.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the
 * crates.io/RubyGems mirrors: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO
 * UPDATE, see {@link RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so
 * calling it once with a seed list is the bulk ingestion and calling it again later is the
 * differential re-sync. Packagist has no single "list every package" dump the way crates.io's
 * db-dump.tar.gz or RubyGems' versions file do, so — same as the other two mirrors — this rollout
 * cannot enumerate the *entire* registry (600k+ packages) on its own, only whichever vendor/package
 * names a caller supplies (e.g. the golden-300 set, or names actually seen in real job CSVs).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PackagistMirrorSyncService {

    private static final String ECOSYSTEM = "packagist";

    private final RestClient packagistSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on Packagist (404),
     *                    lack the required "vendor/package" slash (the same structural limitation
     *                    {@link PackagistRegistryClient#lookup} already has — see its class javadoc),
     *                    or whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s packagist pacing). Never partially writes a package's row —
     *  {@link #fetchVersions} either returns the package's full version list or nothing for it. */
    public SyncOutcome syncPackages(List<String> packageNames) {
        int synced = 0;
        int unresolved = 0;
        Map<String, List<String>> batch = new LinkedHashMap<>();
        for (String rawName : packageNames) {
            if (rawName == null || rawName.isBlank()) {
                continue;
            }
            String packageName = rawName.trim();
            if (!packageName.contains("/")) {
                log.debug("Packagist mirror sync skipping package name with no vendor/package slash: {}",
                        packageName);
                unresolved++;
                continue;
            }
            // Closed-mode backlog item 184 REVISE: reject a package name outside Packagist's own
            // vendor/package naming grammar before rateLimiter.awaitTurn below, so a name that's
            // going to be rejected anyway never consumes a rate-limit slot at the expense of
            // delaying the next (possibly valid) name in the batch. See
            // RegistryMirrorPackageNameValidator's class javadoc for why this check is needed even
            // though this method's caller already sits behind RegistryMirrorSyncService
            // #isValidSeedName's wider, upload-time gate.
            if (!RegistryMirrorPackageNameValidator.isValidVendorSlashPackageName(packageName)) {
                log.warn("Packagist mirror sync rejected package name as invalid for URL assembly: "
                        + "package={}", packageName);
                unresolved++;
                continue;
            }
            rateLimiter.awaitTurn(ECOSYSTEM);
            Optional<List<String>> versions = fetchVersions(packageName);
            if (versions.isEmpty()) {
                unresolved++;
                continue;
            }
            batch.put(OsvPackageNameNormalizer.normalize(ECOSYSTEM, packageName), versions.get());
            synced++;
        }
        registryPackageMirrorRepository.upsertBatch(ECOSYSTEM, batch);
        log.info("packagist mirror sync: {}/{} package names synced ({} not found on packagist, "
                + "malformed, or fetch/parse failed — see preceding log lines)", synced, packageNames.size(),
                unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the crates.io/RubyGems mirrors. Callers must already have filtered
     *  out names with no "/" (see {@link #syncPackages}) -- this method assumes one is present. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            // Closed-mode backlog item 184: reject a package name outside Packagist's own
            // vendor/package naming grammar before it ever reaches the URL below (see
            // RegistryMirrorPackageNameValidator's class javadoc for why this is needed even though
            // this method's caller already sits behind both syncPackages' own "/" precheck above and
            // RegistryMirrorSyncService#isValidSeedName's wider, upload-time gate).
            RegistryMirrorPackageNameValidator.validateVendorSlashPackageName(packageName);
            // Same UriComponentsBuilder.path(...) technique (not a {name} URI template
            // substitution) as CratesIoMirrorSyncService#fetchVersions uses, and for the identical
            // reason: a single {placeholder} substitution percent-encodes the "/" inside
            // packageName (vendor/package), breaking the real p2 path.
            URI uri = UriComponentsBuilder.fromUriString("https://repo.packagist.org/")
                    .path("p2/" + packageName + ".json")
                    .build()
                    .toUri();
            JsonNode body = packagistSyncRestClient.get()
                    .uri(uri)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null) {
                return Optional.empty();
            }
            JsonNode packageVersions = body.path("packages").path(packageName);
            if (!packageVersions.isArray() || packageVersions.isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (JsonNode entry : packageVersions) {
                String version = entry.path("version").asText(null);
                if (version != null) {
                    versions.add(version);
                }
            }
            if (versions.isEmpty()) {
                log.warn("Packagist p2 index returned a body with no parseable version entries for "
                        + "package={}", packageName);
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (IllegalArgumentException e) {
            log.warn("Packagist mirror sync rejected package name as invalid for URL assembly: "
                    + "package={} ({})", packageName, e.getMessage());
            return Optional.empty();
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("Packagist p2 index has no entry for package={}", packageName);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Packagist p2 index fetch failed for package={}", packageName, e);
            return Optional.empty();
        }
    }
}
