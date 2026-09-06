package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.LogSanitizer;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;

/**
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'npm'} from
 * npm's public per-package document endpoint ({@code https://registry.npmjs.org/{name}}) —
 * closed-mode backlog item 176 rollout (npm), same pattern as the crates.io/RubyGems/Packagist/Hex
 * mirrors (see {@code PackagistMirrorSyncService}'s javadoc). {@link NpmRegistryClient} reads
 * unconditionally from that table (the {@code app.closed-mode.npm-mirror-enabled} flag that used to
 * gate this has since been removed); this service is the only writer.
 *
 * <p><b>Endpoint choice, confirmed live 2026-09-02</b> (not assumed from {@code
 * docs/spec/closed-mode-plan.md}'s §5-2 entry alone — this project has repeatedly been burned by
 * exactly that gap): the plan's own §5-2 flags npm's replication API ({@code _changes} feed) as
 * mid-migration to a new pagination shape and therefore unstable to build on right now. This rollout
 * does not attempt that feed at all. Instead it reuses the exact same {@code GET
 * https://registry.npmjs.org/{name}} document endpoint {@link NpmRegistryClient}'s pre-existing live
 * path already calls — confirmed against {@code lodash} (plain name) and the scoped package {@code
 * @types/node} (both return a top-level {@code versions} object keyed by every published version
 * string; a nonexistent package returns a plain 404 with a small JSON error body, {@code {"error":
 * "Not found"}}). Same "per-package request, no bulk listing endpoint" shape and limitation as the
 * crates.io/RubyGems/Packagist/Hex mirrors — this rollout cannot enumerate the entire npm registry
 * (2M+ packages) on its own, only whichever package names a caller supplies (e.g. the golden-300 set,
 * or names actually seen in real job CSVs).
 *
 * <p><b>Scoped package names</b> ({@code @scope/name}) need no special path handling here, unlike
 * {@code PackagistMirrorSyncService#fetchVersions}'s {@code UriComponentsBuilder.path(...)} workaround
 * for Packagist's {@code p2/{vendor}/{package}.json} (a genuinely multi-segment path). npm's endpoint
 * treats the whole scoped name as one logical path segment, and the single {@code {name}} URI
 * template variable's automatic percent-encoding (both {@code @} -> {@code %40} and {@code /} ->
 * {@code %2F}, e.g. {@code @types/node} becomes {@code %40types%2Fnode}) already resolves correctly
 * against the real registry (confirmed live against {@code @types/node} above) — see {@link
 * NpmRegistryClient}'s class javadoc for the same note on the live-lookup path.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the other
 * per-package mirrors: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO
 * UPDATE, see {@link RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so
 * calling it once with a seed list is the bulk ingestion and calling it again later is the
 * differential re-sync.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class NpmMirrorSyncService {

    private static final String ECOSYSTEM = "npm";

    private final RestClient npmSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on the npm
     *                    registry (404) or whose fetch/parse failed — see per-package log lines
     *                    (level varies) for which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s npm pacing). Never partially writes a package's row — {@link
     *  #fetchVersions} either returns the package's full version list or nothing for it. */
    public SyncOutcome syncPackages(List<String> packageNames) {
        int synced = 0;
        int unresolved = 0;
        Map<String, List<String>> batch = new LinkedHashMap<>();
        for (String rawName : packageNames) {
            if (rawName == null || rawName.isBlank()) {
                continue;
            }
            String packageName = rawName.trim();
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
        log.info("npm mirror sync: {}/{} package names synced ({} not found on the npm registry or "
                + "fetch/parse failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the other per-package mirrors. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            JsonNode body = npmSyncRestClient.get()
                    .uri("https://registry.npmjs.org/{name}", packageName)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null || !body.path("versions").isObject() || body.path("versions").isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            Iterator<String> versionKeys = body.path("versions").fieldNames();
            versionKeys.forEachRemaining(versions::add);
            if (versions.isEmpty()) {
                log.warn("npm registry returned a package body with no parseable version keys for "
                        + "package={}", LogSanitizer.sanitize(packageName));
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("npm registry has no entry for package={}", LogSanitizer.sanitize(packageName));
            return Optional.empty();
        } catch (Exception e) {
            log.warn("npm registry package fetch failed for package={}", LogSanitizer.sanitize(packageName), e);
            return Optional.empty();
        }
    }
}
