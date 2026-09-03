package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.LogSanitizer;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
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

/**
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'pub'} from
 * pub.dev's public per-package document endpoint ({@code https://pub.dev/api/packages/{name}}) —
 * closed-mode backlog item 176 rollout (pub.dev), same pattern as the crates.io/RubyGems/Packagist/
 * Hex/npm/PyPI mirrors (see {@code NpmMirrorSyncService}'s javadoc). {@link PubRegistryClient} reads
 * from that table when {@code app.closed-mode.pub-mirror-enabled} is on; this service is the only
 * writer.
 *
 * <p><b>Endpoint choice, confirmed live 2026-09-02</b> (not assumed from {@code
 * docs/spec/closed-mode-plan.md}'s §5-2 entry alone — this project has repeatedly been burned by
 * exactly that gap): the plan's §5-2 flags {@code GET /api/package-names} (full package name
 * enumeration) as an option, and it does work live — but only when the caller sends {@code
 * Accept-Encoding: gzip} (confirmed live: without it, pub.dev returns a 200 with a JSON body {@code
 * {"error":{"code":"NotAcceptable","message":"Client must accept gzip content."}}} instead of the
 * package list). This rollout does not attempt that enumeration endpoint at all — same "per-package
 * request, no bulk listing endpoint used" shape and limitation as the other mirrors, deliberately for
 * consistency with them (this rollout cannot enumerate the entire pub.dev registry on its own, only
 * whichever package names a caller supplies, e.g. the golden-300 set, or names actually seen in real
 * job CSVs). Instead it reuses the exact same {@code GET https://pub.dev/api/packages/{name}}
 * document endpoint {@link PubRegistryClient}'s pre-existing live path already calls — confirmed
 * live against {@code http} (returns a top-level {@code versions} array of objects, each with a
 * {@code version} field; a nonexistent package returns a plain 404, no gzip requirement, no redirect
 * observed).
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
public class PubMirrorSyncService {

    private static final String ECOSYSTEM = "pub";

    private final RestClient pubSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on pub.dev (404)
     *                    or whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s pub pacing). Never partially writes a package's row — {@link
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
        log.info("pub.dev mirror sync: {}/{} package names synced ({} not found on pub.dev or "
                + "fetch/parse failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the other per-package mirrors. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            JsonNode body = pubSyncRestClient.get()
                    .uri("https://pub.dev/api/packages/{name}", packageName)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null || !body.path("versions").isArray() || body.path("versions").isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (JsonNode v : body.path("versions")) {
                String pubVersion = v.path("version").asText();
                if (!pubVersion.isBlank()) {
                    versions.add(pubVersion);
                }
            }
            if (versions.isEmpty()) {
                log.warn("pub.dev registry returned a package body with no parseable version entries "
                        + "for package={}", LogSanitizer.sanitize(packageName));
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("pub.dev registry has no entry for package={}", LogSanitizer.sanitize(packageName));
            return Optional.empty();
        } catch (Exception e) {
            log.warn("pub.dev registry package fetch failed for package={}", LogSanitizer.sanitize(packageName), e);
            return Optional.empty();
        }
    }
}
