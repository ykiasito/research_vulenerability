package com.vulncheck.app.service.registry;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
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
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'go'} from
 * the Go module proxy's per-module version list ({@code
 * GET https://proxy.golang.org/{module}/@v/list}) — closed-mode backlog item 176 rollout (Go), same
 * pattern as the crates.io/RubyGems/Packagist/Hex/npm/PyPI/NuGet mirrors (see {@code
 * NuGetMirrorSyncService}'s javadoc). {@link GoProxyRegistryClient} reads from that table when
 * {@code app.closed-mode.go-mirror-enabled} is on; this service is the only writer.
 *
 * <p><b>Per-module sync, not the bulk {@code index.golang.org/index} feed</b>: {@code
 * docs/spec/closed-mode-plan.md} §5-3 documents a Go-team-official bulk enumeration endpoint
 * ({@code index.golang.org/index?since=...}, JSONL, paged) that could in principle discover every
 * module the proxy has ever served. This pilot rollout deliberately does not attempt it — same
 * "reuse the existing per-item live endpoint instead of the bulk feed" choice the npm/Hex/NuGet
 * rollouts made for their own bulk alternatives (see their javadocs). It reuses the exact same
 * {@code GET https://proxy.golang.org/{module}/@v/list} endpoint {@link GoProxyRegistryClient}'s
 * live path now calls (confirmed live 2026-09-02 against {@code github.com/gin-gonic/gin} — 200 OK,
 * plain {@code text/plain} body, one version per line, no redirect chain; and a nonexistent module —
 * plain 404, no body). Same "per-module request, no bulk listing endpoint consumed" shape and
 * limitation as the other per-package mirrors — this rollout cannot enumerate every module the proxy
 * has ever seen on its own, only whichever module paths a caller supplies (e.g. the golden-300 set,
 * or module paths actually seen in real job CSVs). A true {@code index.golang.org/index}-based full
 * mirror remains future work if closed-mode ever needs coverage beyond explicitly-synced modules.
 *
 * <p><b>Module path escaping</b>: same rule {@link GoProxyRegistryClient} uses (each uppercase
 * letter becomes {@code !}+its lowercase form) — applied here to build the request URL, not to the
 * stored key. Like {@link GoProxyRegistryClient}, this stores the lowercase-folded module path
 * ({@link OsvPackageNameNormalizer#normalize}, {@code go} gets the same plain case-fold every
 * non-PyPI/crates.io ecosystem gets — see that method's javadoc and {@code
 * docs/spec/known-limitations.md} for why this is a deliberately accepted, pre-existing tradeoff for
 * Go specifically) as the mirror's lookup key.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the other
 * per-package mirrors: {@link #syncModules} always re-fetches and upserts (ON CONFLICT ... DO
 * UPDATE, see {@link RegistryPackageMirrorRepository#upsertBatch}) every module path it's given, so
 * calling it once with a seed list is the bulk ingestion and calling it again later is the
 * differential re-sync.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GoMirrorSyncService {

    private static final String ECOSYSTEM = "go";

    private final RestClient goSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested module paths that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested module paths that either don't exist on the Go module
     *                    proxy (404) or whose fetch/parse failed — see per-module log lines (level
     *                    varies) for which case applied to which module.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per module path — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s go pacing). Never partially writes a module's row — {@link
     *  #fetchVersions} either returns the module's full version list or nothing for it. */
    public SyncOutcome syncModules(List<String> modulePaths) {
        int synced = 0;
        int unresolved = 0;
        Map<String, List<String>> batch = new LinkedHashMap<>();
        for (String rawModule : modulePaths) {
            if (rawModule == null || rawModule.isBlank()) {
                continue;
            }
            String modulePath = rawModule.trim();
            rateLimiter.awaitTurn(ECOSYSTEM);
            Optional<List<String>> versions = fetchVersions(modulePath);
            if (versions.isEmpty()) {
                unresolved++;
                continue;
            }
            batch.put(OsvPackageNameNormalizer.normalize(ECOSYSTEM, modulePath), versions.get());
            synced++;
        }
        registryPackageMirrorRepository.upsertBatch(ECOSYSTEM, batch);
        log.info("Go mirror sync: {}/{} module paths synced ({} not found on the Go module proxy or "
                + "fetch/parse failed — see preceding log lines)", synced, modulePaths.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the module doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncModules}), same as the other per-package mirrors. */
    private Optional<List<String>> fetchVersions(String modulePath) {
        String escapedModule = escapeModulePath(modulePath);
        try {
            String body = goSyncRestClient.get()
                    .uri("https://proxy.golang.org/{module}/@v/list", escapedModule)
                    .retrieve()
                    .body(String.class);
            List<String> versions = new ArrayList<>();
            if (body != null) {
                for (String line : body.split("\n")) {
                    String trimmed = line.trim();
                    if (!trimmed.isEmpty()) {
                        versions.add(trimmed);
                    }
                }
            }
            if (versions.isEmpty()) {
                log.warn("Go module proxy returned no parseable version entries for module={}", modulePath);
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("Go module proxy has no entry for module={}", modulePath);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("Go module proxy fetch failed for module={}", modulePath, e);
            return Optional.empty();
        }
    }

    /**
     * Go's module escaping rule: each uppercase letter is replaced by an exclamation mark
     * followed by its lowercase equivalent, so that module paths remain safe on
     * case-insensitive filesystems/URLs.
     */
    private static String escapeModulePath(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            if (Character.isUpperCase(c)) {
                sb.append('!').append(Character.toLowerCase(c));
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
