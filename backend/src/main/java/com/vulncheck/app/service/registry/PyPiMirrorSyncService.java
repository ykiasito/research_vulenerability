package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.LogSanitizer;
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
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'pypi'} from
 * PyPI's Simple API (PEP 691 JSON) — closed-mode backlog item 176 rollout (PyPI), same pattern as the
 * crates.io/RubyGems/Packagist/Hex mirrors (see {@code CratesIoMirrorSyncService}'s class javadoc).
 * {@link PyPiRegistryClient} reads from that table when {@code app.closed-mode.pypi-mirror-enabled}
 * is on; this service is the only writer.
 *
 * <p><b>Simple API endpoint shape</b> (confirmed live 2026-09-02 against real packages — requests,
 * django-extensions — rather than assumed from {@code docs/spec/closed-mode-plan.md}'s §5-2 entry
 * alone, per this project's own repeated "verify the actual API, not just the write-up" lesson):
 * {@code GET https://pypi.org/simple/{normalized-name}/} with header {@code Accept:
 * application/vnd.pypi.simple.v1+json} (PEP 691) returns JSON shaped {@code {"name": "...",
 * "versions": ["...", ...], "files": [...], ...}}. Two live-confirmed gotchas:
 * <ul>
 *   <li><b>The Accept header is mandatory.</b> Without it (including with a generic {@code
 *   application/json, application/*+json} Accept list, which is what {@link RestClient} would send
 *   by default for a {@code JsonNode} response type) PyPI instead returns the legacy HTML index page
 *   (200, {@code text/html}), not JSON — confirmed live. This service therefore sets the header
 *   explicitly on every request rather than relying on the client's default content negotiation.</li>
 *   <li><b>The name in the URL must already be PEP 503 normalized</b> ({@link
 *   OsvPackageNameNormalizer#normalize} already implements PEP 503 for {@code pypi} — see its own
 *   javadoc) — a non-normalized name (mixed case, {@code _}/{@code .} instead of {@code -}, e.g. the
 *   literal {@code Django-Extensions}) 301-redirects to the normalized path instead of answering
 *   directly (confirmed live). Pre-normalizing avoids relying on redirect-following at all. {@link
 *   #fetchVersions} still uses the same {@code UriComponentsBuilder.path(...)} technique (not a
 *   {@code {name}} URI template placeholder) as {@code PackagistMirrorSyncService#fetchVersions} —
 *   not to avoid percent-encoding a literal {@code .} (PEP 503 normalization folds every run of
 *   {@code .}/{@code -}/{@code _} into a single {@code -}, so a normalized name never contains one —
 *   {@code "zope.interface"} normalizes to {@code "zope-interface"}, the same rationale {@link
 *   RegistryMirrorPackageNameValidator}'s class javadoc gives for excluding pypi from its checks), but
 *   simply to keep the same path-building shape (including the trailing {@code /} the Simple API
 *   path requires) as {@code PackagistMirrorSyncService#fetchVersions} already uses.</li>
 * </ul>
 * A package that doesn't exist returns a plain 404 with a small text body, not JSON — same as every
 * other mirror sync here. PEP 691's {@code versions} array is already the deduplicated list of every
 * version PyPI has ever published for the project (PEP 700 extension), so no separate per-file
 * de-duplication step is needed the way {@link PackagistMirrorSyncService}/{@link HexMirrorSyncService}
 * have to walk a per-release array.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the other
 * mirrors: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO UPDATE, see {@link
 * RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so calling it once with
 * a seed list is the bulk ingestion and calling it again later is the differential re-sync. PyPI does
 * publish a full project-name enumeration via the same Simple API's index page ({@code GET
 * https://pypi.org/simple/} with the PEP 691 Accept header, ~650k entries), but — same as the other
 * mirrors here — this rollout's scope is a curated package-name list (golden-300 / names actually seen
 * in real job CSVs), not literal full-registry enumeration, so that index page is not consumed here.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PyPiMirrorSyncService {

    private static final String ECOSYSTEM = "pypi";
    private static final String SIMPLE_API_ACCEPT = "application/vnd.pypi.simple.v1+json";

    private final RestClient pypiSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on PyPI (404) or
     *                    whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s pypi pacing). Never partially writes a package's row — {@link
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
        log.info("pypi mirror sync: {}/{} package names synced ({} not found on pypi or fetch/parse "
                + "failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the other mirror syncs. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            String normalizedName = OsvPackageNameNormalizer.normalize(ECOSYSTEM, packageName);
            // Same UriComponentsBuilder.path(...) technique (not a {name} URI template
            // substitution) as PackagistMirrorSyncService#fetchVersions uses, but for a different
            // reason: a normalized pypi name can never contain a "." (OsvPackageNameNormalizer
            // folds every run of "."/"-"/"_" into a single "-", e.g. "zope.interface" ->
            // "zope-interface" -- same rationale RegistryMirrorPackageNameValidator's class javadoc
            // gives for excluding pypi). This just keeps the same path-building shape (including the
            // trailing "/" the Simple API path requires) as the Packagist sync uses.
            URI uri = UriComponentsBuilder.fromUriString("https://pypi.org/")
                    .path("simple/" + normalizedName + "/")
                    .build()
                    .toUri();
            JsonNode body = pypiSyncRestClient.get()
                    .uri(uri)
                    .header("Accept", SIMPLE_API_ACCEPT)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null) {
                return Optional.empty();
            }
            JsonNode versionsNode = body.path("versions");
            if (!versionsNode.isArray() || versionsNode.isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (JsonNode entry : versionsNode) {
                String version = entry.asText(null);
                if (version != null && !version.isBlank()) {
                    versions.add(version);
                }
            }
            if (versions.isEmpty()) {
                log.warn("PyPI simple index returned a body with no parseable version entries for "
                        + "package={}", LogSanitizer.sanitize(packageName));
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("PyPI simple index has no entry for package={}", LogSanitizer.sanitize(packageName));
            return Optional.empty();
        } catch (Exception e) {
            log.warn("PyPI simple index fetch failed for package={}", LogSanitizer.sanitize(packageName), e);
            return Optional.empty();
        }
    }
}
