package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'crates.io'}
 * from crates.io's public sparse index ({@code https://index.crates.io/}) — closed-mode backlog
 * item 176 pilot. {@link CratesIoRegistryClient} reads from that table when {@code
 * app.closed-mode.crates-io-mirror-enabled} is on; this service is the only writer.
 *
 * <p><b>Sparse index shape</b> (confirmed live 2026-09-02, not assumed from documentation alone —
 * this project has previously been burned by an untested Go-registry API assumption): {@code GET
 * https://index.crates.io/{path}} returns newline-delimited JSON, one object per published version
 * (including yanked ones — this pilot mirrors {@link CratesIoRegistryClient}'s existing live
 * behavior of not filtering yanked versions out, since the live {@code /versions} API endpoint it
 * queries doesn't filter them either), each with at least a {@code name}/{@code vers} field. A
 * package that doesn't exist returns a plain 404, no body. {@code path} depends only on the
 * package's own name length (see {@link #sparseIndexPath}), not on any request parameter.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>: {@link #syncPackages} always
 * re-fetches and upserts (ON CONFLICT ... DO UPDATE, see {@link
 * RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so calling it once
 * with a large initial seed list *is* the bulk ingestion, and calling it again later with the same
 * (or a grown) list *is* the differential re-sync — there is no separate delta/changelog feed on the
 * sparse index to consume instead. One real limitation worth flagging explicitly: the sparse index
 * has no "list every package that exists" endpoint at all (only "does this one specific name exist,
 * and if so what versions"), so this pilot cannot mirror the *entire* crates.io registry (140k+
 * packages) on its own — only whichever package names a caller supplies (e.g. the golden-300 set, or
 * names actually seen in real job CSVs). A literal full-registry mirror would need crates.io's
 * separate DB dump (https://static.crates.io/db-dump.tar.gz) to first enumerate every package name,
 * which is out of scope for this pilot (see the task's own "crates.io一エコシステムに限定" instruction) —
 * left as a follow-up if/when this mirror pattern is extended beyond the pilot.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CratesIoMirrorSyncService {

    private static final String ECOSYSTEM = "crates.io";

    private final RestClient cratesIoSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;
    private final ObjectMapper objectMapper;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on crates.io (404)
     *                    or whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name; not split into separate counters here
     *                    since callers of this pilot-scope method don't currently need to react to
     *                    the two cases differently (a manual re-run either way).
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (the
     *  pilot's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s crates.io pacing, ~1 req/sec, so a few hundred names take a few
     *  minutes). Never partially writes a package's row — {@link #fetchVersions} either returns the
     *  package's full version list or nothing for it. */
    public SyncOutcome syncPackages(List<String> packageNames) {
        int synced = 0;
        int unresolved = 0;
        Map<String, List<String>> batch = new LinkedHashMap<>();
        for (String rawName : packageNames) {
            if (rawName == null || rawName.isBlank()) {
                continue;
            }
            String packageName = rawName.trim();
            // Closed-mode backlog item 184 REVISE: reject a package name outside crates.io's own
            // naming grammar before rateLimiter.awaitTurn below, so a name that's going to be
            // rejected anyway never consumes a rate-limit slot at the expense of delaying the next
            // (possibly valid) name in the batch. See RegistryMirrorPackageNameValidator's class
            // javadoc for why this check is needed even though this method's caller already sits
            // behind RegistryMirrorSyncService#isValidSeedName's wider, upload-time gate.
            if (!RegistryMirrorPackageNameValidator.isValidSimpleName(packageName)) {
                log.warn("crates.io mirror sync rejected package name as invalid for URL assembly: "
                        + "package={}", LogSanitizer.sanitize(packageName));
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
        log.info("crates.io mirror sync: {}/{} package names synced ({} not found on crates.io or "
                + "fetch/parse failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), since this pilot has no need yet to distinguish "confirmed absent" from
     *  "transient failure, retry later" (a manual re-run of {@link #syncPackages} covers both). */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            // packageName is already validated by RegistryMirrorPackageNameValidator in
            // syncPackages (closed-mode backlog item 184 REVISE), before this method is ever called.
            // Not .uri("https://index.crates.io/{path}", sparseIndexPath(...)): RestClient treats a
            // single {placeholder} substitution as one opaque path *segment* and percent-encodes any
            // "/" inside the substituted value (confirmed: produced .../se%2Frd%2Fserde instead of
            // .../se/rd/serde against a MockRestServiceServer expectation) -- sparseIndexPath's own
            // "/" separators must stay literal, so the path is built via UriComponentsBuilder.path
            // instead, which does not re-encode a literal path string passed to it.
            URI uri = UriComponentsBuilder.fromUriString("https://index.crates.io/")
                    .path(sparseIndexPath(packageName))
                    .build()
                    .toUri();
            String body = cratesIoSyncRestClient.get()
                    .uri(uri)
                    .retrieve()
                    .body(String.class);
            if (body == null || body.isBlank()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (String line : body.split("\n")) {
                if (line.isBlank()) {
                    continue;
                }
                JsonNode node = objectMapper.readTree(line);
                String num = node.path("vers").asText(null);
                if (num != null) {
                    versions.add(num);
                }
            }
            if (versions.isEmpty()) {
                log.warn("crates.io sparse index returned a body with no parseable version lines for "
                        + "package={}", LogSanitizer.sanitize(packageName));
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("crates.io sparse index has no entry for package={}", LogSanitizer.sanitize(packageName));
            return Optional.empty();
        } catch (Exception e) {
            log.warn("crates.io sparse index fetch failed for package={}", LogSanitizer.sanitize(packageName), e);
            return Optional.empty();
        }
    }

    /**
     * crates.io's sparse-index directory layout, confirmed live 2026-09-02 against real 1/2/3/4+
     * character package names (serde/rand/abc/x-style probes) rather than assumed from documentation
     * alone: 1-character names live directly under {@code 1/}, 2-character under {@code 2/},
     * 3-character under {@code 3/{first-char}/}, and every longer name under {@code
     * {first-2-chars}/{next-2-chars}/}.
     *
     * <p>Deliberately does NOT apply {@link OsvPackageNameNormalizer}'s "-"/"_" folding here (unlike
     * the mirror table's own storage key) — the sparse index path must match the crate's actual
     * registered spelling exactly, so callers must already be passing in a real, correctly-spelled
     * crates.io package name (e.g. from a curated seed list or an already-confirmed live match), not
     * an arbitrary user-typed product name.
     *
     * <p>Package-private so {@code CratesIoMirrorSyncServiceTest} can assert on it directly without
     * needing a live/mocked HTTP round trip just to check path construction.
     */
    static String sparseIndexPath(String packageName) {
        int len = packageName.length();
        if (len == 1) {
            return "1/" + packageName;
        }
        if (len == 2) {
            return "2/" + packageName;
        }
        if (len == 3) {
            return "3/" + packageName.charAt(0) + "/" + packageName;
        }
        return packageName.substring(0, 2) + "/" + packageName.substring(2, 4) + "/" + packageName;
    }
}
