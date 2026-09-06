package com.vulncheck.app.service.registry;

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
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'rubygems'}
 * from RubyGems' public compact index ({@code https://index.rubygems.org/}) — closed-mode backlog
 * item 176, RubyGems rollout (same pattern as the crates.io pilot, see {@code
 * CratesIoMirrorSyncService}'s javadoc). {@link RubyGemsRegistryClient} reads unconditionally from
 * that table (the {@code app.closed-mode.rubygems-mirror-enabled} flag that used to gate this has
 * since been removed); this service is the only writer.
 *
 * <p><b>Compact index shape</b> (confirmed live 2026-09-02 against real gems — rails/rake — rather
 * than assumed from documentation alone, per this project's own repeated "verify the actual API,
 * not just the write-up" lesson): {@code GET https://index.rubygems.org/info/{gem}} returns a
 * plain-text body whose first line is a literal {@code ---} separator, followed by one line per
 * published version: {@code <version> <comma-separated deps>|<comma-separated metadata>} (e.g.
 * {@code "13.0.0 |checksum:...,ruby:>= 2.2,...,created_at:..."} for a version with no dependencies —
 * confirmed there is still a space before the {@code |} even when the deps segment is empty, so
 * splitting each line on its first space reliably isolates the version number regardless). A
 * package that doesn't exist returns a plain 404 with a short text body ({@code "This gem could not
 * be found"}), no JSON. Unlike crates.io's sparse index, RubyGems' {@code /info/{gem}} path has no
 * name-length-dependent directory nesting (no {@code sparseIndexPath}-equivalent needed) — every gem
 * lives directly under {@code /info/}.
 *
 * <p>Only currently-published (non-yanked) versions appear in {@code /info/{gem}} — RubyGems removes
 * a yanked version from this endpoint entirely rather than flagging it in place (contrast crates.io's
 * sparse index, which keeps yanked versions with a {@code "yanked":true} marker), so this mirror
 * naturally cannot include gem versions that have since been pulled; the pre-existing live path
 * ({@code /api/v1/versions/{name}.json}, unchanged) has the same limitation, since RubyGems' own API
 * excludes yanked versions from that endpoint too.
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the
 * crates.io pilot: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO UPDATE,
 * see {@link RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so calling
 * it once with a seed list is the bulk ingestion and calling it again later is the differential
 * re-sync. RubyGems does separately publish a single {@code https://rubygems.org/versions} file
 * (~24MB, confirmed live 2026-09-02) listing every gem name and its versions in one response, which
 * in principle could enumerate the *entire* registry the way crates.io's sparse index cannot — but
 * consuming it is out of scope for this rollout (same "given a curated package-name list" scope as
 * the crates.io pilot), left as a follow-up if this mirror pattern is ever extended toward a literal
 * full-registry mirror.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RubyGemsMirrorSyncService {

    private static final String ECOSYSTEM = "rubygems";

    private final RestClient rubyGemsSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on RubyGems (404)
     *                    or whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s rubygems pacing). Never partially writes a package's row —
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
        log.info("rubygems mirror sync: {}/{} package names synced ({} not found on rubygems or "
                + "fetch/parse failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the crates.io pilot. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            String body = rubyGemsSyncRestClient.get()
                    .uri("https://index.rubygems.org/info/{name}", packageName)
                    .retrieve()
                    .body(String.class);
            if (body == null || body.isBlank()) {
                return Optional.empty();
            }
            List<String> versions = parseVersions(body);
            if (versions.isEmpty()) {
                log.warn("rubygems compact index returned a body with no parseable version lines for "
                        + "package={}", LogSanitizer.sanitize(packageName));
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("rubygems compact index has no entry for package={}", LogSanitizer.sanitize(packageName));
            return Optional.empty();
        } catch (Exception e) {
            log.warn("rubygems compact index fetch failed for package={}", LogSanitizer.sanitize(packageName), e);
            return Optional.empty();
        }
    }

    /**
     * Parses a {@code GET /info/{gem}} response body into its published version list, skipping the
     * leading {@code ---} separator line. Package-private so {@code RubyGemsMirrorSyncServiceTest}
     * can assert on it directly without needing a live/mocked HTTP round trip just to check parsing.
     */
    static List<String> parseVersions(String body) {
        List<String> versions = new ArrayList<>();
        for (String line : body.split("\n")) {
            String trimmed = line.strip();
            if (trimmed.isEmpty() || "---".equals(trimmed)) {
                continue;
            }
            int spaceIndex = trimmed.indexOf(' ');
            String version = spaceIndex >= 0 ? trimmed.substring(0, spaceIndex) : trimmed;
            if (!version.isBlank()) {
                versions.add(version);
            }
        }
        return versions;
    }
}
