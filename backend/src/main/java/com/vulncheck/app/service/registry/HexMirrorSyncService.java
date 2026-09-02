package com.vulncheck.app.service.registry;

import com.fasterxml.jackson.databind.JsonNode;
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
 * Populates/refreshes the {@code registry_package_mirror} table for {@code ecosystem = 'hex'} from
 * Hex.pm's public package API ({@code https://hex.pm/api/packages/{name}}) — closed-mode backlog
 * item 176 rollout (Hex), same pattern as the crates.io/RubyGems pilots (see {@link
 * CratesIoMirrorSyncService}/{@link RubyGemsMirrorSyncService}'s javadoc). {@link HexRegistryClient}
 * reads unconditionally from that table (the {@code app.closed-mode.hex-mirror-enabled} flag that
 * used to gate this has since been removed — {@link HexRegistryClient#lookup} always calls {@code
 * lookupViaMirror}); this service is the only writer.
 *
 * <p><b>Two Hex.pm endpoints exist; this service deliberately uses the simpler one</b> (confirmed
 * live 2026-09-02, not assumed from {@code docs/spec/closed-mode-plan.md}'s Web-research-based §5-2
 * entry alone — this project has repeatedly been burned by exactly that gap, both in the crates.io
 * and RubyGems pilots):
 * <ul>
 *   <li>{@code GET https://hex.pm/api/packages/{name}} (used here, and already what the pre-existing
 *   live path in {@link HexRegistryClient} has always used) returns plain JSON with a {@code
 *   releases[].version} array — confirmed live against {@code jason} and {@code phoenix}, identical
 *   shape to the live client's existing parsing. A package that doesn't exist returns a plain 404.</li>
 *   <li>{@code GET https://repo.hex.pm/packages/{name}} is the "registry protobuf" endpoint the plan
 *   references ({@code mix hex.registry build}'s target format) — confirmed live to return a
 *   gzip-compressed protobuf-encoded {@code Signed}-wrapped {@code Package} message (verified the raw
 *   bytes start with the gzip magic number {@code 1f 8b}, and the decompressed body's varint/wire-type
 *   framing decodes as it should). Decoding it fully would require adding a new {@code protobuf-java}
 *   dependency (not currently in {@code backend/pom.xml}) plus hand-writing (or vendoring) the {@code
 *   .proto} schema for Hex's {@code Elixir.Hex.Registry.Message.{Signed,Package}} messages, and
 *   verifying/discarding the outer signature. That is real added complexity for a mirror whose scope
 *   (per this rollout's own task brief) is a curated package-name list, not a literal from-scratch
 *   full-registry mirror — the JSON API returns the exact same (name, versions) tuple this table
 *   needs, with zero new dependencies and using the same endpoint the live path already trusts. Left
 *   as a follow-up (protobuf decode via {@code repo.hex.pm}) only if this pattern is ever extended
 *   toward literal full-registry enumeration, where the JSON API's per-package request shape (no bulk
 *   listing endpoint, same limitation as crates.io's sparse index) would become the bottleneck.</li>
 * </ul>
 *
 * <p><b>"Bulk" vs "differential" sync are the same operation here</b>, same rationale as the
 * crates.io/RubyGems pilots: {@link #syncPackages} always re-fetches and upserts (ON CONFLICT ... DO
 * UPDATE, see {@link RegistryPackageMirrorRepository#upsertBatch}) every package name it's given, so
 * calling it once with a seed list is the bulk ingestion and calling it again later is the
 * differential re-sync. Hex.pm has no separate delta/changelog feed exposed on the JSON API to
 * consume instead, and (per the endpoint comparison above) this rollout does not attempt the
 * protobuf registry's own diff format either.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class HexMirrorSyncService {

    private static final String ECOSYSTEM = "hex";

    private final RestClient hexSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @param synced number of requested package names that resolved to at least one published
     *               version and were written to the mirror.
     * @param unresolved number of requested package names that either don't exist on Hex.pm (404) or
     *                    whose fetch/parse failed — see per-package log lines (level varies) for
     *                    which case applied to which name.
     */
    public record SyncOutcome(int synced, int unresolved) {
    }

    /** Best-effort, one request per package name — safe to call with a small hand-picked list (this
     *  rollout's practical entry point) or a larger one (still bounded by {@link
     *  ExternalRegistryRateLimiter}'s hex pacing). Never partially writes a package's row — {@link
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
        log.info("hex mirror sync: {}/{} package names synced ({} not found on hex.pm or fetch/parse "
                + "failed — see preceding log lines)", synced, packageNames.size(), unresolved);
        return new SyncOutcome(synced, unresolved);
    }

    /** Empty when the package doesn't exist (404) or the request/parse failed — both cases are
     *  logged individually and folded into {@code unresolved} by the only caller ({@link
     *  #syncPackages}), same as the crates.io/RubyGems pilots. */
    private Optional<List<String>> fetchVersions(String packageName) {
        try {
            JsonNode body = hexSyncRestClient.get()
                    .uri("https://hex.pm/api/packages/{name}", packageName)
                    .retrieve()
                    .body(JsonNode.class);
            if (body == null || !body.path("releases").isArray() || body.path("releases").isEmpty()) {
                return Optional.empty();
            }
            List<String> versions = new ArrayList<>();
            for (JsonNode release : body.path("releases")) {
                String releaseVersion = release.path("version").asText(null);
                if (releaseVersion != null && !releaseVersion.isBlank()) {
                    versions.add(releaseVersion);
                }
            }
            if (versions.isEmpty()) {
                log.warn("hex.pm returned a package body with no parseable release versions for "
                        + "package={}", packageName);
                return Optional.empty();
            }
            return Optional.of(versions);
        } catch (HttpClientErrorException.NotFound e) {
            log.debug("hex.pm has no entry for package={}", packageName);
            return Optional.empty();
        } catch (Exception e) {
            log.warn("hex.pm package fetch failed for package={}", packageName, e);
            return Optional.empty();
        }
    }
}
