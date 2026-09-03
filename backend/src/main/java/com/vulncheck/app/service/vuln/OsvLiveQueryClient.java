package com.vulncheck.app.service.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.service.LogSanitizer;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Live, per-call {@code api.osv.dev} queries — split out of {@link OsvVulnerabilitySource} once
 * that class's {@code find()} was switched to the local OSV mirror (plan {@code
 * docs/spec/osv-mirror-plan.md} §7-2/§0(e)). The sole remaining caller is {@code
 * BundledComponentResearchService#adjudicate}, which has no {@code IdentifiedProduct}/{@code
 * ResearchJobItem} at all — just an LLM-extracted "component name" guess (see that class's own
 * javadoc) — so it can't use the mirror's {@code (ecosystem, package_name_normalized)} exact-match
 * lookup, and deliberately keeps querying OSV.dev's own server-side version resolution instead.
 *
 * <p><b>Why this stays live rather than also being mirrored (plan §7-2, two reasons):</b>
 * <ol>
 *   <li>Bundled-component detection is an opt-in, per-item-budget-gated feature (~$0.02/item, {@code
 *       docs/spec/bundled-package-detection-plan.md} §4) that doesn't share Stage2's main-path
 *       throughput constraint — a live call's latency is acceptable here.
 *   <li>The mirror only covers the ~13,600 non-GHSA-reviewed OSV records (plan §3) out of OSV.dev's
 *       full ~48,540 in-scope population (the other ~34,939 being {@code GHSA-*} records this
 *       mirror deliberately excludes, plan §4-1) — and this call site has no {@code
 *       GhsaVulnerabilitySource}-style fallback the way Stage2's {@code find()} does (multiple
 *       sources unioned together). Mirroring this call site would silently drop ~72% of OSV.dev's
 *       real coverage for bundled-component detection specifically.
 * </ol>
 *
 * <p>Every call is paced through {@link OsvRateLimiter} — see that class's javadoc, which as of
 * this split now only needs to account for this single call site's own volume (up to {@code
 * BundledComponentResearchService.MAX_COMPONENTS_PER_ITEM} calls per opted-in item), not both this
 * and Stage2's old per-item {@code find()} traffic.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class OsvLiveQueryClient {

    private static final String OSV_QUERY_API = "https://api.osv.dev/v1/query";
    static final String SOURCE = "osv";

    private final RestClient externalApiRestClient;
    private final OsvRateLimiter osvRateLimiter;

    /**
     * The bare POST-to-{@code api.osv.dev}-and-parse logic — no {@code ResearchJobItem}/{@code
     * IdentifiedProduct} required. {@code osvEcosystem} must already be an OSV-native ecosystem
     * string (e.g. {@code "npm"}/{@code "Maven"} — see {@link OsvEcosystems#INTERNAL_TO_OSV}'s
     * values), not one of this app's internal ecosystem keys.
     */
    public SourceResult queryPackage(String osvEcosystem, String packageName, String version) {
        osvRateLimiter.awaitTurn();
        Map<String, Object> requestBody = Map.of(
                "version", version,
                "package", Map.of(
                        "name", packageName,
                        "ecosystem", osvEcosystem));

        try {
            JsonNode body = externalApiRestClient.post()
                    .uri(OSV_QUERY_API)
                    .body(requestBody)
                    .retrieve()
                    .body(JsonNode.class);

            if (body == null) {
                return SourceResult.success(List.of());
            }

            List<VulnFinding> findings = new ArrayList<>();
            for (JsonNode vulnNode : body.path("vulns")) {
                String id = vulnNode.path("id").asText(null);
                if (id == null) {
                    continue;
                }

                String url = firstReferenceUrl(vulnNode.path("references"));
                if (url == null) {
                    url = "https://osv.dev/vulnerability/" + id;
                }

                findings.add(new VulnFinding(
                        id,
                        SOURCE,
                        vulnNode.path("database_specific").path("severity").asText(null),
                        vulnNode.path("summary").asText(vulnNode.path("details").asText(null)),
                        url,
                        extractFixedVersion(vulnNode.path("affected"), packageName)));
            }
            return SourceResult.success(findings);
        } catch (Exception e) {
            log.warn("OSV query failed for ecosystem={} package={} version={}", osvEcosystem,
                    LogSanitizer.sanitize(packageName), LogSanitizer.sanitize(version), e);
            return SourceResult.failure();
        }
    }

    /** First "fixed" version event from the {@code affected} entry matching our package — OSV's
     *  own structured range data, no extra call. */
    private String extractFixedVersion(JsonNode affected, String packageName) {
        for (JsonNode affectedEntry : affected) {
            String entryPackageName = affectedEntry.path("package").path("name").asText(null);
            if (packageName == null || !packageName.equalsIgnoreCase(entryPackageName)) {
                continue;
            }
            for (JsonNode range : affectedEntry.path("ranges")) {
                for (JsonNode event : range.path("events")) {
                    if (event.has("fixed")) {
                        return event.path("fixed").asText(null);
                    }
                }
            }
        }
        return null;
    }

    private String firstReferenceUrl(JsonNode references) {
        if (references.isArray() && !references.isEmpty()) {
            return references.get(0).path("url").asText(null);
        }
        return null;
    }
}
