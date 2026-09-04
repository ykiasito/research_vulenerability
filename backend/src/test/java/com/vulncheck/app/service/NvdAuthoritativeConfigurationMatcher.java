package com.vulncheck.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.service.nvd.CpeUtils;
import java.util.ArrayList;
import java.util.List;

/**
 * Pure, DB/network-free predicate extracted from {@code NvdMirrorAbVerificationRunner} (closed-mode
 * backlog item 261/B7, 2026-09-04) when that class was deleted outright: it was a real-dev-DB/live-NVD
 * A/B verification harness (round 5 already ran to completion with {@code gatePassed=true}, see
 * {@code docs/spec/closed-mode-backlog.md} item 241's history for that measurement) whose sole
 * remaining production-adjacent dependency, a {@code @Autowired RestClient externalApiRestClient}
 * field, could no longer resolve to any bean once item 263 deleted
 * {@code RestClientConfig#externalApiRestClient} outright — closed-mode's own "physical deletion over
 * flag-gating" philosophy (§3-4) argues against keeping a test-scope live-NVD-egress harness alive
 * (even a disabled one) once the production capability it exercised is gone. This class preserves the
 * one piece of that harness with real, still-useful standalone coverage: {@link
 * #authoritativeConfigurationsCover}, the pure predicate deciding whether NVD's own authoritative
 * {@code ?cveId=} {@code configurations} JSON covers a queried (part, vendor, product, version) — see
 * {@link NvdAuthoritativeConfigurationMatcherTest} for its fixture-based unit coverage.
 */
final class NvdAuthoritativeConfigurationMatcher {

    private NvdAuthoritativeConfigurationMatcher() {
    }

    /** Does the NVD authoritative {@code ?cveId=} response's {@code configurations} tree contain a
     *  {@code cpeMatch} for the given (part, vendor, product) whose version-applicability covers
     *  {@code itemVersion}? OR-only, fail-closed-on-{@code -} semantics, delegating to {@link
     *  CpeUtils#versionInRange}. */
    static boolean authoritativeConfigurationsCover(JsonNode configurations, String part, String vendor,
            String product, String itemVersion) {
        for (JsonNode cpeMatch : matchingCriteriaNodes(configurations, part, vendor, product)) {
            String criteriaVersion = CpeUtils.parseVersion(cpeMatch.path("criteria").asText(""));
            if (CpeUtils.versionInRange(itemVersion, criteriaVersion,
                    cpeMatch.path("versionStartIncluding").asText(null),
                    cpeMatch.path("versionStartExcluding").asText(null),
                    cpeMatch.path("versionEndIncluding").asText(null),
                    cpeMatch.path("versionEndExcluding").asText(null))) {
                return true;
            }
        }
        return false;
    }

    /** Every {@code cpeMatch} node across {@code configurations[].nodes[]} whose own {@code criteria}
     *  parses to the given (part, vendor, product) — regardless of version applicability. */
    private static List<JsonNode> matchingCriteriaNodes(JsonNode configurations, String part, String vendor,
            String product) {
        List<JsonNode> result = new ArrayList<>();
        if (configurations == null || configurations.isMissingNode() || configurations.isNull()) {
            return result;
        }
        for (JsonNode config : configurations) {
            for (JsonNode node : config.path("nodes")) {
                for (JsonNode cpeMatch : node.path("cpeMatch")) {
                    List<String> segments = splitCpeSegments(cpeMatch.path("criteria").asText(""));
                    if (segments.size() > 4 && part.equals(segments.get(2)) && vendor.equals(segments.get(3))
                            && product.equals(segments.get(4))) {
                        result.add(cpeMatch);
                    }
                }
            }
        }
        return result;
    }

    /** Escape-aware CPE 2.3 segment split — a deliberate duplicate of {@code CpeUtils}'s own private
     *  {@code splitCpeSegments} (that method is private on {@code CpeUtils}), same rationale as the
     *  deleted harness this class was extracted from: don't have the thing under test lean on the code
     *  that produced its own input. */
    private static List<String> splitCpeSegments(String cpeString) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < cpeString.length(); i++) {
            char c = cpeString.charAt(i);
            if (c == '\\' && i + 1 < cpeString.length()) {
                current.append(c).append(cpeString.charAt(i + 1));
                i++;
            } else if (c == ':') {
                segments.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        segments.add(current.toString());
        return segments;
    }
}
