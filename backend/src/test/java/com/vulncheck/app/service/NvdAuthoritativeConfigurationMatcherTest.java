package com.vulncheck.app.service;

import static com.vulncheck.app.service.NvdAuthoritativeConfigurationMatcher.authoritativeConfigurationsCover;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

/**
 * Pure, DB/network-free unit coverage for {@link
 * NvdAuthoritativeConfigurationMatcher#authoritativeConfigurationsCover} -- the predicate that
 * decides whether NVD's own authoritative {@code ?cveId=} {@code configurations} JSON actually
 * covers a queried (part, vendor, product, version). Originally developed (as round 5's fix) inside
 * {@code NvdMirrorAbVerificationRunner}, a disabled real-dev-DB/live-NVD A/B verification harness
 * that ran to completion with {@code gatePassed=true} (see {@code
 * docs/spec/closed-mode-backlog.md} item 241's history); that harness was deleted outright in
 * closed-mode backlog item 261/B7 (2026-09-04) once item 263 removed the last {@code RestClient}
 * bean it depended on, and this predicate (the harness's only piece with real standalone value) was
 * extracted here rather than lost along with it.
 *
 * <p>The first fixture below ({@link #CVE_2026_18301_GIMP_RESPONSE}) is shaped after the real
 * {@code ?cveId=CVE-2026-18301} response a senior-reviewer fetched live (non-destructive,
 * unauthenticated) while investigating round 4's one {@code unexplained} liveOnly CVE: a single
 * {@code gimp:gimp} {@code cpeMatch} pinned to a fixed version ({@code 3.2.2}, no range), which is
 * exactly why golden-300's queried {@code 2.10.38} isn't covered -- this is what motivated the round
 * 5 fix in the first place.
 */
class NvdAuthoritativeConfigurationMatcherTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Real shape (fixed version, no range fields) confirmed live for CVE-2026-18301 -- see class
     *  javadoc. */
    private static final String CVE_2026_18301_GIMP_RESPONSE = """
            {
              "vulnerabilities": [
                {
                  "cve": {
                    "id": "CVE-2026-18301",
                    "lastModified": "2026-09-02T10:15:23.123",
                    "configurations": [
                      {
                        "nodes": [
                          {
                            "operator": "OR",
                            "cpeMatch": [
                              {
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:gimp:gimp:3.2.2:*:*:*:*:*:*:*"
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                }
              ]
            }
            """;

    private static final String RANGE_COVERED_RESPONSE = """
            {
              "vulnerabilities": [
                {
                  "cve": {
                    "id": "CVE-2026-99999",
                    "lastModified": "2026-08-01T00:00:00.000",
                    "configurations": [
                      {
                        "nodes": [
                          {
                            "operator": "OR",
                            "cpeMatch": [
                              {
                                "vulnerable": true,
                                "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "5.0.0",
                                "versionEndExcluding": "5.2.0"
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                }
              ]
            }
            """;

    private static final String DASH_SEGMENT_RESPONSE = """
            {
              "vulnerabilities": [
                {
                  "cve": {
                    "id": "CVE-2026-88888",
                    "lastModified": "2026-08-01T00:00:00.000",
                    "configurations": [
                      {
                        "nodes": [
                          {
                            "operator": "AND",
                            "cpeMatch": [
                              {
                                "vulnerable": false,
                                "criteria": "cpe:2.3:o:cisco:ios_xe:-:*:*:*:*:*:*:*"
                              }
                            ]
                          }
                        ]
                      }
                    ]
                  }
                }
              ]
            }
            """;

    private JsonNode configurationsOf(String responseJson) throws Exception {
        JsonNode root = objectMapper.readTree(responseJson);
        return root.path("vulnerabilities").get(0).path("cve").path("configurations");
    }

    @Test
    void fixedVersionCpeMatchDoesNotCoverADifferentQueriedVersion() throws Exception {
        // The exact CVE-2026-18301/GIMP case that motivated this round's fix: the authoritative
        // cpeMatch is pinned to 3.2.2 with no range fields, so golden-300's queried 2.10.38 must not
        // be considered covered -- this is what makes the liveOnly CVE a LIVE_ONLY_FALSE_POSITIVE,
        // not a freshness gap.
        JsonNode configurations = configurationsOf(CVE_2026_18301_GIMP_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "gimp", "gimp", "2.10.38")).isFalse();
    }

    @Test
    void fixedVersionCpeMatchDoesCoverTheExactSameVersion() throws Exception {
        JsonNode configurations = configurationsOf(CVE_2026_18301_GIMP_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "gimp", "gimp", "3.2.2")).isTrue();
    }

    @Test
    void versionEndExcludingRangeCoversAVersionInsideTheRange() throws Exception {
        JsonNode configurations = configurationsOf(RANGE_COVERED_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "acme", "widget", "5.1.0")).isTrue();
    }

    @Test
    void versionEndExcludingRangeDoesNotCoverTheExcludedBoundary() throws Exception {
        JsonNode configurations = configurationsOf(RANGE_COVERED_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "acme", "widget", "5.2.0")).isFalse();
    }

    @Test
    void versionEndExcludingRangeDoesNotCoverAVersionBelowTheStart() throws Exception {
        JsonNode configurations = configurationsOf(RANGE_COVERED_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "acme", "widget", "4.9.0")).isFalse();
    }

    @Test
    void bareDashVersionSegmentFailsClosedRegardlessOfQueriedVersion() throws Exception {
        // A bare '-' is CPE 2.3's own "not applicable" marker, not a synonym for "*" -- must never be
        // treated as unconditionally covering every version (see versionInRange's javadoc).
        JsonNode configurations = configurationsOf(DASH_SEGMENT_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "o", "cisco", "ios_xe", "17.3.1")).isFalse();
        assertThat(authoritativeConfigurationsCover(configurations, "o", "cisco", "ios_xe", "1.0.0")).isFalse();
    }

    @Test
    void noMatchingPartVendorProductMeansNoCoverage() throws Exception {
        JsonNode configurations = configurationsOf(CVE_2026_18301_GIMP_RESPONSE);
        assertThat(authoritativeConfigurationsCover(configurations, "a", "someothervendor", "gimp", "3.2.2"))
                .isFalse();
    }
}
