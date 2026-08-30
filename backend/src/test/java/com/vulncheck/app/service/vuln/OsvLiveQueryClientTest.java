package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/** Split out of the former {@code OsvVulnerabilitySourceTest} once {@code find()} moved to the
 *  local mirror ({@code docs/spec/osv-mirror-plan.md} §7-2) — this class now covers exactly what
 *  remains live: {@link OsvLiveQueryClient#queryPackage}, the sole surviving caller being {@code
 *  BundledComponentResearchService}. Response shapes mirror OSV.dev's real query API
 *  (https://api.osv.dev/v1/query). */
class OsvLiveQueryClientTest {

    private RestClient.Builder restClientBuilder;
    private MockRestServiceServer server;
    private OsvRateLimiter osvRateLimiter;
    private OsvLiveQueryClient client;

    private static final String OSV_RESPONSE = """
            {
              "vulns": [
                {
                  "id": "GHSA-35jh-r3h4-6jhm",
                  "summary": "Prototype Pollution in lodash",
                  "database_specific": {"severity": "HIGH"},
                  "references": [
                    {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"}
                  ],
                  "affected": [
                    {
                      "package": {"name": "lodash", "ecosystem": "npm"},
                      "ranges": [
                        {"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}
                      ]
                    }
                  ]
                }
              ]
            }
            """;

    @BeforeEach
    void setUp() {
        restClientBuilder = RestClient.builder();
        server = MockRestServiceServer.bindTo(restClientBuilder).build();
        // A mock (rather than OsvRateLimiter.disabledForTesting()) so the wiring test below can
        // verify() it was actually invoked — see this project's prior GHSA rate-limiting gap.
        osvRateLimiter = mock(OsvRateLimiter.class);
        client = new OsvLiveQueryClient(restClientBuilder.build(), osvRateLimiter);
    }

    @Test
    void queryPackagePacesTheCallThroughOsvRateLimiter() {
        server.expect(method(HttpMethod.POST)).andRespond(withSuccess(OSV_RESPONSE, MediaType.APPLICATION_JSON));

        client.queryPackage("npm", "lodash", "4.17.15");

        verify(osvRateLimiter).awaitTurn();
    }

    @Test
    void findsAVulnerabilityAndExtractsFixedVersionForTheMatchingPackage() {
        server.expect(method(HttpMethod.POST))
                .andExpect(requestTo(Matchers.containsString("api.osv.dev")))
                .andRespond(withSuccess(OSV_RESPONSE, MediaType.APPLICATION_JSON));

        SourceResult result = client.queryPackage("npm", "lodash", "4.17.15");

        assertThat(result.succeeded()).isTrue();
        List<VulnFinding> findings = result.findings();
        assertThat(findings).hasSize(1);
        VulnFinding finding = findings.get(0);
        assertThat(finding.cveOrGhsaId()).isEqualTo("GHSA-35jh-r3h4-6jhm");
        assertThat(finding.source()).isEqualTo("osv");
        assertThat(finding.severity()).isEqualTo("HIGH");
        assertThat(finding.description()).isEqualTo("Prototype Pollution in lodash");
        assertThat(finding.fixedVersion()).isEqualTo("4.17.19");
        assertThat(finding.url()).isEqualTo("https://github.com/advisories/GHSA-35jh-r3h4-6jhm");
    }

    @Test
    void fallsBackToOsvDetailUrlWhenNoReferenceIsPresent() {
        String noReferenceResponse = """
                {"vulns":[{"id":"GHSA-xxxx","summary":"x",
                  "affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[]}]}]}
                """;
        server.expect(method(HttpMethod.POST)).andRespond(withSuccess(noReferenceResponse, MediaType.APPLICATION_JSON));

        SourceResult result = client.queryPackage("npm", "lodash", "4.17.15");

        assertThat(result.findings().get(0).url()).isEqualTo("https://osv.dev/vulnerability/GHSA-xxxx");
    }

    @Test
    void returnsFailureOnHttpFailureRatherThanThrowing() {
        server.expect(method(HttpMethod.POST)).andRespond(withServerError());

        SourceResult result = client.queryPackage("npm", "lodash", "4.17.15");

        assertThat(result.succeeded()).isFalse();
        assertThat(result.findings()).isEmpty();
    }
}
