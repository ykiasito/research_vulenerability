package com.vulncheck.app.service.cveorg;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.CveOrgAffectedProductRepository;
import com.vulncheck.app.repository.CveOrgRecordRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import java.io.IOException;
import java.net.URI;
import java.net.URLConnection;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Regression coverage for backlog items 359/361/362: {@link CveOrgSyncService#download} takes a
 * URL parsed from GitHub's {@code browser_download_url} (not a hardcoded constant), so it must
 * validate the scheme/host and re-validate any redirect target the same way the sibling sync
 * services ({@code OsvSyncService}, {@code GhsaSyncService}, both CSAF sync services) already do,
 * and must not leave the read timeout unbounded. These tests exercise {@link
 * CveOrgSyncService#validatedUri}, {@link CveOrgSyncService#resolveRedirectTarget}, and {@link
 * CveOrgSyncService#openConnection} directly — all three are package-private specifically so this
 * test can call them without needing a live network call, matching {@code
 * RestClientConfig#simpleRequestFactory}'s established convention for this kind of seam.
 */
@ExtendWith(MockitoExtension.class)
class CveOrgSyncServiceTest {

    @Mock
    private CveOrgRecordRepository cveOrgRecordRepository;
    @Mock
    private CveOrgAffectedProductRepository cveOrgAffectedProductRepository;
    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;

    private CveOrgSyncService service(RestClient restClient) {
        return new CveOrgSyncService(
                restClient, cveOrgRecordRepository, cveOrgAffectedProductRepository, cveOrgSyncStateRepository);
    }

    private RestClient.Builder builder() {
        return RestClient.builder();
    }

    // ----------------------------------------------------------------- validatedUri ------------

    @Test
    void validatedUriRejectsNonHttpsScheme() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("http://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriRejectsDisallowedHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://evil.example.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNull();
    }

    @Test
    void validatedUriAcceptsAllowlistedGitHubHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("github.com");
    }

    @Test
    void validatedUriAcceptsAllowlistedAssetCdnHost() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("https://objects.githubusercontent.com/github-production-release-asset/x");

        assertThat(result).isNotNull();
        assertThat(result.getHost()).isEqualTo("objects.githubusercontent.com");
    }

    @Test
    void validatedUriRejectsUnparseableUrl() {
        CveOrgSyncService service = service(builder().build());

        URI result = service.validatedUri("not a url at all");

        assertThat(result).isNull();
    }

    // ------------------------------------------------------------ resolveRedirectTarget --------

    @Test
    void resolveRedirectTargetReturnsOriginalUriWhenNoRedirect() throws IOException {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString())).andRespond(withSuccess());

        URI resolved = service.resolveRedirectTarget(uri);

        assertThat(resolved).isEqualTo(uri);
        server.verify();
    }

    @Test
    void resolveRedirectTargetFollowsAndRevalidatesAnAllowlistedRedirect() throws IOException {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");
        String redirectTarget = "https://objects.githubusercontent.com/github-production-release-asset/x";

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", redirectTarget));

        URI resolved = service.resolveRedirectTarget(uri);

        assertThat(resolved.toString()).isEqualTo(redirectTarget);
        server.verify();
    }

    @Test
    void resolveRedirectTargetRejectsARedirectToADisallowedHost() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString()))
                .andRespond(withStatus(HttpStatus.FOUND).header("Location", "https://evil.example.com/steal-me"));

        assertThatThrownBy(() -> service.resolveRedirectTarget(uri))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("rejected non-allowlisted redirect target");
    }

    @Test
    void resolveRedirectTargetRejectsARedirectMissingTheLocationHeader() {
        RestClient.Builder builder = builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        CveOrgSyncService service = service(builder.build());
        URI uri = URI.create("https://github.com/CVEProject/cvelistV5/releases/download/x/y.zip");

        server.expect(requestTo(uri.toString())).andRespond(withStatus(HttpStatus.FOUND));

        assertThatThrownBy(() -> service.resolveRedirectTarget(uri))
                .isInstanceOf(IOException.class)
                .hasMessageContaining("no Location header");
    }

    // -------------------------------------------------------------------- openConnection -------

    @Test
    void openConnectionSetsAFiniteReadTimeoutInsteadOfUnbounded() throws IOException {
        CveOrgSyncService service = service(builder().build());

        URLConnection connection = service.openConnection(URI.create("https://github.com/whatever"));

        assertThat(connection.getReadTimeout())
                .isGreaterThan(0)
                .isEqualTo((int) Duration.ofSeconds(30).toMillis());
    }

    @Test
    void openConnectionSetsATenSecondConnectTimeout() throws IOException {
        CveOrgSyncService service = service(builder().build());

        URLConnection connection = service.openConnection(URI.create("https://github.com/whatever"));

        assertThat(connection.getConnectTimeout()).isEqualTo((int) Duration.ofSeconds(10).toMillis());
    }

    @Test
    void openConnectionSetsTheDescriptiveUserAgent() throws IOException {
        CveOrgSyncService service = service(builder().build());

        URLConnection connection = service.openConnection(URI.create("https://github.com/whatever"));

        assertThat(connection.getRequestProperty("User-Agent")).isEqualTo("vulncheck-server/0.1 (cve.org sync)");
    }
}
