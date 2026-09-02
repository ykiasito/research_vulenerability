package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Closed-mode backlog item 176 rollout (PyPI) regression check: for every {@code
 * expected_ecosystem = pypi} row of {@code golden-300.csv} (20 rows as of 2026-09-02), {@link
 * PyPiRegistryClient} must produce the exact same {@link RegistryMatch} whether it answers from the
 * mirror ({@link RegistryPackageMirrorRepository}, mocked here) or the pre-existing live path ({@code
 * https://pypi.org/pypi/{name}/json}, mocked via {@link MockRestServiceServer}).
 *
 * <p>Deliberately does not hit the real PyPI network (neither the live JSON API nor the Simple API
 * mirror-sync endpoint) — same convention as {@link PyPiRegistryClientTest}/{@link
 * PyPiMirrorSyncServiceTest} and this repo's own crates.io/RubyGems/Packagist/Hex mirrors ({@link
 * CratesIoMirrorParityGolden300Test}/{@link RubyGemsMirrorParityGolden300Test}/{@link
 * PackagistMirrorParityGolden300Test}/{@link HexMirrorParityGolden300Test}). Both the mocked live
 * response and the mocked mirror content are fed the exact same version list per row, so this test
 * verifies {@link PyPiRegistryClient}'s two code paths build an identical {@link RegistryMatch} from
 * identical input — not that PyPI's real, live data happens to agree with {@code golden-300.csv}'s
 * ground truth.
 */
class PyPiMirrorParityGolden300Test {

    private record GoldenRow(String productName, String version) {
    }

    @Test
    void mirrorLookupMatchesLiveLookupForEveryPyPiGolden300Row() throws IOException {
        List<GoldenRow> rows = loadPyPiRows();
        // Sanity check on the fixture itself: if golden-300.csv's pypi rows ever change, this test
        // should fail loudly rather than silently start covering fewer/more/different rows.
        assertThat(rows).hasSize(20);

        RestClient.Builder builder = RestClient.builder();
        MockRestServiceServer server = MockRestServiceServer.bindTo(builder).build();
        RestClient restClient = builder.build();
        RegistryPackageMirrorRepository mirrorRepository = Mockito.mock(RegistryPackageMirrorRepository.class);
        Mockito.when(mirrorRepository.hasAnyEntries("pypi")).thenReturn(true);

        PyPiRegistryClient liveClient = new PyPiRegistryClient(
                restClient, ExternalRegistryRateLimiter.disabledForTesting(), mirrorRepository);
        PyPiRegistryClient mirrorClient = new PyPiRegistryClient(
                restClient, ExternalRegistryRateLimiter.disabledForTesting(), mirrorRepository);
        ReflectionTestUtils.setField(mirrorClient, "mirrorEnabled", true);

        for (GoldenRow row : rows) {
            server.expect(method(HttpMethod.GET))
                    .andRespond(withSuccess(
                            "{\"info\":{\"name\":\"" + row.productName() + "\"},\"releases\":{\""
                                    + row.version() + "\":[]}}",
                            MediaType.APPLICATION_JSON));
            String normalizedName = OsvPackageNameNormalizer.normalize("pypi", row.productName());
            Mockito.when(mirrorRepository.findVersions("pypi", normalizedName))
                    .thenReturn(List.of(row.version()));
        }

        for (GoldenRow row : rows) {
            Optional<RegistryMatch> liveResult = liveClient.lookup(row.productName(), row.version());
            Optional<RegistryMatch> mirrorResult = mirrorClient.lookup(row.productName(), row.version());

            assertThat(liveResult).as("live lookup for %s", row).isPresent();
            assertThat(mirrorResult).as("mirror lookup for %s", row).isPresent();
            assertThat(mirrorResult.get().ecosystem()).isEqualTo(liveResult.get().ecosystem());
            assertThat(mirrorResult.get().packageName()).isEqualTo(liveResult.get().packageName());
            assertThat(mirrorResult.get().purl()).isEqualTo(liveResult.get().purl());
            assertThat(mirrorResult.get().exactVersionConfirmed()).isEqualTo(liveResult.get().exactVersionConfirmed());
            assertThat(mirrorResult.get().confidence()).isEqualByComparingTo(liveResult.get().confidence());
        }
        server.verify();
    }

    private List<GoldenRow> loadPyPiRows() throws IOException {
        List<GoldenRow> rows = new ArrayList<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv");
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                if ("pypi".equals(record.get("expected_ecosystem"))) {
                    rows.add(new GoldenRow(record.get("product_name"), record.get("version")));
                }
            }
        }
        return rows;
    }
}
