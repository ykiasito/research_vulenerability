package com.vulncheck.app;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Test;

/**
 * Backlog item 325: {@code golden300-cpe-and-control-subset.csv} (read by {@link
 * com.vulncheck.app.service.VendorProductExactMatchFallbackGolden300Test}) is a hand-derived
 * projection of a subset of {@code golden-300.csv}'s rows, generated once (2026-09-05) rather than
 * mechanically kept in sync with its source. {@code FixtureDirectoryParityTest} (item 321) does not
 * cover it: that test only guards {@code backend/src/test/resources/} vs {@code test-data/} copies
 * of the *same-named* file, and this subset has no {@code test-data/} counterpart at all. That gap
 * let this subset's Blender/Rufus rows silently keep their pre-item-320 {@code expected_outcome}
 * label after item 320 corrected {@code golden-300.csv}'s own ground truth for those two products --
 * a peer reviewer, not a test, caught the drift by hand during item 320's review.
 *
 * <p>This test closes that gap generically: for every row in the subset, it looks up the
 * same-keyed {@code (product_name, version)} row in {@code golden-300.csv} and asserts every
 * column except {@code product_name}/{@code version} (the join key itself) and {@code
 * ground_truth_source} (allowed -- and expected -- to differ; the subset's rows document their own
 * item-320 correction history in prose there, see e.g. its Blender/Rufus rows) is identical between
 * the two copies. A subset row whose key has no match in {@code golden-300.csv} at all is also a
 * failure -- that would mean the subset drifted to reference a product/version pairing the source of
 * truth no longer has.
 *
 * <p>Unlike {@code FixtureDirectoryParityTest}, both files live under the same {@code
 * backend/src/test/resources/} directory and are always present on the test classpath, so no
 * repo-root-walking / narrow-Docker-mount fallback is needed here -- this test is never skipped, and
 * (like {@code FixtureDirectoryParityTest}) it is never {@code @Disabled}.
 */
class GoldenSubsetFixtureLabelParityTest {

    private static final String GOLDEN_CSV = "golden-300.csv";
    private static final String SUBSET_CSV = "golden300-cpe-and-control-subset.csv";
    private static final Set<String> JOIN_KEY_OR_PROVENANCE_COLUMNS =
            Set.of("product_name", "version", "ground_truth_source");

    @Test
    void subsetRowsCarryTheSameLabelsAsGolden300() throws IOException {
        Map<String, CSVRecord> goldenByKey = new HashMap<>();
        List<String> goldenHeaders;
        try (InputStream in = openClasspathResource(GOLDEN_CSV);
                CSVParser parser = CSVParser.parse(new InputStreamReader(in, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            goldenHeaders = parser.getHeaderNames();
            for (CSVRecord record : parser) {
                goldenByKey.put(key(record.get("product_name"), record.get("version")), record);
            }
        }

        List<String> missingKeys = new ArrayList<>();
        List<String> mismatches = new ArrayList<>();
        int subsetRowCount = 0;
        try (InputStream in = openClasspathResource(SUBSET_CSV);
                CSVParser parser = CSVParser.parse(new InputStreamReader(in, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            assertThat(parser.getHeaderNames())
                    .as("golden300-cpe-and-control-subset.csv column structure must match golden-300.csv")
                    .isEqualTo(goldenHeaders);

            for (CSVRecord subsetRecord : parser) {
                subsetRowCount++;
                String recordKey = key(subsetRecord.get("product_name"), subsetRecord.get("version"));
                CSVRecord goldenRecord = goldenByKey.get(recordKey);
                if (goldenRecord == null) {
                    missingKeys.add(recordKey);
                    continue;
                }
                for (String column : goldenHeaders) {
                    if (JOIN_KEY_OR_PROVENANCE_COLUMNS.contains(column)) {
                        continue;
                    }
                    String subsetValue = subsetRecord.get(column);
                    String goldenValue = goldenRecord.get(column);
                    if (!subsetValue.equals(goldenValue)) {
                        mismatches.add(recordKey + ": column '" + column + "' differs (subset='"
                                + subsetValue + "', golden-300='" + goldenValue + "')");
                    }
                }
            }
        }

        assertThat(subsetRowCount).as("sanity check: subset CSV must not be empty").isGreaterThan(0);

        if (!missingKeys.isEmpty() || !mismatches.isEmpty()) {
            fail("golden300-cpe-and-control-subset.csv has drifted from golden-300.csv. "
                    + "Row keys with no golden-300.csv match: " + missingKeys + ". "
                    + "Label mismatches: " + mismatches);
        }
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }

    private static InputStream openClasspathResource(String name) {
        InputStream in = GoldenSubsetFixtureLabelParityTest.class.getClassLoader().getResourceAsStream(name);
        assertThat(in).as("classpath resource '%s' must exist", name).isNotNull();
        return in;
    }
}
