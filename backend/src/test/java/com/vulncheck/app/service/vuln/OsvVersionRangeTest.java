package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Table-driven unit tests for {@link OsvVersionRange} — see {@code
 * docs/spec/ghsa-mirror-plan.md} §3-1(B)/§8 item 6. No DB/HTTP involved; pure logic.
 */
class OsvVersionRangeTest {

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void evaluatesAsExpected(String description, String rangeType, String introduced, String fixed,
            String lastAffected, String itemVersion, boolean expectedMatch) {
        boolean actual = OsvVersionRange.matches(rangeType, introduced, fixed, lastAffected, itemVersion);
        assertThat(actual).as(description).isEqualTo(expectedMatch);
    }

    static Stream<Arguments> cases() {
        return Stream.of(
                // --- normal ECOSYSTEM/SEMVER ranges: '<' (fixed) ---------------------------------
                Arguments.of("below the fixed ceiling matches", "ECOSYSTEM", null, "4.17.21", null, "4.17.15", true),
                Arguments.of("exactly at the fixed ceiling does NOT match ('<' is exclusive)",
                        "ECOSYSTEM", null, "4.17.21", null, "4.17.21", false),
                Arguments.of("above the fixed ceiling does not match", "SEMVER", null, "4.17.21", null, "4.17.22", false),

                // --- '<=' (last_affected) is inclusive, unlike fixed ------------------------------
                Arguments.of("exactly at last_affected DOES match ('<=' is inclusive)",
                        "ECOSYSTEM", null, null, "1.1.0", "1.1.0", true),
                Arguments.of("above last_affected does not match", "ECOSYSTEM", null, null, "1.1.0", "1.1.1", false),
                Arguments.of("below last_affected matches", "ECOSYSTEM", null, null, "1.1.0", "1.0.0", true),

                // --- introduced floor ---------------------------------------------------------
                Arguments.of("below the introduced floor does not match",
                        "ECOSYSTEM", "6.0.0", "6.0.7", null, "5.9.9", false),
                Arguments.of("at the introduced floor matches", "ECOSYSTEM", "6.0.0", "6.0.7", null, "6.0.0", true),
                Arguments.of("null introduced means vulnerable from the very first version",
                        "ECOSYSTEM", null, "1.0.0", null, "0.0.1", true),

                // --- unbounded above (no fix yet) -------------------------------------------------
                Arguments.of("unbounded above (both fixed/last_affected null) still matches above the floor",
                        "ECOSYSTEM", "2.0.0", null, null, "999.0.0", true),

                // --- fail-closed: VersionUtils' known "1.0.0-rc1" pre-release weakness ------------
                Arguments.of("a pre-release-suffixed item version fails closed (VersionUtils weakness #1)",
                        "ECOSYSTEM", null, "1.0.0", null, "1.0.0-rc1", false),
                Arguments.of("a pre-release-suffixed range bound fails closed",
                        "ECOSYSTEM", null, "1.0.0-rc1", null, "0.9.0", false),

                // --- fail-closed: null item version (VersionUtils' null->0/"equal" weakness) -----
                Arguments.of("a null item version fails closed rather than matching every <= check",
                        "ECOSYSTEM", null, null, "9.9.9", null, false),

                // --- GIT ranges are never evaluated (commit SHAs aren't versions) ----------------
                Arguments.of("a GIT range type is always skipped, even with otherwise-numeric bounds",
                        "GIT", "1.0.0", "2.0.0", null, "1.5.0", false),
                Arguments.of("an unrecognized/future range type is also skipped (not just GIT)",
                        "SOMETHING_NEW", null, "2.0.0", null, "1.0.0", false),

                // --- other unparseable shapes fail closed rather than guessing --------------------
                Arguments.of("a non-numeric item version fails closed", "ECOSYSTEM", null, "2.0.0", null, "abc", false),
                Arguments.of("an empty-string item version fails closed", "ECOSYSTEM", null, "2.0.0", null, "", false));
    }
}
