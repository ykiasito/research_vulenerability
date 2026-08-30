package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Range specs below are real strings observed in Siemens' live CSAF feed (2026-08-27 capture). */
class SiemensCsafVersionRangeTest {

    @Test
    void allVersionsMarkerAlwaysMatches() {
        assertThat(SiemensCsafVersionRange.matches("vers:all/*", "1.0.0")).isTrue();
        assertThat(SiemensCsafVersionRange.matches("vers:all/*", "999.0.0")).isTrue();
    }

    @Test
    void simpleLessThanRangeMatchesBelowAndRejectsAtOrAbove() {
        assertThat(SiemensCsafVersionRange.matches("vers:intdot/<3.0.0", "2.9.9")).isTrue();
        assertThat(SiemensCsafVersionRange.matches("vers:intdot/<3.0.0", "3.0.0")).isFalse();
        assertThat(SiemensCsafVersionRange.matches("vers:intdot/<3.0.0", "3.0.1")).isFalse();
    }

    @Test
    void compoundRangeRequiresBothBounds() {
        // Real string from SSA search: "vers:intdot/>=1.7.6|<1.15.17"
        String range = "vers:intdot/>=1.7.6|<1.15.17";
        assertThat(SiemensCsafVersionRange.matches(range, "1.10.0")).isTrue();
        assertThat(SiemensCsafVersionRange.matches(range, "1.7.5")).isFalse();
        assertThat(SiemensCsafVersionRange.matches(range, "1.15.17")).isFalse();
        assertThat(SiemensCsafVersionRange.matches(range, "1.15.16")).isTrue();
    }

    @Test
    void freeTextRangeWithoutTheVersSchemeIsStillParsed() {
        // Real string: "All versions < V17 Update 9" — the leading "V" is stripped before comparing.
        assertThat(SiemensCsafVersionRange.matches("All versions < V17 Update 9", "16")).isTrue();
        assertThat(SiemensCsafVersionRange.matches("All versions < V17 Update 9", "17")).isFalse();
    }

    // REVISE item 7 (senior review 2026-08-27): a compound vers: range with two disjoint (OR'd)
    // sub-ranges must not collapse to "matches nothing" (ANDing all four constraints together would).
    @Test
    void disjointFourConstraintRangeMatchesEitherBranchAndRejectsBetweenThem() {
        String range = "vers:intdot/>=1.0.0|<2.0.0|>=3.0.0|<4.0.0";
        assertThat(SiemensCsafVersionRange.matches(range, "1.5.0")).isTrue(); // inside first branch
        assertThat(SiemensCsafVersionRange.matches(range, "3.5.0")).isTrue(); // inside second branch
        assertThat(SiemensCsafVersionRange.matches(range, "2.5.0")).isFalse(); // strictly between, outside both
        assertThat(SiemensCsafVersionRange.matches(range, "1.0.0")).isTrue(); // lower bound of first branch, inclusive
        assertThat(SiemensCsafVersionRange.matches(range, "2.0.0")).isFalse(); // upper bound of first branch, exclusive
        assertThat(SiemensCsafVersionRange.matches(range, "4.5.0")).isFalse(); // above both branches
    }

    @Test
    void unparseableFreeTextIsTreatedAsPossiblyApplicableRatherThanSilentlyExcluded() {
        // A string with neither "*"/"all versions" nor an extractable comparator+version pair.
        assertThat(SiemensCsafVersionRange.matches("see release notes for details", "1.0.0")).isTrue();
    }

    @Test
    void nullOrBlankRangeAlwaysMatches() {
        assertThat(SiemensCsafVersionRange.matches(null, "1.0.0")).isTrue();
        assertThat(SiemensCsafVersionRange.matches("", "1.0.0")).isTrue();
    }
}
