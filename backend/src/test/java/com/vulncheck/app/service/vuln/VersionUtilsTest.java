package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class VersionUtilsTest {

    @Test
    void comparesNumericSegmentsNumericallyNotLexicographically() {
        // A naive string compare would put "0.9.0" after "0.15.2" (since "9" > "1" as characters)
        // — the whole reason this isn't just String.compareTo.
        assertThat(VersionUtils.compare("0.9.0", "0.15.2")).isLessThan(0);
        assertThat(VersionUtils.compare("0.15.2", "0.9.0")).isGreaterThan(0);
    }

    @Test
    void treatsMissingTrailingSegmentsAsZero() {
        assertThat(VersionUtils.compare("1.2", "1.2.0")).isZero();
        assertThat(VersionUtils.compare("1.2.1", "1.2")).isGreaterThan(0);
    }

    @Test
    void equalVersionsCompareAsZero() {
        assertThat(VersionUtils.compare("6.2.13.Final", "6.2.13.Final")).isZero();
    }
}
