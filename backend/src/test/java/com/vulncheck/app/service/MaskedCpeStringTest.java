package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class MaskedCpeStringTest {

    @Test
    void ofRawCpeStringMasksOnlyTheVersionSegment() {
        MaskedCpeString masked = MaskedCpeString.ofRawCpeString("cpe:2.3:a:rarlab:winrar:6.11:*:*:*:*:*:*:*");

        assertThat(masked.value()).isEqualTo("cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*");
    }

    @Test
    void ofRawCpeStringPreservesTrailingSegmentsPastVersion() {
        // Same target_sw-scoping concern as CpeUtils.withVersion: masking the version must not
        // clobber a real scoping segment like target_sw further down the CPE string.
        MaskedCpeString masked = MaskedCpeString.ofRawCpeString("cpe:2.3:a:jenkins:slack:1.0:*:*:*:*:jenkins:*:*");

        assertThat(masked.value()).isEqualTo("cpe:2.3:a:jenkins:slack:*:*:*:*:*:jenkins:*:*");
    }

    @Test
    void ofRawCpeStringLeavesATooShortStringUnchanged() {
        // Fewer than 6 segments means there's no version field (index 5) to mask at all — mirrors
        // CpeUtils.withVersion's own defensive behavior for malformed input.
        MaskedCpeString masked = MaskedCpeString.ofRawCpeString("not-a-cpe-string");

        assertThat(masked.value()).isEqualTo("not-a-cpe-string");
    }

    @Test
    void ofRawCpeStringRejectsNull() {
        assertThatThrownBy(() -> MaskedCpeString.ofRawCpeString(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void ofRawCpeStringOnAnAlreadyMaskedStringIsIdempotent() {
        // Re-masking an already-masked string (e.g. if a caller mistakenly re-wraps a
        // MaskedCpeString#value()) must not corrupt it further.
        MaskedCpeString masked = MaskedCpeString.ofRawCpeString("cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*");

        assertThat(masked.value()).isEqualTo("cpe:2.3:a:rarlab:winrar:*:*:*:*:*:*:*:*");
    }
}
