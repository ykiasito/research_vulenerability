package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ProductNameAnnotationStripperTest {

    @Test
    void stripsAHalfWidthParentheticalAnnotation() {
        assertThat(ProductNameAnnotationStripper.strip("swA(ホニャホニャ)")).isEqualTo("swA");
    }

    @Test
    void stripsAFullWidthParentheticalAnnotation() {
        assertThat(ProductNameAnnotationStripper.strip("swA（ホニャホニャ）")).isEqualTo("swA");
    }

    @Test
    void stripsAKomejirushiAnnotation() {
        assertThat(ProductNameAnnotationStripper.strip("swB※ホニャホニャ")).isEqualTo("swB");
    }

    @Test
    void stripsBothAParentheticalAndAKomejirushiAnnotationTogether() {
        assertThat(ProductNameAnnotationStripper.strip("swA(注1)※備考")).isEqualTo("swA");
    }

    @Test
    void stripsBothMarkersRegardlessOfWhichAppearsFirst() {
        // Komejirushi appears before the parenthetical this time — whichever marker is earliest
        // in the string is the one that determines the cut point.
        assertThat(ProductNameAnnotationStripper.strip("swA※備考(注1)")).isEqualTo("swA");
    }

    @Test
    void stripsAnUnclosedParentheticalTheSameAsAClosedOne() {
        // A missing closing bracket (a typo) doesn't change anything — the opening bracket alone
        // marks "everything after this is noise", so it's stripped exactly like a well-formed
        // "swA(ホニャホニャ)" would be.
        assertThat(ProductNameAnnotationStripper.strip("swA(ホニャホニャ")).isEqualTo("swA");
    }

    @Test
    void leavesAStrayClosingBracketWithNoOpenerAlone() {
        // There's no opening bracket to cut from, so this isn't treated as annotation noise at
        // all — only trimmed.
        assertThat(ProductNameAnnotationStripper.strip("swA)note")).isEqualTo("swA)note");
    }

    @Test
    void fallsBackToTheOriginalWhenStrippingWouldLeaveNothing() {
        // The entire name is "annotation" per this heuristic (marker is the very first
        // character) — treated as a heuristic miss, not a genuinely empty product name, so the
        // original (trimmed) text is kept rather than handing Stage1 an empty search term.
        assertThat(ProductNameAnnotationStripper.strip("（全部注記）")).isEqualTo("（全部注記）");
        assertThat(ProductNameAnnotationStripper.strip("※全部注記")).isEqualTo("※全部注記");
    }

    @Test
    void leavesAPlainNameUnchangedApartFromTrimming() {
        assertThat(ProductNameAnnotationStripper.strip("  swA  ")).isEqualTo("swA");
        assertThat(ProductNameAnnotationStripper.strip("plainName")).isEqualTo("plainName");
    }

    @Test
    void returnsNullUnchanged() {
        assertThat(ProductNameAnnotationStripper.strip(null)).isNull();
    }
}
