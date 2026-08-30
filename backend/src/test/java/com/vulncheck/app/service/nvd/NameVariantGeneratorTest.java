package com.vulncheck.app.service.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class NameVariantGeneratorTest {

    @Test
    void contractsAThreeOrMoreWordNameToItsAcronym() {
        // Real case (job 34, 2026-08-25): "GNU Image Manipulation Program" is GIMP's own full
        // expansion, and the local dictionary has real CPE entries under product "gimp".
        assertThat(NameVariantGenerator.contractToAcronym("GNU Image Manipulation Program")).isEqualTo("gimp");
    }

    @Test
    void skipsConnectorWordsWhenBuildingTheAcronym() {
        // "The" is skipped as a connector word, leaving 4 meaningful words (north, atlantic,
        // treaty, organization) — enough to clear the 4-meaningful-word floor below.
        assertThat(NameVariantGenerator.contractToAcronym("The North Atlantic Treaty Organization")).isEqualTo("nato");
    }

    @Test
    void refusesToContractFewerThanFourMeaningfulWords() {
        // Raised from 3 to 4 (senior review, 2026-08-25): a 3-letter acronym is too collision-prone
        // against a ~500K-unique-product dictionary even with an exact-match acceptance check — of
        // 8 real 3-meaningful-word acronym-direction candidates measured against the live
        // dictionary, 7 were wrong (e.g. "animal-sniffer-annotations" -> pix_asa,
        // "org.projectlombok:lombok" -> oplynx).
        assertThat(NameVariantGenerator.contractToAcronym("GNU Image Manipulation")).isNull();
        assertThat(NameVariantGenerator.contractToAcronym("Docker Desktop")).isNull();
        assertThat(NameVariantGenerator.contractToAcronym("Rufus")).isNull();
    }

    @Test
    void stripsALeadingVendorPrefixAtAWordBoundary() {
        assertThat(NameVariantGenerator.stripLeadingVendor("Broadcom Norton 360", "Broadcom")).isEqualTo("Norton 360");
        assertThat(NameVariantGenerator.stripLeadingVendor("openai-python", "OpenAI")).isEqualTo("python");
    }

    @Test
    void refusesToStripAMidWordCoincidence() {
        // Vendor "Go" must never strip the leading "Go" out of "Google Chrome" — there's no real
        // word boundary between them, just a shared prefix.
        assertThat(NameVariantGenerator.stripLeadingVendor("Google Chrome", "Go")).isNull();
    }

    @Test
    void refusesToStripWhenProductNameDoesNotStartWithTheVendor() {
        assertThat(NameVariantGenerator.stripLeadingVendor("Norton 360", "NortonLifeLock")).isNull();
        assertThat(NameVariantGenerator.stripLeadingVendor("Rufus", "Pete Batard")).isNull();
    }

    @Test
    void refusesToStripWhenNothingMeaningfulWouldBeLeft() {
        assertThat(NameVariantGenerator.stripLeadingVendor("Broadcom", "Broadcom")).isNull();
    }

    @Test
    void handlesBlankOrMissingInputsGracefully() {
        assertThat(NameVariantGenerator.contractToAcronym(null)).isNull();
        assertThat(NameVariantGenerator.stripLeadingVendor(null, "Acme")).isNull();
        assertThat(NameVariantGenerator.stripLeadingVendor("Acme Widget", null)).isNull();
        assertThat(NameVariantGenerator.stripLeadingVendor("Acme Widget", "")).isNull();
    }
}
