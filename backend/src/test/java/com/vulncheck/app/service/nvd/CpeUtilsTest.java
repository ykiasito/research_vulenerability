package com.vulncheck.app.service.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class CpeUtilsTest {

    @Test
    void withVersionReplacesOnlyTheVersionSegment() {
        assertThat(CpeUtils.withVersion("cpe:2.3:a:rarlab:winrar:6.11:*:*:*:*:*:*:*", "1.0.0"))
                .isEqualTo("cpe:2.3:a:rarlab:winrar:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void withVersionPreservesTargetSwAndOtherTrailingSegments() {
        // REVISE item 6 (senior review, job 36 root-cause): the old rebuild-from-vendor/product-only
        // path (CpeUtils.buildCpe) silently reset every trailing segment to "*", including
        // target_sw — turning cpe:2.3:a:jenkins:slack:1.0:*:*:*:*:jenkins:*:* (a real NVD CPE,
        // scoped to being a Jenkins plugin) into cpe:2.3:a:jenkins:slack:4.29.149:*:*:*:*:*:*:*
        // (a CPE that doesn't actually exist in NVD, silently broadened in scope). withVersion must
        // substitute only the version segment and leave every other segment — including target_sw —
        // exactly as parsed from the source entry's own CPE string.
        String sourceCpe = "cpe:2.3:a:jenkins:slack:1.0:*:*:*:*:jenkins:*:*";

        String persisted = CpeUtils.withVersion(sourceCpe, "4.29.149");

        assertThat(persisted).isEqualTo("cpe:2.3:a:jenkins:slack:4.29.149:*:*:*:*:jenkins:*:*");
        // Round-trip: re-parsing the persisted string's own segments still carries target_sw="jenkins"
        // at CPE 2.3 segment index 10 (0-indexed), the same segment-splitting convention
        // CpeUtils.parseVendorProduct itself uses for vendor (index 3) and product (index 4).
        String[] segments = persisted.split(":");
        assertThat(segments[10]).isEqualTo("jenkins");
        assertThat(segments[5]).isEqualTo("4.29.149");
    }

    @Test
    void withVersionLeavesAMalformedCpeStringUnchanged() {
        assertThat(CpeUtils.withVersion("not-a-cpe-string", "1.0.0")).isEqualTo("not-a-cpe-string");
    }

    @Test
    void withVersionReturnsNullForANullCpeString() {
        assertThat(CpeUtils.withVersion(null, "1.0.0")).isNull();
    }

    @Test
    void withVersionResetsTheUpdateSegmentRatherThanCarryingForwardAStaleQualifier() {
        // REVISE item 8 (senior review, job 37 root-cause): withVersion previously preserved the
        // *update* segment (index 6) verbatim from whichever historical dictionary row matched,
        // producing e.g. ...:webpack:5.86.0:beta8:... for an item whose real installed version has
        // nothing at all to do with "beta8" — that qualifier belonged to a different catalogued
        // version. Every other trailing segment (target_sw here) must still carry forward unchanged.
        String sourceCpe = "cpe:2.3:a:webpack:webpack:5.0.0:beta8:*:*:*:node.js:*:*";

        String persisted = CpeUtils.withVersion(sourceCpe, "5.86.0");

        assertThat(persisted).isEqualTo("cpe:2.3:a:webpack:webpack:5.86.0:*:*:*:*:node.js:*:*");
    }

    @Test
    void parseVendorProductHandlesEscapedColonsWithinASegment() {
        // REVISE item 7 (senior review, job 37 root-cause): a plain split(":") mis-indexes every
        // segment from the first escaped colon onward. Real dictionary row: Perl's HTTP::Session
        // module, cataloged in NVD as cpe:2.3:a:ktat:http\:\:session:0.01_01:*:*:*:*:perl:*:*.
        CpeUtils.VendorProduct vendorProduct =
                CpeUtils.parseVendorProduct("cpe:2.3:a:ktat:http\\:\\:session:0.01_01:*:*:*:*:perl:*:*");

        assertThat(vendorProduct.vendor()).isEqualTo("ktat");
        assertThat(vendorProduct.product()).isEqualTo("http\\:\\:session");
    }

    @Test
    void withVersionHandlesEscapedColonsWithinASegmentAndPreservesTheRealTargetSw() {
        // Same real row as above: a naive split corrupts every segment from the escaped colon
        // onward, which previously turned this into a version segment that doesn't correspond to
        // the real NVD entry at all and silently lost the real target_sw=perl scoping.
        String sourceCpe = "cpe:2.3:a:ktat:http\\:\\:session:0.01_01:*:*:*:*:perl:*:*";

        String persisted = CpeUtils.withVersion(sourceCpe, "0.53");

        assertThat(persisted).isEqualTo("cpe:2.3:a:ktat:http\\:\\:session:0.53:*:*:*:*:perl:*:*");
    }

    @Test
    void parseVendorProductHandlesEscapedColonsForAnAlreadyFixedUpVersion() {
        // Regression guard for the round-4 fix (senior review): confirms the exact escaped-colon
        // CPE string called out in that fix — cpe:2.3:a:ktat:http\:\:session:0.53:*:*:*:*:perl:*:*
        // — still splits into vendor "ktat" and product "http\:\:session" rather than being
        // corrupted by a naive split(":").
        CpeUtils.VendorProduct vendorProduct =
                CpeUtils.parseVendorProduct("cpe:2.3:a:ktat:http\\:\\:session:0.53:*:*:*:*:perl:*:*");

        assertThat(vendorProduct.vendor()).isEqualTo("ktat");
        assertThat(vendorProduct.product()).isEqualTo("http\\:\\:session");
    }
}
