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

    @Test
    void buildCpeWithExplicitPartUsesThatPartInsteadOfAssumingApplication() {
        // task-backlog item 39 (senior review, 2026-08-30, PR#16 review): NvdVulnerabilitySource#find
        // used to always call the 3-arg buildCpe (hardcoded part=a), silently querying NVD for a
        // nonexistent CPE name for part=o products like PAN-OS.
        assertThat(CpeUtils.buildCpe("o", "paloaltonetworks", "pan-os", "10.2.4"))
                .isEqualTo("cpe:2.3:o:paloaltonetworks:pan-os:10.2.4:*:*:*:*:*:*:*");
    }

    @Test
    void buildCpeThreeArgOverloadStillDefaultsToPartA() {
        // BundledComponentResearchService has no source CPE to read a real part from at all, so it
        // deliberately keeps using this overload — must keep behaving exactly as before.
        assertThat(CpeUtils.buildCpe("rarlab", "winrar", "6.11"))
                .isEqualTo("cpe:2.3:a:rarlab:winrar:6.11:*:*:*:*:*:*:*");
    }

    @Test
    void parsePartExtractsThePartSegmentFromAFullyQualifiedCpeString() {
        assertThat(CpeUtils.parsePart("cpe:2.3:o:paloaltonetworks:pan-os:10.2.4:*:*:*:*:*:*:*")).isEqualTo("o");
        assertThat(CpeUtils.parsePart("cpe:2.3:a:rarlab:winrar:6.11:*:*:*:*:*:*:*")).isEqualTo("a");
        assertThat(CpeUtils.parsePart("cpe:2.3:h:cisco:asa_5505:-:*:*:*:*:*:*:*")).isEqualTo("h");
    }

    @Test
    void parsePartDefaultsToAWhenTheCpeStringIsNullOrTooShortToCarryAPart() {
        assertThat(CpeUtils.parsePart(null)).isEqualTo("a");
        assertThat(CpeUtils.parsePart("cpe:2.3")).isEqualTo("a");
        assertThat(CpeUtils.parsePart("not-a-cpe-string")).isEqualTo("a");
    }

    // --- parseVersion/versionInRange (closed-mode backlog item 251, senior-reviewer REVISE item 10:
    // moved from NvdMirrorAbVerificationRunner's disposable A/B harness into production, since
    // NvdVulnerabilitySource's mirror-backed rewrite needs the exact same, already-hardened logic
    // that harness's GATE PASSED conclusion validated) -----------------------------------------------

    @Test
    void parseVersionExtractsTheVersionSegment() {
        assertThat(CpeUtils.parseVersion("cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*")).isEqualTo("2.15.0");
    }

    @Test
    void parseVersionDefaultsToWildcardWhenTheCpeStringIsNullOrTooShortToCarryAVersion() {
        assertThat(CpeUtils.parseVersion(null)).isEqualTo("*");
        assertThat(CpeUtils.parseVersion("cpe:2.3:a:apache:log4j")).isEqualTo("*");
    }

    @Test
    void parseVersionHandlesADashSegmentAsNotApplicableRatherThanWildcard() {
        assertThat(CpeUtils.parseVersion("cpe:2.3:o:cisco:ios_xe:-:*:*:*:*:*:*:*")).isEqualTo("-");
    }

    @Test
    void versionInRangeMatchesAConcreteCriteriaVersionExactlyCaseInsensitive() {
        assertThat(CpeUtils.versionInRange("2.15.0", "2.15.0", null, null, null, null)).isTrue();
        assertThat(CpeUtils.versionInRange("2.15.0", "2.15.1", null, null, null, null)).isFalse();
    }

    @Test
    void versionInRangeNeverMatchesABareDashCriteriaVersionEvenWithNoRangeColumnsSet() {
        // CPE 2.3's own "not applicable" marker, not a synonym for "*" (any version) -- a
        // version-less platform entry like cpe:2.3:o:cisco:ios_xe:-:*:*:*:*:*:*:* has all four range
        // columns null (there's no range to describe for a field that doesn't apply), which would
        // otherwise fall into the "unconditionally vulnerable at every version" branch and match
        // every queried version indiscriminately -- the exact false-positive shape
        // NvdMirrorAbVerificationRunner's own REVISE history (see its versionApplies javadoc) found
        // and fixed. The only safe, fail-closed treatment is to never match on a bare "-".
        assertThat(CpeUtils.versionInRange("17.3.1", "-", null, null, null, null)).isFalse();
        assertThat(CpeUtils.versionInRange("1.0.0", "-", null, null, null, null)).isFalse();
    }

    @Test
    void versionInRangeWithWildcardCriteriaVersionAndNoRangeColumnsMatchesEveryVersion() {
        assertThat(CpeUtils.versionInRange("1.0.0", "*", null, null, null, null)).isTrue();
        assertThat(CpeUtils.versionInRange("999.999.999", "*", null, null, null, null)).isTrue();
    }

    @Test
    void versionInRangeRespectsAllFourRangeBoundsInclusiveAndExclusive() {
        assertThat(CpeUtils.versionInRange("2.0.0", "*", "2.0.0", null, null, null)).isTrue();
        assertThat(CpeUtils.versionInRange("1.9.9", "*", "2.0.0", null, null, null)).isFalse();
        assertThat(CpeUtils.versionInRange("2.0.0", "*", null, "2.0.0", null, null)).isFalse();
        assertThat(CpeUtils.versionInRange("2.0.1", "*", null, "2.0.0", null, null)).isTrue();
        assertThat(CpeUtils.versionInRange("3.0.0", "*", null, null, "3.0.0", null)).isTrue();
        assertThat(CpeUtils.versionInRange("3.0.1", "*", null, null, "3.0.0", null)).isFalse();
        assertThat(CpeUtils.versionInRange("2.9.9", "*", null, null, null, "3.0.0")).isTrue();
        assertThat(CpeUtils.versionInRange("3.0.0", "*", null, null, null, "3.0.0")).isFalse();
    }
}
