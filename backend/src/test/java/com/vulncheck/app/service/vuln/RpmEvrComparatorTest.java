package com.vulncheck.app.service.vuln;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Senior review REVISE item 2 (2026-08-27, CRITICAL) — real RPM EVR examples, not synthetic ones,
 *  per the review's own instruction. */
class RpmEvrComparatorTest {

    @Test
    void aLowerReleaseSortsBelowAHigherReleaseWithTheSameEpochAndVersion() {
        assertThat(RpmEvrComparator.compareEvr("1:3.0.7-24.el9_2", "1:3.0.7-25.el9_2")).isLessThan(0);
        assertThat(RpmEvrComparator.compareEvr("1:3.0.7-25.el9_2", "1:3.0.7-24.el9_2")).isGreaterThan(0);
    }

    @Test
    void identicalEvrStringsCompareEqual() {
        assertThat(RpmEvrComparator.compareEvr("1:3.0.7-24.el9_2", "1:3.0.7-24.el9_2")).isZero();
        assertThat(RpmEvrComparator.compareEvr("0.96.2-8.3E", "0.96.2-8.3E")).isZero();
    }

    @Test
    void epochWinsOverVersionAndReleaseEntirely() {
        // A higher epoch always outranks a "larger-looking" version/release on the lower-epoch side.
        assertThat(RpmEvrComparator.compareEvr("1:1.0-1", "0:99.0-99")).isGreaterThan(0);
        assertThat(RpmEvrComparator.compareEvr("0:99.0-99", "1:1.0-1")).isLessThan(0);
    }

    @Test
    void missingEpochDefaultsToZero() {
        // No epoch prefix at all — purl-derived Red Hat versions are usually epoch-free when the
        // real epoch is 0 (see CsafProductTreeWalker's real quagga/mongodb fixtures).
        assertThat(RpmEvrComparator.compareEvr("3.0.7-24.el9_2", "0:3.0.7-25.el9_2")).isLessThan(0);
        assertThat(RpmEvrComparator.compareEvr("3.0.7-24.el9_2", "3.0.7-24.el9_2")).isZero();
    }

    @Test
    void realQuaggaVersionsCompareByReleaseWhenVersionMatches() {
        // Real fixture from CsafProductTreeWalkerTest/RedHatCsafSyncServiceTest: quagga 0.96.2-8.3E.
        assertThat(RpmEvrComparator.compareEvr("0.96.2-8.2E", "0.96.2-8.3E")).isLessThan(0);
        assertThat(RpmEvrComparator.compareEvr("0.96.2-8.3E", "0.96.2-8.2E")).isGreaterThan(0);
    }

    @Test
    void higherVersionSegmentWinsRegardlessOfRelease() {
        assertThat(RpmEvrComparator.compareEvr("0.96.1-99.9E", "0.96.2-1.el6")).isLessThan(0);
    }

    @Test
    void moreNumericDigitsAfterStrippingLeadingZerosWinsOutright() {
        // "10" (2 digits) beats "9" (1 digit) even though a naive string compare would say "10" < "9".
        assertThat(RpmEvrComparator.compareEvr("1.9-1", "1.10-1")).isLessThan(0);
    }

    @Test
    void leadingZerosAreStrippedBeforeNumericComparison() {
        assertThat(RpmEvrComparator.compareEvr("1.09-1", "1.9-1")).isZero();
    }

    @Test
    void numericSegmentAlwaysOutranksAnAlphaSegmentAtTheSamePosition() {
        // rpmvercmp: a numeric segment is always "newer" than an alpha one at the same position.
        assertThat(RpmEvrComparator.compareEvr("1.0a", "1.0.1")).isLessThan(0);
    }

    @Test
    void aTildeSegmentSortsBeforeEverythingElseIncludingAnEmptyCounterpart() {
        // RPM's own pre-release convention: "1.0~rc1" < "1.0".
        assertThat(RpmEvrComparator.compareEvr("1.0~rc1-1", "1.0-1")).isLessThan(0);
        assertThat(RpmEvrComparator.compareEvr("1.0-1", "1.0~rc1-1")).isGreaterThan(0);
    }

    @Test
    void separatorCharactersAreNotThemselvesCompared() {
        // "." vs "_" vs "-" as a pure segment separator makes no difference once release is isolated.
        assertThat(RpmEvrComparator.compareEvr("24.el9_2", "24.el9.2")).isZero();
    }

    @Test
    void nullVersionStringsAreTreatedAsEpochZeroEmptyVersionEmptyRelease() {
        assertThat(RpmEvrComparator.compareEvr(null, null)).isZero();
        assertThat(RpmEvrComparator.compareEvr(null, "0:1.0-1")).isLessThan(0);
    }

    @Test
    void rpmvercmpDirectlyMatchesKnownRpmBehaviorForWhicheverSideHasLeftoverCharacters() {
        // Whichever side still has unconsumed characters once the other side is exhausted is newer.
        assertThat(RpmEvrComparator.rpmvercmp("1.0", "1.0.1")).isLessThan(0);
        assertThat(RpmEvrComparator.rpmvercmp("1.0.1", "1.0")).isGreaterThan(0);
        assertThat(RpmEvrComparator.rpmvercmp("1.0", "1.0")).isZero();
    }

    @Test
    void aColonIsOnlyAnEpochDelimiterWhenEverythingBeforeItIsAsciiDigits() {
        // Senior review REVISE follow-up item 3 (2026-08-27, CRITICAL): before the fix, parseEvr took
        // everything before the FIRST ':' as the epoch unconditionally, so "2.0:x" parsed as bogus
        // epoch "2.0" (unparseable, silently defaulting to 0 via parseEpoch's catch) with version "x"
        // — and likewise for "1.0:x" — making these two genuinely different strings compare EQUAL.
        // With the fix, since "2.0" and "1.0" are not all-ASCII-digits, no epoch is stripped at all
        // and the whole string (including the ':') is the version, so numeric comparison of the "2"
        // vs "1" leading segment correctly distinguishes them.
        assertThat(RpmEvrComparator.compareEvr("2.0:x", "1.0:x")).isGreaterThan(0);
        assertThat(RpmEvrComparator.compareEvr("1.0:x", "2.0:x")).isLessThan(0);
    }

    @Test
    void aVersionStringWithANonEpochColonRoundTripsThroughComparisonInsteadOfBeingTruncated() {
        // The colon here is inside the release segment (after the '-'), not a leading all-digit epoch
        // prefix — it must survive parseEvr intact and be treated as an ordinary separator character
        // by rpmvercmp, so the real alpha content after it ("alpha" vs "beta") decides the comparison.
        assertThat(RpmEvrComparator.compareEvr("1.0-1:alpha", "1.0-1:beta")).isLessThan(0);
        assertThat(RpmEvrComparator.compareEvr("1.0-1:alpha", "1.0-1:alpha")).isZero();
    }

    @Test
    void aRealAsciiDigitEpochPrefixIsStillStrippedAsAnEpoch() {
        // Guards against the item-3 fix over-correcting to "never strip a colon prefix" — a genuine
        // all-digit epoch prefix must still behave exactly as before.
        assertThat(RpmEvrComparator.compareEvr("2:1.0-1", "1:1.0-1")).isGreaterThan(0);
        assertThat(RpmEvrComparator.compareEvr("0:1.0-1", "1.0-1")).isZero();
    }

    @Test
    void aCaretSortsAfterAnExhaustedOtherSideButBeforeARealAlnumSegment() {
        // Senior review REVISE follow-up item 4a (2026-08-27): '^' is RPM's post-release/snapshot
        // marker, the opposite priority of '~'. Real rpmvercmp semantics: "1.0^20240101git" > "1.0"
        // (an exhausted other side loses to a present '^'), but "1.0^20240101git" < "1.0.1" (a '^'
        // itself loses to real alnum content on the other side).
        assertThat(RpmEvrComparator.rpmvercmp("1.0^20240101git", "1.0")).isGreaterThan(0);
        assertThat(RpmEvrComparator.rpmvercmp("1.0", "1.0^20240101git")).isLessThan(0);
        assertThat(RpmEvrComparator.rpmvercmp("1.0^20240101git", "1.0.1")).isLessThan(0);
        assertThat(RpmEvrComparator.rpmvercmp("1.0.1", "1.0^20240101git")).isGreaterThan(0);
    }

    @Test
    void isAlnumAndIsAlphaAreAsciiOnlyNotUnicodeAware() {
        // Senior review REVISE follow-up item 4b (2026-08-27): real RPM's risalnum/risalpha are
        // ASCII-only ([0-9A-Za-z]). "1café" (é = 'é', a Unicode letter) must compare EQUAL to
        // "1caf" once 'é' is correctly excluded from the alpha segment and instead skipped as an
        // ordinary (non-alnum, non-'~', non-'^') separator character — a Unicode-aware Character
        // .isLetter/.isLetterOrDigit would instead have included 'é' in the alpha segment, making
        // "1café" compare strictly greater than "1caf" (segA="café" vs segB="caf", segB a prefix
        // of segA).
        assertThat(RpmEvrComparator.rpmvercmp("1café", "1caf")).isZero();
    }
}
