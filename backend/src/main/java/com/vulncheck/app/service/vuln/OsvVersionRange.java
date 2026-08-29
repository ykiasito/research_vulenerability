package com.vulncheck.app.service.vuln;

import java.util.regex.Pattern;

/**
 * Evaluates whether an item's version falls inside one GHSA/OSV vulnerable-version range —
 * previously delegated entirely to GitHub's server (see {@code GhsaVulnerabilitySource}'s old
 * per-item live-API javadoc), now needed locally since the mirror is queried directly (see {@code
 * docs/spec/ghsa-mirror-plan.md} §1-4/§3-1(B) for the full rationale).
 *
 * <p><b>Fail-closed, not fail-open:</b> {@link com.vulncheck.app.service.vuln.VersionUtils} is a
 * deliberately minimal comparator (its own javadoc says so) with two known weaknesses that would be
 * dangerous to feed range evaluation directly: (1) it splits on {@code [._+-]}, so a pre-release
 * suffix like {@code "1.0.0-rc1"} sorts as segment 4 {@code "rc1"} vs. a missing segment's default
 * {@code "0"} — an ASCII string compare that makes {@code "1.0.0-rc1" > "1.0.0"}, the wrong
 * direction; (2) {@code compare(null, x)} returns {@code 0} (treated as equal), which would make a
 * null item version pass every {@code <=} check. Rather than let either of those produce a
 * confidently-wrong "safe"/"vulnerable" verdict, this class only evaluates versions that look like
 * plain dot-separated non-negative integers ({@code ^\d+(\.\d+)*$}) — anything else (item version,
 * range floor, or range ceiling) makes the whole range unevaluable, and {@link #matches} returns
 * {@code false} ("no finding from this range" — plan §0-1 principle 1: this is NOT the same as
 * "confirmed not affected"; {@code GhsaVulnerabilitySource} must not report it as such). {@code
 * range_type = "GIT"} ranges (commit-SHA bounds) are rejected the same way — a lexicographic
 * compare of two hex strings is meaningless as a version ordering.
 */
public final class OsvVersionRange {

    private static final Pattern PLAIN_NUMERIC_VERSION = Pattern.compile("^\\d+(\\.\\d+)*$");

    private OsvVersionRange() {
    }

    /**
     * @param rangeType OSV's {@code ranges[].type} verbatim ({@code "SEMVER"}/{@code "ECOSYSTEM"}/
     *                  {@code "GIT"}) — only the first two are ever evaluated.
     * @param introducedVersion null means "vulnerable from the very first version" (OSV's {@code
     *                          introduced:"0"}, normalized to null by the ingest parser).
     * @param fixedVersion exclusive upper bound ({@code <}), or null.
     * @param lastAffectedVersion inclusive upper bound ({@code <=}), or null. Never both non-null
     *                            for the same range (enforced by V19's CHECK constraint) — if both
     *                            are null, the range is unbounded above (still vulnerable, no known
     *                            fix yet).
     * @param itemVersion the job item's own version string.
     * @return true if {@code itemVersion} falls inside this range. Fail-closed: any unparseable
     *         version (item's own, or either bound) or a {@code GIT} range type returns {@code
     *         false} rather than guessing.
     */
    public static boolean matches(
            String rangeType, String introducedVersion, String fixedVersion, String lastAffectedVersion, String itemVersion) {
        if (!"SEMVER".equals(rangeType) && !"ECOSYSTEM".equals(rangeType)) {
            return false; // GIT (or any future/unknown type) — not evaluable, see class javadoc.
        }
        if (!isPlainNumericVersion(itemVersion)) {
            return false;
        }
        if (introducedVersion != null && !isPlainNumericVersion(introducedVersion)) {
            return false;
        }
        if (fixedVersion != null && !isPlainNumericVersion(fixedVersion)) {
            return false;
        }
        if (lastAffectedVersion != null && !isPlainNumericVersion(lastAffectedVersion)) {
            return false;
        }

        if (introducedVersion != null && VersionUtils.compare(itemVersion, introducedVersion) < 0) {
            return false; // itemVersion predates this range's floor
        }
        if (fixedVersion != null) {
            return VersionUtils.compare(itemVersion, fixedVersion) < 0;
        }
        if (lastAffectedVersion != null) {
            return VersionUtils.compare(itemVersion, lastAffectedVersion) <= 0;
        }
        return true; // unbounded above — still vulnerable at every version from the floor onward
    }

    static boolean isPlainNumericVersion(String version) {
        return version != null && PLAIN_NUMERIC_VERSION.matcher(version).matches();
    }
}
