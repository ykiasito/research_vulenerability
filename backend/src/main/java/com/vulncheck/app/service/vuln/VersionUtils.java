package com.vulncheck.app.service.vuln;

/**
 * Minimal version comparator — originally for {@link CveOrgVulnerabilitySource}'s affected-range
 * checks (CVE records carry a {@code versionType} field: semver, rpm, custom, ... but reliably
 * parsing every scheme those imply is out of scope here), now also used to pick the single highest
 * recommended fix version across a job item's several vulnerability findings for display
 * (see {@code JobController#detail}). Splits on non-alphanumeric boundaries and compares segment
 * by segment: numeric segments compare numerically, anything else falls back to a string compare
 * — good enough for the common "X.Y.Z"-shaped versions this app already assumes elsewhere (see the
 * existing, similarly-scoped version handling in the registry clients), not a general semver/rpm-
 * version implementation.
 */
public final class VersionUtils {

    private VersionUtils() {
    }

    /** @return negative if {@code a < b}, zero if equal, positive if {@code a > b} */
    public static int compare(String a, String b) {
        if (a == null || b == null) {
            return 0;
        }
        String[] segmentsA = a.split("[._+\\-]");
        String[] segmentsB = b.split("[._+\\-]");
        int length = Math.max(segmentsA.length, segmentsB.length);
        for (int i = 0; i < length; i++) {
            String sa = i < segmentsA.length ? segmentsA[i] : "0";
            String sb = i < segmentsB.length ? segmentsB[i] : "0";
            int cmp = compareSegment(sa, sb);
            if (cmp != 0) {
                return cmp;
            }
        }
        return 0;
    }

    private static int compareSegment(String a, String b) {
        if (isNumeric(a) && isNumeric(b)) {
            return Long.compare(Long.parseLong(a), Long.parseLong(b));
        }
        return a.compareTo(b);
    }

    private static boolean isNumeric(String s) {
        return !s.isEmpty() && s.chars().allMatch(Character::isDigit) && s.length() < 18;
    }
}
