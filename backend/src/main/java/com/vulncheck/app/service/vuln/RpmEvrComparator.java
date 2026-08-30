package com.vulncheck.app.service.vuln;

/**
 * Standard RPM {@code Epoch:Version-Release} ("EVR") comparison — implements the real {@code
 * rpmvercmp} algorithm (as shipped by RPM/DNF/YUM), NOT {@link VersionUtils#compare}, which is
 * documented elsewhere in this project as a generic, non-authoritative comparator not suited to any
 * one packaging ecosystem's real tie-breaking rules.
 *
 * <p><b>Senior review REVISE item 2 (2026-08-27, CRITICAL):</b> {@code CsafVulnerabilitySource
 * #versionMatches} was a Siemens-specific branch followed by an unconditional {@code return true} —
 * every Red Hat name match became a finding regardless of whether the CSV's version was ever actually
 * affected, contradicting the design doc's own requirement (§1-3/§7) for per-entry version
 * re-verification. This class provides the real comparison Red Hat's purl-derived, EVR-shaped version
 * strings (e.g. {@code "1:3.0.7-24.el9_2"}, {@code "0.96.2-8.3E"}) need — see {@code
 * CsafVulnerabilitySource#passesRedHatFixedVersionGate} for how it's applied.
 *
 * <p><b>Algorithm (verbatim port of RPM's own {@code rpmvercmp}):</b> epoch compares numerically
 * first (missing epoch on either side defaults to {@code 0}); version and release then each compare
 * via {@link #rpmvercmp}, which walks both strings left to right, alternating between digit-only and
 * alpha-only segments (any other character — {@code .}, {@code _}, {@code -}, ...  — is treated as a
 * pure segment separator, never compared itself): a numeric segment always outranks an alpha segment
 * at the same position (so {@code "1.0a"} sorts before {@code "1.0.1"} — {@code "a"} vs a missing/
 * empty numeric segment loses); within two numeric segments, the one with more digits (after
 * stripping leading zeros) wins outright, otherwise digit-for-digit string comparison (equivalent to
 * numeric comparison once leading zeros are stripped and lengths match); within two alpha segments,
 * plain {@link String#compareTo}. A leading {@code ~} sorts before EVERYTHING, including an empty
 * string on the other side — RPM's own convention for marking pre-releases (e.g. {@code "1.0~rc1"} <
 * {@code "1.0"}). A leading {@code ^} is the opposite: RPM's post-release/snapshot marker, it sorts
 * AFTER an exhausted other side (e.g. {@code "1.0^20240101git"} > {@code "1.0"}) but still loses to a
 * real alnum segment on the other side (e.g. {@code "1.0^20240101git"} < {@code "1.0.1"}). Whichever
 * side still has unconsumed, non-separator characters left over once the other side is exhausted is
 * considered the newer (larger) one.
 */
final class RpmEvrComparator {

    private RpmEvrComparator() {
    }

    private record Evr(String epoch, String version, String release) {
    }

    /** @return negative if {@code a < b}, zero if equal, positive if {@code a > b} — per RPM's own
     *          Epoch:Version-Release ordering (epoch, then version, then release). */
    static int compareEvr(String a, String b) {
        Evr evrA = parseEvr(a);
        Evr evrB = parseEvr(b);

        int epochCmp = Long.compare(parseEpoch(evrA.epoch()), parseEpoch(evrB.epoch()));
        if (epochCmp != 0) {
            return epochCmp;
        }
        int versionCmp = rpmvercmp(evrA.version(), evrB.version());
        if (versionCmp != 0) {
            return versionCmp;
        }
        return rpmvercmp(evrA.release(), evrB.release());
    }

    private static long parseEpoch(String epoch) {
        if (epoch == null || epoch.isBlank()) {
            return 0L;
        }
        try {
            return Long.parseLong(epoch.trim());
        } catch (NumberFormatException e) {
            return 0L; // an unparseable epoch is treated as absent (0), not a hard failure
        }
    }

    /** {@code "[epoch:]version[-release]"} — the shape both a purl-derived {@code component_version}
     *  (e.g. {@code "3.0.7-24.el9_2"}, usually epoch-free per the purl rpm type's own convention when
     *  epoch is 0) and an explicit-epoch string (e.g. {@code "1:3.0.7-24.el9_2"}) share. The FIRST
     *  {@code ':'} is the epoch delimiter ONLY when everything before it is a non-empty run of ASCII
     *  digits (real RPM epochs are a plain non-negative integer) — a {@code ':'} appearing anywhere
     *  else in the string (e.g. inside a version that isn't actually epoch-prefixed) is just an
     *  ordinary character of the version itself, not a delimiter (senior review REVISE follow-up item
     *  3, 2026-08-27: the previous unconditional {@code indexOf(':')} treated ANY text before the
     *  first {@code ':'} as the epoch, silently discarding it as a bogus, unparseable epoch — via
     *  {@link #parseEpoch}'s catch-all — whenever that prefix wasn't numeric, which could make two
     *  genuinely different version strings compare equal). The FIRST {@code '-'} in what remains is
     *  the version/release delimiter (RPM version and release segments never contain {@code '-'}
     *  themselves, by the format's own rules — a version string with no {@code '-'} at all has no
     *  release segment). */
    private static Evr parseEvr(String raw) {
        if (raw == null) {
            return new Evr("0", "", "");
        }
        String s = raw.trim();
        String epoch = "0";
        String rest = s;
        int colonIdx = s.indexOf(':');
        if (colonIdx > 0 && isAllAsciiDigits(s, colonIdx)) {
            epoch = s.substring(0, colonIdx);
            rest = s.substring(colonIdx + 1);
        }
        String version = rest;
        String release = "";
        int dashIdx = rest.indexOf('-');
        if (dashIdx >= 0) {
            version = rest.substring(0, dashIdx);
            release = rest.substring(dashIdx + 1);
        }
        return new Evr(epoch, version, release);
    }

    /** @return whether {@code s.substring(0, end)} is a non-empty run of ASCII digits only — the real
     *          RPM rule for whether a leading {@code ':'} is an epoch delimiter at all. */
    private static boolean isAllAsciiDigits(String s, int end) {
        for (int i = 0; i < end; i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true;
    }

    /** Direct port of RPM's own {@code rpmvercmp(a, b)} — see the class javadoc for the rules. */
    static int rpmvercmp(String a, String b) {
        if (a == null) {
            a = "";
        }
        if (b == null) {
            b = "";
        }
        if (a.equals(b)) {
            return 0;
        }

        int i = 0;
        int j = 0;
        int lenA = a.length();
        int lenB = b.length();

        while (i < lenA || j < lenB) {
            // Skip separator characters (neither alphanumeric nor '~' nor '^') on both sides.
            while (i < lenA && !isAlnum(a.charAt(i)) && a.charAt(i) != '~' && a.charAt(i) != '^') {
                i++;
            }
            while (j < lenB && !isAlnum(b.charAt(j)) && b.charAt(j) != '~' && b.charAt(j) != '^') {
                j++;
            }

            // '~' sorts before everything, including an exhausted other side.
            boolean aTilde = i < lenA && a.charAt(i) == '~';
            boolean bTilde = j < lenB && b.charAt(j) == '~';
            if (aTilde || bTilde) {
                if (!aTilde) {
                    return 1;
                }
                if (!bTilde) {
                    return -1;
                }
                i++;
                j++;
                continue;
            }

            // REVISE follow-up item 4a (senior review 2026-08-27): '^' is RPM's post-release/snapshot
            // marker — the opposite priority of '~'. An exhausted other side LOSES to a present '^'
            // (e.g. "1.0^20240101git" > "1.0"), but a '^' itself loses to a real alnum segment on the
            // other side (e.g. "1.0^20240101git" < "1.0.1") — direct port of RPM's own rpmvercmp caret
            // handling, which is intentionally NOT symmetric with the tilde block above.
            boolean aAtEnd = i >= lenA;
            boolean bAtEnd = j >= lenB;
            boolean aCaret = !aAtEnd && a.charAt(i) == '^';
            boolean bCaret = !bAtEnd && b.charAt(j) == '^';
            if (aCaret || bCaret) {
                if (aAtEnd) {
                    return -1;
                }
                if (bAtEnd) {
                    return 1;
                }
                if (!aCaret) {
                    return 1;
                }
                if (!bCaret) {
                    return -1;
                }
                i++;
                j++;
                continue;
            }

            if (i >= lenA || j >= lenB) {
                break;
            }

            int startA = i;
            int startB = j;
            boolean isNum;
            if (Character.isDigit(a.charAt(i))) {
                while (i < lenA && Character.isDigit(a.charAt(i))) {
                    i++;
                }
                while (j < lenB && Character.isDigit(b.charAt(j))) {
                    j++;
                }
                isNum = true;
            } else {
                while (i < lenA && isAlpha(a.charAt(i))) {
                    i++;
                }
                while (j < lenB && isAlpha(b.charAt(j))) {
                    j++;
                }
                isNum = false;
            }

            String segA = a.substring(startA, i);
            String segB = b.substring(startB, j);

            // The other side had nothing of this segment's type at this position (e.g. a numeric
            // segment on one side, an empty/alpha one on the other) — numeric always outranks alpha.
            if (segB.isEmpty()) {
                return isNum ? 1 : -1;
            }

            if (isNum) {
                String trimmedA = stripLeadingZeros(segA);
                String trimmedB = stripLeadingZeros(segB);
                if (trimmedA.length() != trimmedB.length()) {
                    return trimmedA.length() > trimmedB.length() ? 1 : -1;
                }
                segA = trimmedA;
                segB = trimmedB;
            }

            int cmp = segA.compareTo(segB);
            if (cmp != 0) {
                return cmp < 0 ? -1 : 1;
            }
            // Segment compared equal — continue from where each side left off (i/j already advanced).
        }

        if (i >= lenA && j >= lenB) {
            return 0;
        }
        // Whichever side still has characters left over wins (is considered newer/larger).
        return i >= lenA ? -1 : 1;
    }

    /** RPM's own {@code rpmvercmp} strips ALL leading zeros, including down to an empty string for
     *  an all-zero segment (e.g. {@code "00"} -> {@code ""}) — two all-zero segments then compare
     *  equal-length/equal-value, exactly as they should. */
    private static String stripLeadingZeros(String s) {
        int i = 0;
        while (i < s.length() && s.charAt(i) == '0') {
            i++;
        }
        return s.substring(i);
    }

    /** RPM's own {@code risalnum} is ASCII-only ({@code [0-9A-Za-z]}) — {@link Character#isLetterOrDigit}
     *  is Unicode-aware and would treat characters real RPM never considers alphanumeric (e.g.
     *  combining marks, non-Latin letters) as segment characters instead of separators (senior review
     *  REVISE follow-up item 4b, 2026-08-27). */
    private static boolean isAlnum(char c) {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /** RPM's own {@code risalpha} is ASCII-only ({@code [A-Za-z]}) — see {@link #isAlnum}. */
    private static boolean isAlpha(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }
}
