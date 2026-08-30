package com.vulncheck.app.service.vuln;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Best-effort applicability check for Siemens' {@code product_tree} version-range branches. Real
 * captured data (2026-08-27, all 831 advisories in the live feed) shows two shapes:
 * <ul>
 *   <li>the {@code vers:} scheme (<a href="https://github.com/package-url/purl-spec">purl-spec</a>
 *   VERSION-RANGE-SPEC), e.g. {@code vers:all/*}, {@code vers:intdot/<3.0.0}, or a compound {@code
 *   vers:intdot/>=1.7.6|<1.15.17} (constraints joined with {@code |}) — the large majority
 *   (~96%) of entries observed.</li>
 *   <li>free text that never adopted the {@code vers:} prefix at all, e.g. {@code "All versions <
 *   V17 Update 9"} or {@code "<5.5.4"} — roughly 4% of entries observed, mixing a {@code V}/{@code
 *   F}/{@code L} letter prefix into the version token inconsistently.</li>
 * </ul>
 *
 * <p>Rather than two separate parsers, both shapes are handled by one generic regex that extracts
 * every {@code (comparator, versionToken)} pair found anywhere in the string — this works
 * identically whether the string happens to start with {@code vers:} or not. A string with no
 * extractable constraint at all (and that isn't the "matches everything" {@code all}/{@code *}
 * marker) is treated as "cannot determine — possibly applicable" rather than silently excluded,
 * per the plan's §0-1 principle 1 (a tool whose job is flagging things for the user to check should
 * not manufacture false confidence by staying silent on data it can't parse).
 *
 * <p><b>REVISE item 7 (senior review 2026-08-27) — disjoint (OR'd) ranges:</b> the purl-spec {@code
 * vers:} scheme uses {@code |} to express alternating disjoint range pairs, e.g. two separately-
 * maintained firmware branches: {@code vers:intdot/>=1.0.0|<2.0.0|>=3.0.0|<4.0.0} means "affected if
 * in [1.0.0,2.0.0) OR [3.0.0,4.0.0)" — ANDing all four constraints together (the original
 * implementation) evaluates to {@code false} for every possible input version, a false negative that
 * silently excludes a product that should have matched, directly contradicting this class's own
 * fail-open bias. {@link #matches} now groups extracted constraints into consecutive (lower-bound,
 * upper-bound) pairs and ORs across the groups instead — see {@link #evaluateGroups} for exactly how
 * constraints are grouped, and its fallback when a group can't be cleanly formed.
 *
 * <p><b>Known limitation (implementation judgment call, not covered by the plan's own text):</b>
 * version tokens are compared via {@link VersionUtils#compare}, which does not understand the
 * {@code V}/{@code F}/{@code L} vendor letter prefixes seen in the free-text shape (e.g. {@code
 * "V17 Update 9"}) — {@link #normalizeVersionToken} strips a single leading non-digit run so the
 * comparison degrades to comparing the numeric remainder, which is good enough for the common
 * {@code V<number>[.<number>...]} shape but not guaranteed correct for every free-text variant
 * (e.g. {@code "Update 9"} suffixes are ignored entirely, not compared).
 */
final class SiemensCsafVersionRange {

    private static final Pattern CONSTRAINT_PATTERN = Pattern.compile("(>=|<=|>|<)\\s*([A-Za-z]*[0-9][\\w.\\-]*)");

    private SiemensCsafVersionRange() {
    }

    /** @return true if {@code itemVersion} is plausibly covered by {@code rangeSpec} — also true
     *          (deliberately permissive) when {@code rangeSpec} is null/blank/unparseable. */
    static boolean matches(String rangeSpec, String itemVersion) {
        if (rangeSpec == null || rangeSpec.isBlank() || itemVersion == null || itemVersion.isBlank()) {
            return true;
        }
        String normalized = rangeSpec.trim();
        String lower = normalized.toLowerCase(java.util.Locale.ROOT);
        boolean unboundedMarker = normalized.contains("*")
                || (lower.contains("all versions") && !normalized.contains("<") && !normalized.contains(">"));
        if (unboundedMarker) {
            return true;
        }

        List<Constraint> constraints = new ArrayList<>();
        Matcher matcher = CONSTRAINT_PATTERN.matcher(normalized);
        while (matcher.find()) {
            constraints.add(new Constraint(matcher.group(1), normalizeVersionToken(matcher.group(2))));
        }
        // No extractable constraint at all (and it wasn't the "all/*" marker checked above) — "can't
        // determine", err toward flagging it rather than silently excluding (§0-1 principle 1).
        if (constraints.isEmpty()) {
            return true;
        }
        return evaluateGroups(constraints, itemVersion);
    }

    private record Constraint(String comparator, String version) {
    }

    /** Groups {@code constraints} into consecutive (lower-bound, upper-bound) pairs per the {@code
     *  vers:} spec's disjoint-range shape and ORs across the groups — {@code itemVersion} matches if
     *  it falls within ANY one group's range (REVISE item 7).
     *
     *  <p>A single constraint (e.g. a lone {@code <3.0.0}, the common single-bound shape) is
     *  evaluated directly — it's inherently one-sided, not something to pair. Two or more
     *  constraints are split into consecutive pairs; each pair must be a {@code >}/{@code >=} lower
     *  bound immediately followed by a {@code <}/{@code <=} upper bound (both must hold — AND) or
     *  this can't cleanly determine the shape at all. If the constraint count is odd (a leftover
     *  constraint with no pairing partner) or any pair doesn't fit that lower-then-upper shape, this
     *  falls back to {@code true} — same "can't determine, possibly applicable" bias as the
     *  no-constraint-found case in {@link #matches}, rather than risk misreading an unfamiliar
     *  shape as either an AND or an OR. */
    private static boolean evaluateGroups(List<Constraint> constraints, String itemVersion) {
        if (constraints.size() == 1) {
            return satisfies(itemVersion, constraints.get(0));
        }
        if (constraints.size() % 2 != 0) {
            return true;
        }
        for (int i = 0; i < constraints.size(); i += 2) {
            Constraint lower = constraints.get(i);
            Constraint upper = constraints.get(i + 1);
            boolean lowerIsBound = lower.comparator().equals(">") || lower.comparator().equals(">=");
            boolean upperIsBound = upper.comparator().equals("<") || upper.comparator().equals("<=");
            if (!lowerIsBound || !upperIsBound) {
                return true; // unexpected operator arrangement — can't cleanly pair, fail open
            }
            if (satisfies(itemVersion, lower) && satisfies(itemVersion, upper)) {
                return true;
            }
        }
        return false;
    }

    private static boolean satisfies(String itemVersion, Constraint constraint) {
        int cmp = VersionUtils.compare(itemVersion, constraint.version());
        return switch (constraint.comparator()) {
            case "<" -> cmp < 0;
            case "<=" -> cmp <= 0;
            case ">" -> cmp > 0;
            case ">=" -> cmp >= 0;
            default -> true;
        };
    }

    /** Strips a leading run of non-digit characters (the {@code V}/{@code F}/{@code L} vendor
     *  prefixes) so {@link VersionUtils#compare} sees a numeric-leading string. */
    private static String normalizeVersionToken(String token) {
        int i = 0;
        while (i < token.length() && !Character.isDigit(token.charAt(i))) {
            i++;
        }
        return i < token.length() ? token.substring(i) : token;
    }
}
