package com.vulncheck.app.service.nvd;

import com.vulncheck.app.service.vuln.VersionUtils;
import java.util.ArrayList;
import java.util.List;

/**
 * Minimal CPE 2.3 string helpers.
 *
 * <p>Segment splitting is escape-aware ({@link #splitCpeSegments}), not a plain {@code split(":")}
 * — CPE 2.3 backslash-escapes reserved characters (including {@code :}) within a segment, and a
 * real NVD dictionary entry can and does contain one, e.g. Perl's {@code HTTP::Session} module:
 * {@code cpe:2.3:a:ktat:http\:\:session:0.01_01:*:*:*:*:perl:*:*}. A naive split mis-indexes every
 * segment from the escaped one onward (senior review, job 37 root-cause: this silently corrupted
 * that exact row's persisted CPE and hid its real {@code target_sw=perl} scoping from the crates.io
 * gate, letting it masquerade as the unrelated Rust {@code hyper:http} crate).
 */
public final class CpeUtils {

    private CpeUtils() {
    }

    /**
     * Splits a CPE 2.3 string on unescaped {@code :} only — a {@code \:} sequence stays part of its
     * enclosing segment rather than being treated as a delimiter. Never throws on malformed input
     * (e.g. a trailing lone backslash is just appended literally), mirroring the previous naive
     * splitter's own permissiveness.
     */
    private static List<String> splitCpeSegments(String cpeString) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < cpeString.length(); i++) {
            char c = cpeString.charAt(i);
            if (c == '\\' && i + 1 < cpeString.length()) {
                current.append(c).append(cpeString.charAt(i + 1));
                i++;
            } else if (c == ':') {
                segments.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        segments.add(current.toString());
        return segments;
    }

    /** cpe:2.3:part:vendor:product:version:... — extracts just vendor/product. */
    public static VendorProduct parseVendorProduct(String cpeString) {
        if (cpeString == null) {
            return null;
        }
        List<String> parts = splitCpeSegments(cpeString);
        if (parts.size() <= 4) {
            return null;
        }
        return new VendorProduct(parts.get(3), parts.get(4));
    }

    /** Builds a fully-qualified CPE 2.3 {@code part=a} (application) string for the given
     *  vendor/product/version — for callers that only ever deal with applications/libraries (e.g.
     *  {@code BundledComponentResearchService}'s embedded-component adjudication, which has no
     *  source CPE to read a real part from in the first place). Callers that already have an
     *  identified product's own CPE string — and so can and should preserve its real part instead of
     *  assuming {@code a} — must use {@link #buildCpe(String, String, String, String)} together with
     *  {@link #parsePart}. */
    public static String buildCpe(String vendor, String product, String version) {
        return buildCpe("a", vendor, product, version);
    }

    /**
     * Builds a fully-qualified CPE 2.3 string for the given part/vendor/product/version.
     *
     * <p>task-backlog item 39 (senior review, 2026-08-30, PR#16 review): {@link
     * #buildCpe(String, String, String)} always hardcoded {@code part=a}, so {@code
     * NvdVulnerabilitySource#find} rebuilding a candidate's CPE through it silently queried NVD for
     * a CPE name that doesn't exist for {@code part=o} (operating system) products — job 194's
     * {@code cpe:2.3:o:paloaltonetworks:pan-os:10.2.4} and {@code cpe:2.3:o:mikrotik:routeros:6.49.10}
     * were both queried as {@code part=a}, so NVD (which only has {@code part=o} rows for them)
     * returned zero results: a silent false negative, not a visible error. This overload takes the
     * real part explicitly instead.
     */
    public static String buildCpe(String part, String vendor, String product, String version) {
        return "cpe:2.3:" + part + ":" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*";
    }

    /**
     * Extracts just the part segment (index 2 — {@code a}/{@code o}/{@code h}) from a CPE 2.3
     * string, defaulting to {@code "a"} when the string is null or too short to carry one — the
     * same permissive default {@link #buildCpe(String, String, String)} has always applied, so a
     * caller that can't determine a real part (e.g. a malformed or absent source CPE) keeps behaving
     * exactly as before this method existed.
     */
    public static String parsePart(String cpeString) {
        if (cpeString == null) {
            return "a";
        }
        List<String> parts = splitCpeSegments(cpeString);
        if (parts.size() <= 2 || parts.get(2).isBlank()) {
            return "a";
        }
        return parts.get(2);
    }

    /**
     * Rebuilds {@code cpeString} with only its version segment (index 5, 0-indexed) replaced by
     * {@code newVersion}, and its update segment (index 6) reset to {@code *} — every other segment
     * (edition, language, sw_edition, target_sw, target_hw, other) is preserved exactly as parsed.
     * Unlike {@link #buildCpe}, which always discards everything past version, this doesn't
     * silently broaden a candidate's scope: a dictionary entry scoped by {@code target_sw} (e.g. a
     * Jenkins plugin's CPE is scoped {@code target_sw=jenkins}) really does exist in NVD only with
     * that scoping — persisting it with target_sw silently reset to {@code *} produces a CPE string
     * that doesn't actually exist in NVD (senior review, job 36 root-cause: {@code
     * cpe:2.3:a:jenkins:slack:1.0:*:*:*:*:jenkins:*:*} was turning into
     * {@code cpe:2.3:a:jenkins:slack:4.29.149:*:*:*:*:*:*:*}).
     *
     * <p>The update segment (index 6) is reset rather than preserved, unlike every other trailing
     * segment: it's the dictionary candidate's own historical qualifier (e.g. {@code beta8}) for a
     * <em>different</em> catalogued version than the item's real, just-substituted one — carrying it
     * forward verbatim produced a persisted CPE like {@code ...:webpack:5.86.0:beta8:...} where
     * "beta8" has nothing to do with the actual installed 5.86.0 (senior review, job 37 root-cause).
     * Target_sw and the rest are genuinely part of the matched product's own identity/scoping, not
     * tied to one specific cataloged version, so they still carry forward unchanged.
     *
     * @return {@code cpeString} unchanged if it doesn't have enough segments to contain a version
     *         field at all (mirrors {@link #parseVendorProduct}'s own defensive fallback).
     */
    public static String withVersion(String cpeString, String newVersion) {
        if (cpeString == null) {
            return null;
        }
        List<String> parts = splitCpeSegments(cpeString);
        if (parts.size() <= 5) {
            return cpeString;
        }
        parts.set(5, newVersion);
        if (parts.size() > 6) {
            parts.set(6, "*");
        }
        return String.join(":", parts);
    }

    /**
     * Extracts just the version segment (index 5) from a CPE 2.3 string, defaulting to {@code "*"}
     * ("any version" -- CPE 2.3's own wildcard) when the string is too short to carry one. Same
     * escape-aware splitting as every other accessor here.
     *
     * <p>Closed-mode backlog item 251 (B4, senior-reviewer REVISE item 10): moved here from {@code
     * NvdMirrorAbVerificationRunner}'s disposable A/B verification harness (which duplicated its
     * own escape-aware splitter rather than depending on production code — see that class's own
     * javadoc for why) once the harness's GATE PASSED conclusion made this parsing logic a real
     * production dependency (production {@code NvdVulnerabilitySource} needs the exact same
     * criteria-version extraction the harness used to compute the numbers senior-reviewer signed off
     * on) — the harness now delegates here instead of keeping an independent copy, per backlog item
     * 254's lesson about the same CPE-parsing bug being rediscovered three separate times across
     * independently-maintained copies.
     */
    public static String parseVersion(String cpeString) {
        if (cpeString == null) {
            return "*";
        }
        List<String> parts = splitCpeSegments(cpeString);
        return parts.size() > 5 ? parts.get(5) : "*";
    }

    /**
     * One {@code cpeMatch} entry's version applicability against {@code itemVersion} — mirrors NVD's
     * own documented semantics: if the match's own {@code criteriaVersion} (see {@link
     * #parseVersion}) carries a concrete (non-{@code *}) version segment, that's an exact-version
     * match with no range fields to consult; a {@code *} version defers to the four range bound
     * arguments (all-null means unconditionally vulnerable at every version).
     *
     * <p>A {@code -} version segment is CPE 2.3's own "not applicable" marker, not a synonym for
     * {@code *} ("any version") — this deliberately never matches on a bare {@code -} (fail-closed)
     * rather than guessing at whatever paired AND-node condition a flattened, node-less table like
     * {@code nvd_cve_cpe_match} has no column to represent. See {@code NvdMirrorAbVerificationRunner}
     * class javadoc's "Known modeling gap" note (closed-mode backlog item 202) for the schema
     * limitation this defends against, and item 251 REVISE item 10 for why this predicate now lives
     * here instead of being duplicated between that disposable test harness and production {@code
     * NvdVulnerabilitySource}.
     *
     * @return whether {@code itemVersion} falls within the range/exact-match this one {@code
     *         cpeMatch} entry describes — see {@link VersionUtils#compare} for the numeric-aware
     *         comparator the range checks below are built on.
     */
    public static boolean versionInRange(String itemVersion, String criteriaVersion, String startIncluding,
            String startExcluding, String endIncluding, String endExcluding) {
        if ("-".equals(criteriaVersion)) {
            return false;
        }
        if (!"*".equals(criteriaVersion)) {
            return criteriaVersion.equalsIgnoreCase(itemVersion);
        }
        if (startIncluding != null && VersionUtils.compare(itemVersion, startIncluding) < 0) {
            return false;
        }
        if (startExcluding != null && VersionUtils.compare(itemVersion, startExcluding) <= 0) {
            return false;
        }
        if (endIncluding != null && VersionUtils.compare(itemVersion, endIncluding) > 0) {
            return false;
        }
        if (endExcluding != null && VersionUtils.compare(itemVersion, endExcluding) >= 0) {
            return false;
        }
        return true;
    }

    public record VendorProduct(String vendor, String product) {
    }
}
