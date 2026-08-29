package com.vulncheck.app.service.nvd;

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

    /** Builds a fully-qualified CPE 2.3 application string for the given vendor/product/version. */
    public static String buildCpe(String vendor, String product, String version) {
        return "cpe:2.3:a:" + vendor + ":" + product + ":" + version + ":*:*:*:*:*:*:*";
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

    public record VendorProduct(String vendor, String product) {
    }
}
