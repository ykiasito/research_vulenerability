package com.vulncheck.app.service;

/**
 * Pure, stateless CSV-ingestion-time cleanup of user-added annotation noise in the product-name
 * column — e.g. {@code "swA(補足)"} or {@code "swB※備考"} — before that value is used as the
 * {@code product_name} Stage1 identification searches against the CPE dictionary/registries with.
 * Applied exactly once, at CSV parse time (see {@code ResearchJobService#createJob}); the caller
 * is responsible for separately keeping the untouched original string (the raw CSV cell) around
 * for display/export, since a user who typed an annotation still wants to see what they actually
 * typed when reviewing results.
 *
 * <p>Deliberately distinct from {@code NameVariantGenerator}: that class derives alternate search
 * terms from an already-clean product name (acronym contraction, vendor-prefix stripping) and
 * runs repeatedly during Stage1 lookup; this class removes noise from the raw CSV input and runs
 * once, before Stage1 ever sees the value.
 */
public final class ProductNameAnnotationStripper {

    private ProductNameAnnotationStripper() {
    }

    /**
     * Everything from the first occurrence of any of these onward is annotation noise to be
     * dropped. Half-width {@code (} and full-width {@code （} are treated identically, and so is
     * {@code ※}; whichever of the three appears earliest in the string wins (handles the
     * "both an annotation in parens and a ※ remark" case, e.g. {@code "swA(注1)※備考"} ->
     * {@code "swA"}, correctly regardless of which one the CSV author put first).
     *
     * <p>Deliberately does <b>not</b> look for a matching closing bracket at all: an opening
     * bracket is treated as "everything after this is noise" outright, so an unclosed bracket
     * (e.g. {@code "swA(ホニャホニャ"}, a closing-bracket typo) is stripped exactly the same way a
     * well-formed {@code "swA(ホニャホニャ)"} is — there is no well-formed/malformed distinction
     * to make here, since the closing bracket's presence or absence never changes what gets kept.
     * A stray closing bracket with no matching opener (e.g. {@code "swA)note"}) is conversely
     * <i>not</i> treated as a cut point at all — there's no "start of the annotation" to cut from
     * in that case, so the name is left alone (only trimmed).
     */
    private static final char[] CUT_MARKERS = {'(', '（', '※'};

    /**
     * Strips CSV product-name annotation noise per the class javadoc. Returns {@code null}
     * unchanged (nothing to strip). When the cut would leave nothing behind (the annotation
     * marker was the very first character, e.g. {@code "（全部注記）"} or {@code "※全部注記"}),
     * falls back to the original (trimmed) input rather than handing Stage1 an empty search term
     * — a name that's entirely "annotation" per this heuristic is far more likely a heuristic
     * miss than a genuinely empty product name (CSV parsing already rejects a blank product-name
     * cell outright, so this fallback only ever fires on a non-blank input that happens to start
     * with a cut marker).
     */
    public static String strip(String productName) {
        if (productName == null) {
            return null;
        }
        int cutIndex = -1;
        for (char marker : CUT_MARKERS) {
            int idx = productName.indexOf(marker);
            if (idx >= 0 && (cutIndex == -1 || idx < cutIndex)) {
                cutIndex = idx;
            }
        }
        if (cutIndex < 0) {
            return productName.trim();
        }
        String stripped = productName.substring(0, cutIndex).trim();
        return stripped.isEmpty() ? productName.trim() : stripped;
    }
}
