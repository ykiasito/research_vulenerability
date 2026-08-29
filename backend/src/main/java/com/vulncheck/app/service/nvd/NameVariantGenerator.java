package com.vulncheck.app.service.nvd;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Pure, stateless string transforms for the two directions of short-form&lt;-&gt;long-form
 * product-name variance ("GNU Image Manipulation Program" &lt;-&gt; "GIMP", "Visual Studio Code"
 * &lt;-&gt; "VS Code"), plus a related vendor-prefix strip. Deliberately mechanical — derived only
 * from the input string's own words, never from a lookup table of specific known product-name
 * pairs (that layer, if it's ever needed, belongs in a separate/last-resort component per the
 * project's design constraint, not here).
 *
 * <p>Only the <b>contraction</b> direction (long form -&gt; acronym) is a plain string transform;
 * the <b>expansion</b> direction (abbreviation -&gt; long form, e.g. "VS Code" -&gt;
 * {@code visual_studio_code}) fundamentally can't be done as a string rewrite without external
 * knowledge of what the abbreviation stands for, and pg_trgm similarity was measured live
 * (2026-08-25) to be too low in both directions to find it either (e.g.
 * {@code similarity('visual_studio_code','vs code')} = 0.29, {@code similarity(...,'code')} =
 * 0.26 — both under the 0.3 product threshold). That direction is instead handled in {@code
 * Stage1IdentificationService#expandLeadingInitialism}, which anchors on the dictionary's own
 * product slugs (checking whether a candidate's leading words spell the query's leading token) —
 * a dictionary-backed search, not a string transform, so it doesn't belong in this class.
 */
public final class NameVariantGenerator {

    private NameVariantGenerator() {
    }

    /**
     * Below this many meaningful (non-connector) words, a mechanically derived acronym is too
     * short to be a safe search term against a dictionary with ~500K unique products — a short
     * acronym collides with far too much (this is exactly the kind of false-positive class prior
     * sessions found and fixed for containment matching; a lower bound here avoids reintroducing
     * it via a different code path).
     *
     * <p>Raised from 3 to 4 after a senior review (2026-08-25) measured real false positives at 3:
     * of 8 real 3-meaningful-word acronym-direction candidates tested against the live dictionary,
     * 7 were wrong (e.g. "animal-sniffer-annotations" -&gt; {@code pix_asa}, "javax.servlet-api"
     * -&gt; {@code jsa1500}, "org.projectlombok:lombok" -&gt; {@code oplynx}) — a 3-letter acronym
     * is simply too short to be a safe search term even with an exact-match acceptance check (see
     * {@code Stage1IdentificationService#acronymVariantSearch}). Every real 4-meaningful-word case
     * the design targets (e.g. "GNU Image Manipulation Program" -&gt; {@code gimp}) still clears
     * this bar.
     */
    private static final int MIN_MEANINGFUL_TOKENS_FOR_CONTRACTION = 4;

    /** Connector words skipped when building an acronym — standard English initialism convention
     *  ("GNU's Not Unix" style acronyms never count "is"/"not"/"a"/"the"). Deliberately small and
     *  used only to decide which letters contribute to an acronym, not to reject or accept a match
     *  outright — unlike the project's prior, deliberately-avoided "version qualifier" stop-word
     *  list, getting this list slightly wrong only costs one candidate query, never a false
     *  positive or a silently dropped real product. */
    private static final Set<String> ACRONYM_CONNECTOR_WORDS =
            Set.of("a", "an", "the", "of", "for", "and", "or", "&");

    /**
     * Long-form -&gt; acronym contraction, e.g. "GNU Image Manipulation Program" -&gt; "GIMP".
     * Purely mechanical: first letter of each meaningful word. Returns {@code null} (nothing to
     * try) when {@code productName} doesn't have enough real words to make a safe acronym.
     */
    public static String contractToAcronym(String productName) {
        List<String> tokens = meaningfulTokens(productName);
        if (tokens.size() < MIN_MEANINGFUL_TOKENS_FOR_CONTRACTION) {
            return null;
        }
        StringBuilder acronym = new StringBuilder();
        for (String token : tokens) {
            acronym.append(token.charAt(0));
        }
        return acronym.toString();
    }

    /**
     * Strips a leading vendor-name prefix from {@code productName} when the item's own vendor
     * field literally starts the product string (e.g. productName "Broadcom Norton 360" with
     * vendor "Broadcom" -&gt; "Norton 360") — the same "vendor diluted the query" problem the
     * dictionary search's own vendor-as-ranking-signal fix (see {@code
     * Stage1IdentificationService}'s class javadoc) addressed for the vendor *field*, generalized
     * to when the vendor text is instead baked directly into the product name itself.
     *
     * <p>Requires a real word boundary right after the vendor prefix (not a mid-word cut) — e.g.
     * vendor "Go" must never strip the leading "Go" out of "Google Chrome". Returns {@code null}
     * when there's nothing to strip, or nothing meaningful left afterward.
     */
    public static String stripLeadingVendor(String productName, String vendor) {
        if (productName == null || productName.isBlank() || vendor == null || vendor.isBlank()) {
            return null;
        }
        String trimmedVendor = vendor.trim();
        String lowerProduct = productName.toLowerCase(Locale.ROOT);
        String lowerVendor = trimmedVendor.toLowerCase(Locale.ROOT);
        if (!lowerProduct.startsWith(lowerVendor)) {
            return null;
        }
        String remainder = productName.substring(trimmedVendor.length());
        if (!remainder.isEmpty() && Character.isLetterOrDigit(remainder.charAt(0))) {
            // No word boundary right after the prefix — this is a mid-word coincidence
            // ("Go" against "Google"), not the vendor actually prefixing the product name.
            return null;
        }
        remainder = remainder.replaceFirst("^[^a-zA-Z0-9]+", "").trim();
        return remainder.isBlank() ? null : remainder;
    }

    private static List<String> meaningfulTokens(String value) {
        if (value == null) {
            return List.of();
        }
        return Arrays.stream(value.toLowerCase(Locale.ROOT).split("[^a-zA-Z0-9]+"))
                .filter(token -> !token.isEmpty() && !ACRONYM_CONNECTOR_WORDS.contains(token))
                .toList();
    }
}
