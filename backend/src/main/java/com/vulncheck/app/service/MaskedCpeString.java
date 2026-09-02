package com.vulncheck.app.service;

import java.util.Objects;

/**
 * A CPE 2.3 string whose version field (the 5th colon-separated segment) is always forced to
 * {@code "*"} — the LLM microservice must never be shown a dictionary/name-variant candidate's
 * real cataloged version. Showing the LLM the candidate's own historical version was observed to
 * make it falsely reject correct vendor/product matches purely because that version differed from
 * the item's; Stage2 substitutes the item's real version when it later queries NVD anyway (see
 * {@code CpeUtils.buildCpe}), so the specific cataloged version is irrelevant to vendor/product
 * identity in the first place.
 *
 * <p>Closed-mode backlog items 169/170 (senior review, 2026-09-01, PR#91): before this type
 * existed, {@link Stage1AiArbitration#disambiguateCpeCandidates} and {@link
 * Stage1AiArbitration#verifyVariantDerivedCpeMatchWithAi} both accepted plain {@code String}s and
 * relied on the caller ({@code Stage1IdentificationService}) to have already masked them — a
 * caller-discipline invariant with no compiler backing. This record makes "sent-to-the-LLM CPE
 * strings are always masked" a structural guarantee instead of a discipline: the masking itself
 * happens unconditionally inside the compact canonical constructor, so there is no code path
 * (direct construction, the {@link #ofRawCpeString} factory, or anything added later) that can
 * produce an instance whose {@link #value()} carries an unmasked version segment. (A record's
 * canonical constructor cannot be made less accessible than the public record itself — masking
 * inside the constructor, rather than trying to hide it, is what makes the guarantee airtight
 * either way.)
 */
public record MaskedCpeString(String value) {

    public MaskedCpeString {
        Objects.requireNonNull(value, "value");
        value = maskVersionSegment(value);
    }

    /** Readability alias for {@code new MaskedCpeString(rawCpeString)} — masking happens either
     *  way (see class javadoc), this just makes call sites read as "masking a raw CPE" rather than
     *  "wrapping an already-masked one". */
    public static MaskedCpeString ofRawCpeString(String rawCpeString) {
        return new MaskedCpeString(rawCpeString);
    }

    private static String maskVersionSegment(String cpeString) {
        String[] parts = cpeString.split(":", -1);
        if (parts.length > 5) {
            parts[5] = "*";
        }
        return String.join(":", parts);
    }
}
