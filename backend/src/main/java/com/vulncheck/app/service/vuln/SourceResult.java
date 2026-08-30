package com.vulncheck.app.service.vuln;

import java.util.List;

/**
 * The outcome of one {@link VulnerabilitySource#find} call — carries {@code findings} plus
 * whether the source actually completed its query ({@code succeeded}). Before this type existed,
 * every source collapsed both "queried fine, genuinely nothing found" and "the query itself
 * failed (network error, rate limit, ...)" into the same empty {@code List<VulnFinding>}, so
 * Stage2's aggregator (see {@code Stage2VulnerabilityResearchService}) couldn't tell them apart —
 * a rate-limited/down source silently masqueraded as a real zero-findings answer and triggered a
 * paid Stage4 AI web-search "because nothing was found", when really nothing was ever checked.
 */
public record SourceResult(List<VulnFinding> findings, boolean succeeded) {

    /** The query completed — {@code findings} may legitimately be empty (including "this source
     *  doesn't apply to this item", e.g. unsupported ecosystem or no CPE, which is a real answer
     *  of "nothing here", not a failure). */
    public static SourceResult success(List<VulnFinding> findings) {
        return new SourceResult(findings, true);
    }

    /** The query could not be completed (HTTP error, rate limit, unexpected exception, ...) — the
     *  aggregator must not treat this the same as a genuine zero-findings result. */
    public static SourceResult failure() {
        return new SourceResult(List.of(), false);
    }
}
