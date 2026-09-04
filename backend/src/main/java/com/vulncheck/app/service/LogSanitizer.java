package com.vulncheck.app.service;

/**
 * Strips CR/LF from a value before it's interpolated into a log line — closed-mode backlog items
 * 223/258 (senior-reviewer, PR#141/#166 reviews): several services log CSV-derived values (product
 * names, registry package/module names, NVD keyword-search terms) verbatim, so a CSV cell containing
 * {@code \r}/{@code \n} could forge extra, fake-looking log lines (log injection) in whatever log
 * viewer an operator is reading. The values themselves aren't otherwise validated at the point they
 * reach these log calls (that's a separate, already-tracked concern — see backlog item 253 for the
 * URL-encoding side of the same untrusted-CSV-value problem), so this only needs to neutralize the
 * two characters that let one log line masquerade as several.
 */
public final class LogSanitizer {

    private LogSanitizer() {
    }

    /**
     * Returns {@code value} with every {@code \r}/{@code \n} removed, or {@code value} unchanged
     * (including {@code null}) when it contains neither — never throws, never rewrites anything else
     * about the value (case, whitespace, length), so a log line's readability for the overwhelming
     * majority of legitimate values is unaffected.
     */
    public static String sanitize(String value) {
        if (value == null || value.indexOf('\r') < 0 && value.indexOf('\n') < 0) {
            return value;
        }
        return value.replace("\r", "").replace("\n", "");
    }
}
