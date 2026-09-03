package com.vulncheck.app.service;

/**
 * Strips CR/LF and the ANSI escape character (ESC, U+001B) from a value before it's interpolated
 * into a log line — closed-mode backlog items 223/258/276 (senior-reviewer, PR#141/#166/2026-09-04
 * reviews): several services log CSV-derived values (product names, registry package/module names,
 * NVD keyword-search terms) verbatim, so a CSV cell containing {@code \r}/{@code \n} could forge
 * extra, fake-looking log lines (log injection) in whatever log viewer an operator is reading. The
 * values themselves aren't otherwise validated at the point they reach these log calls (that's a
 * separate, already-tracked concern — see backlog item 253 for the URL-encoding side of the same
 * untrusted-CSV-value problem).
 *
 * <p><b>ESC (task-backlog item 276)</b>: this app's logs are read either via {@code docker compose
 * logs} or by opening the bind-mounted log file directly (see {@code logging.file.name} in
 * application.yml) — both terminal-based, not through a dedicated log-aggregation UI that would
 * already neutralize control sequences of its own accord. An unescaped ANSI sequence (e.g. {@code
 * ESC[31m} to recolor text, {@code ESC[2K} to erase the current line) in a CSV-derived value can
 * therefore actually manipulate what an operator's terminal displays — hide or repaint a log line,
 * not just forge an extra one the way bare CR/LF does — when they tail these logs live. Cheap to
 * close alongside CR/LF: one more character stripped by the same pass.
 *
 * <p><b>Deliberately NOT stripping U+0085 (NEL) / U+2028 (LINE SEPARATOR) / U+2029 (PARAGRAPH
 * SEPARATOR)</b>, considered and declined as part of the same review (item 276): unlike ANSI
 * escapes, these three have no effect on either viewer this app's logs actually reach (a plain
 * terminal via {@code docker compose logs}, or the raw file) — they only matter to a text editor or
 * log-processing tool that specifically treats them as line breaks, and this project's stack has
 * neither. Stripping them would be defense against a viewer this app doesn't have, at the cost of
 * three more special cases every future reader of this class has to reason about.
 */
public final class LogSanitizer {

    /** The ANSI escape character (ESC) — kept as a named constant rather than an inline {@code
     *  '\u001B'} literal so both call sites below (and any future reader) can see at a glance which
     *  control character this is, without needing to look up the code point. */
    private static final char ESC = '\u001B';

    private LogSanitizer() {
    }

    /**
     * Returns {@code value} with every {@code \r}/{@code \n}/ESC (U+001B) removed, or {@code value}
     * unchanged (including {@code null}) when it contains none of them — never throws, never
     * rewrites anything else about the value (case, whitespace, length), so a log line's readability
     * for the overwhelming majority of legitimate values is unaffected.
     */
    public static String sanitize(String value) {
        if (value == null
                || value.indexOf('\r') < 0 && value.indexOf('\n') < 0 && value.indexOf(ESC) < 0) {
            return value;
        }
        return value.replace("\r", "").replace("\n", "").replace(String.valueOf(ESC), "");
    }
}
