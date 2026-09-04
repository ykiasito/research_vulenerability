package com.vulncheck.app.service;

/**
 * Strips every C0 control character (U+0000-U+001F, including CR/LF/TAB/ESC/BS/VT/FF/NUL) plus DEL
 * (U+007F) from a value before it's interpolated into a log line — closed-mode backlog items
 * 223/258/276 (senior-reviewer, PR#141/#166/2026-09-04 reviews, REVISE round): several services log
 * CSV-derived values (product names, registry package/module names, NVD keyword-search terms)
 * verbatim, so a CSV cell containing {@code \r}/{@code \n} could forge extra, fake-looking log lines
 * (log injection) in whatever log viewer an operator is reading. The values themselves aren't
 * otherwise validated at the point they reach these log calls (that's a separate, already-tracked
 * concern — see backlog item 253 for the URL-encoding side of the same untrusted-CSV-value problem).
 *
 * <p><b>C0 control characters generally (task-backlog item 276, REVISE)</b>: this app's logs are
 * read either via {@code docker compose logs} or by opening the bind-mounted log file directly (see
 * {@code logging.file.name} in application.yml) — both terminal-based, not through a dedicated
 * log-aggregation UI that would already neutralize control characters of its own accord. The first
 * pass of this fix only stripped ESC (to block ANSI escape sequences like {@code ESC[31m}/{@code
 * ESC[2K}), but that missed the rest of the same threat class: backspace (BS, U+0008) moves a
 * terminal's cursor left *without* erasing anything, so a CSV-derived product name like {@code
 * "log4j\b\b\b\b\bsafe!"} tails as {@code "safe!"} — the exact live-terminal-display-manipulation
 * risk item 276 set out to close, just via a different single byte than ESC. Vertical tab (VT,
 * U+000B) and form feed (FF, U+000C) are the same story (page/line-advance side effects some
 * terminals still honor), and NUL (U+0000) can truncate a C-string-based log sink's line entirely.
 * Rather than adding these one at a time as each is independently rediscovered, this now strips the
 * whole C0 control block in one range check — TAB (U+0009) included, since a CSV-derived value has
 * no legitimate reason to inject a tab into a single-line log message either — plus DEL (U+007F),
 * the one non-C0 control character with the same terminal-display-manipulation profile.
 *
 * <p><b>Deliberately NOT stripping U+0085 (NEL) / U+2028 (LINE SEPARATOR) / U+2029 (PARAGRAPH
 * SEPARATOR)</b>, considered and declined as part of the same review (item 276): unlike C0 control
 * characters, these three have no effect on either viewer this app's logs actually reach (a plain
 * terminal via {@code docker compose logs}, or the raw file) — they only matter to a text editor or
 * log-processing tool that specifically treats them as line breaks, and this project's stack has
 * neither. Stripping them would be defense against a viewer this app doesn't have, at the cost of
 * three more special cases every future reader of this class has to reason about.
 */
public final class LogSanitizer {

    private LogSanitizer() {
    }

    /**
     * Returns {@code value} with every C0 control character (U+0000-U+001F) and DEL (U+007F)
     * removed, or the exact same {@code value} instance (including {@code null}) when it contains
     * none of them — never throws, never rewrites anything else about the value (case or length —
     * note this now includes TAB unlike this method's original CR/LF-only version, since a
     * CSV-derived value has no legitimate reason to carry one into a single log line), so a log
     * line's readability for the overwhelming majority of legitimate values is unaffected. Single
     * pass: only allocates a {@link StringBuilder} once it actually finds a character to strip,
     * copying everything scanned before that point in one shot, so the common case (no control
     * characters at all) costs nothing beyond the scan itself.
     */
    public static String sanitize(String value) {
        if (value == null) {
            return null;
        }
        StringBuilder result = null;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (isStrippedControlCharacter(c)) {
                if (result == null) {
                    result = new StringBuilder(value.length());
                    result.append(value, 0, i);
                }
            } else if (result != null) {
                result.append(c);
            }
        }
        return result == null ? value : result.toString();
    }

    /** C0 control block (U+0000-U+001F) plus DEL (U+007F) — see this class's own javadoc for why
     *  every one of these, not just CR/LF/ESC, needs to come out of a log line. */
    private static boolean isStrippedControlCharacter(char c) {
        return c <= 0x1F || c == 0x7F;
    }
}
