package com.vulncheck.app.service;

import java.net.URI;

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

    /**
     * Reduces {@code uri} to {@code scheme://host<rawPath>} — dropping the query string and fragment
     * entirely — before it's safe to put in a log line or exception message (closed-mode backlog item
     * 421, generalizing the helper {@code CveOrgSyncService} introduced for itself in item 416).
     * Several of this app's external sync services (GHSA, OSV, Red Hat CSAF, Siemens CSAF, cve.org)
     * fetch through an allowlisted-host redirect chain where the final hop's query string can carry a
     * request-signing credential (e.g. a CDN's {@code sig=}/{@code jwt=} parameter) — that must never
     * reach a log line verbatim. Uses {@link URI#getRawPath()} (not the decoding {@link URI#getPath()})
     * so a maliciously crafted redirect {@code Location} can't smuggle a decoded control character into
     * the reduced value; {@link #sanitize} is still applied on top as this codebase's standard defense
     * against exactly that class of log-injection risk for any other externally-derived log value.
     *
     * <p><b>Non-hierarchical / relative URIs (PR#308 senior-review, REVISE round)</b>: {@link
     * URI#getHost()} is {@code null} both for opaque URIs (e.g. {@code mailto:}, {@code javascript:} —
     * no authority component at all) and for relative URIs with no scheme (e.g. a bare {@code
     * /path?query}). The naive {@code scheme + "://" + host + rawPath} concatenation above silently
     * stringifies those {@code null}s (observed: {@code mailto:a@b.com} became the near-meaningless
     * {@code "mailto://nullnull"}, and a relative path became {@code "null://null/relative/path"}),
     * which both looks like a real (bogus) host and throws away the diagnostic value of the log line.
     * Every caller of this class ({@code validatedUri}/{@code fetchBounded} and friends) already
     * rejects any URI with a null host before it's actually fetched, so this branch is reached only for
     * logging/error-message purposes, never as part of a fetch decision — but the log line still needs
     * to (a) never contain the raw query/fragment and (b) not read as a fabricated host. Uses {@link
     * URI#getRawSchemeSpecificPart()} (fragment is already a separate URI component, never included in
     * it) and additionally truncates at the first {@code '?'} so an opaque URI's query-like suffix
     * (e.g. {@code mailto:a@b.com?subject=...}) can't leak either.
     *
     * <p><b>Protocol-relative URIs (PR#308 senior-review, 2nd REVISE round)</b>: {@link URI#getHost()}
     * is non-null but {@link URI#getScheme()} is null for a protocol-relative reference (e.g. {@code
     * //evil.example.com/adv.json?sig=...}), which a feed-driven fetch ({@code
     * SiemensCsafSyncService} and friends resolving an untrusted {@code feedUrl}/{@code contentUrl}/
     * {@code hashUrl}) can hand to this method. That case still takes the hierarchical branch below
     * (it has a host), so the earlier null-host fix above didn't cover it: the naive {@code scheme +
     * "://"} concatenation stringified the null scheme into {@code "null://evil.example.com/..."} --
     * still no secret leak (the query is dropped the same as always) but a bogus-looking scheme
     * prepended to a real host. Falls back to a bare {@code "//"} prefix (matching the protocol-relative
     * syntax itself) when there's no scheme to print.
     */
    public static String sanitizeUrl(URI uri) {
        String host = uri.getHost();
        if (host == null) {
            String scheme = uri.getScheme();
            String label = scheme == null ? "(no scheme)" : scheme;
            return sanitize("(non-hierarchical URL, scheme=" + label + "): "
                    + withoutQuery(uri.getRawSchemeSpecificPart()));
        }
        String scheme = uri.getScheme();
        String prefix = scheme == null ? "//" : scheme + "://";
        String rawPath = uri.getRawPath();
        return sanitize(prefix + host + (rawPath == null ? "" : rawPath));
    }

    /** Truncates {@code schemeSpecificPart} at its first {@code '?'}, if any — used only by the
     *  non-hierarchical/relative branch of {@link #sanitizeUrl(URI)}, where the query component isn't
     *  parsed out separately by {@link URI} the way it is for a hierarchical URI. */
    private static String withoutQuery(String schemeSpecificPart) {
        if (schemeSpecificPart == null) {
            return "";
        }
        int queryStart = schemeSpecificPart.indexOf('?');
        return queryStart < 0 ? schemeSpecificPart : schemeSpecificPart.substring(0, queryStart);
    }

    /** {@link #sanitizeUrl(URI)} for a raw, not-yet-parsed URL string — falls back to a fixed
     *  placeholder if {@code url} isn't even a parseable URI. */
    public static String sanitizeUrl(String url) {
        try {
            return sanitizeUrl(URI.create(url));
        } catch (IllegalArgumentException e) {
            return "(unparseable URL)";
        }
    }
}
