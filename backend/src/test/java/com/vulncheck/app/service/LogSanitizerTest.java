package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Closed-mode backlog items 223/258/276: every C0 control character (CR/LF/TAB/ESC/BS/VT/FF/NUL)
 *  plus DEL must not survive into a log line. */
class LogSanitizerTest {

    /** Same code points {@link LogSanitizer} itself documents, named here too so these tests read
     *  the same way without a raw control character sitting in this source file. */
    private static final char ESC = '\u001B';
    private static final char BS = '\u0008';
    private static final char VT = '\u000B';
    private static final char FF = '\u000C';
    private static final char NUL = '\u0000';
    private static final char DEL = '\u007F';
    private static final char NEL = '\u0085';
    private static final char LINE_SEPARATOR = '\u2028';
    private static final char PARAGRAPH_SEPARATOR = '\u2029';

    @Test
    void removesCarriageReturnAndLineFeed() {
        assertThat(LogSanitizer.sanitize("foo\r\nbar")).isEqualTo("foobar");
    }

    @Test
    void removesBareCarriageReturn() {
        assertThat(LogSanitizer.sanitize("foo\rbar")).isEqualTo("foobar");
    }

    @Test
    void removesBareLineFeed() {
        assertThat(LogSanitizer.sanitize("foo\nbar")).isEqualTo("foobar");
    }

    @Test
    void forgedLogLineIsNeutralized() {
        String forged = "legit-package\n2026-09-03 00:00:00 INFO fake log line injected by CSV";
        String sanitized = LogSanitizer.sanitize(forged);
        assertThat(sanitized).doesNotContain("\n").doesNotContain("\r");
        assertThat(sanitized).isEqualTo("legit-package2026-09-03 00:00:00 INFO fake log line injected by CSV");
    }

    @Test
    void removesAnsiEscapeCharacter() {
        assertThat(LogSanitizer.sanitize("foo" + ESC + "[31mbar")).isEqualTo("foo[31mbar");
    }

    @Test
    void forgedAnsiSequenceIsNeutralized() {
        // Task-backlog item 276: a raw ANSI erase-line/recolor sequence in a CSV-derived value
        // could otherwise repaint or hide what an operator's terminal displays when tailing docker
        // compose logs. Confirms the ESC byte itself (not just CR/LF) is stripped -- the rest of
        // the sequence's bracket/digit text survives as inert, visible characters, but with no lone
        // ESC left for a terminal to interpret as an escape-sequence introducer.
        String forged = "legit-package" + ESC + "[2K" + ESC + "[31mFAKE ADMIN LOGIN" + ESC + "[0m";
        String sanitized = LogSanitizer.sanitize(forged);
        assertThat(sanitized).doesNotContain(String.valueOf(ESC));
        assertThat(sanitized).isEqualTo("legit-package[2K[31mFAKE ADMIN LOGIN[0m");
    }

    @Test
    void removesCarriageReturnLineFeedAndAnsiEscapeTogether() {
        assertThat(LogSanitizer.sanitize("foo\r\n" + ESC + "[31mbar")).isEqualTo("foo[31mbar");
    }

    @Test
    void removesBackspaceInsteadOfLettingItMaskPrecedingCharactersInATerminal() {
        // Task-backlog item 276 REVISE (senior-reviewer): unlike CR/LF (which forge a whole extra
        // line) or ESC (which needs a full ANSI sequence), a bare backspace (BS) moves a terminal's
        // cursor left WITHOUT erasing anything -- so a CSV-derived product name like
        // "log4j\b\b\b\b\bsafe!" tails as "safe!" in a live `docker compose logs` view, the exact
        // live-terminal-display-manipulation risk this backlog item exists to close. Confirms BS
        // itself is removed, not just that the visible rendering happens to look fine.
        String forged = "log4j" + String.valueOf(BS).repeat(5) + "safe!";
        String sanitized = LogSanitizer.sanitize(forged);
        assertThat(sanitized).doesNotContain(String.valueOf(BS));
        assertThat(sanitized).isEqualTo("log4jsafe!");
    }

    @Test
    void removesVerticalTab() {
        assertThat(LogSanitizer.sanitize("foo" + VT + "bar")).isEqualTo("foobar");
    }

    @Test
    void removesFormFeed() {
        assertThat(LogSanitizer.sanitize("foo" + FF + "bar")).isEqualTo("foobar");
    }

    @Test
    void removesNulByte() {
        assertThat(LogSanitizer.sanitize("foo" + NUL + "bar")).isEqualTo("foobar");
    }

    @Test
    void removesDelete() {
        assertThat(LogSanitizer.sanitize("foo" + DEL + "bar")).isEqualTo("foobar");
    }

    @Test
    void removesTab() {
        // Deliberate policy call (item 276 REVISE), asserted explicitly rather than left implicit:
        // a CSV-derived value has no legitimate reason to carry a literal tab into a single-line
        // log message, so TAB is swept up with the rest of the C0 control block rather than
        // special-cased as "whitespace, therefore harmless".
        assertThat(LogSanitizer.sanitize("foo\tbar")).isEqualTo("foobar");
    }

    @Test
    void doesNotRemoveNelLineSeparatorOrParagraphSeparator() {
        // Pins the item 276 decision to deliberately NOT strip these three (see LogSanitizer's own
        // class javadoc for why) -- a future change to widen the stripped set again must not
        // silently sweep these back in without that decision being revisited on purpose.
        String value = "foo" + NEL + "bar" + LINE_SEPARATOR + "baz" + PARAGRAPH_SEPARATOR + "qux";
        assertThat(LogSanitizer.sanitize(value)).isEqualTo(value);
    }

    @Test
    void leavesOrdinaryValueUnchanged() {
        assertThat(LogSanitizer.sanitize("normal-package-name")).isEqualTo("normal-package-name");
    }

    @Test
    void returnsTheSameInstanceWhenNoControlCharacterIsPresent() {
        // Task-backlog item 276 REVISE: sanitize() must only allocate when it actually finds
        // something to strip -- confirms the no-op fast path returns the exact same String
        // instance, not just an equal one, for the overwhelmingly common case of an already-clean
        // value.
        String value = "normal-package-name";
        assertThat(LogSanitizer.sanitize(value)).isSameAs(value);
    }

    @Test
    void handlesNull() {
        assertThat(LogSanitizer.sanitize(null)).isNull();
    }

    @Test
    void handlesEmpty() {
        assertThat(LogSanitizer.sanitize("")).isEmpty();
    }
}
