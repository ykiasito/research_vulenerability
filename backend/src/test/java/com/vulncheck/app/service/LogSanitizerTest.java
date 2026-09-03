package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Closed-mode backlog items 223/258/276: CR/LF/ESC must not survive into a log line. */
class LogSanitizerTest {

    /** Same named constant as {@link LogSanitizer}'s own, so these tests read the code point the
     *  same way the class under test documents it, without a raw control character sitting in this
     *  source file either. */
    private static final char ESC = '\u001B';

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
    void leavesOrdinaryValueUnchanged() {
        assertThat(LogSanitizer.sanitize("normal-package-name")).isEqualTo("normal-package-name");
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
