package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** Closed-mode backlog items 223/258: CR/LF must not survive into a log line. */
class LogSanitizerTest {

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
