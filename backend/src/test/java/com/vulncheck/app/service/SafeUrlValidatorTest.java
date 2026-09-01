package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SafeUrlValidatorTest {

    @Test
    void allowsHttpAndHttpsUnchanged() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("https://example.com/advisory/CVE-2024-12345"))
                .isEqualTo("https://example.com/advisory/CVE-2024-12345");
        assertThat(SafeUrlValidator.sanitizeHttpUrl("http://example.com/a"))
                .isEqualTo("http://example.com/a");
    }

    @Test
    void schemeMatchingIsCaseInsensitive() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("HTTPS://example.com/a"))
                .isEqualTo("HTTPS://example.com/a");
    }

    @Test
    void rejectsJavascriptScheme() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("javascript:alert(document.cookie)")).isNull();
    }

    @Test
    void rejectsDataScheme() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("data:text/html,<script>alert(1)</script>")).isNull();
    }

    @Test
    void rejectsFileScheme() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("file:///etc/passwd")).isNull();
    }

    @Test
    void rejectsSchemelessValue() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl("example.com/a")).isNull();
    }

    @Test
    void rejectsMalformedUri() {
        // Unterminated IPv6 literal — java.net.URI throws URISyntaxException parsing this, which must
        // be treated the same as any other disallowed value rather than propagating.
        assertThat(SafeUrlValidator.sanitizeHttpUrl("http://[::1")).isNull();
    }

    @Test
    void nullAndBlankAreNull() {
        assertThat(SafeUrlValidator.sanitizeHttpUrl(null)).isNull();
        assertThat(SafeUrlValidator.sanitizeHttpUrl("")).isNull();
        assertThat(SafeUrlValidator.sanitizeHttpUrl("   ")).isNull();
    }
}
