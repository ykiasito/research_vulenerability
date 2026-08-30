package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.ResponseEntity;

/**
 * Opposite case of {@link SessionCookieSecureDefaultTest}: with {@code
 * server.servlet.session.cookie.secure} explicitly set to {@code true} (the production posture,
 * driven by {@code SESSION_COOKIE_SECURE=true} — see application.yml and docker-compose.yml), the
 * session cookie must actually carry the {@code Secure} attribute. A separate {@code
 * @SpringBootTest} context (distinct {@code properties}) is used rather than toggling the flag
 * within one test class, since the property is only read once at context startup.
 */
@SpringBootTest(
        webEnvironment = WebEnvironment.RANDOM_PORT,
        properties = "server.servlet.session.cookie.secure=true")
class SessionCookieSecureEnabledTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void sessionCookieCarriesSecureAttributeWhenSessionCookieSecureIsTrue() {
        ResponseEntity<String> response = SessionCookieSecureDefaultTest.getRootAsUnauthenticatedBrowser(restTemplate);

        String sessionCookie = SessionCookieSecureDefaultTest.sessionCookieHeader(response);
        assertThat(sessionCookie).containsIgnoringCase("HttpOnly");
        assertThat(sessionCookie).containsIgnoringCase("Secure");
    }
}
