package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * Regression coverage for {@code server.servlet.session.cookie.secure} in application.yml (see
 * {@code SESSION_COOKIE_SECURE}). Local development and any other TLS-less environment MUST keep
 * getting a session cookie without the {@code Secure} attribute by default, otherwise the browser
 * would silently refuse to send it back over plain HTTP and login would appear to "not work" —
 * see {@link SessionCookieSecureEnabledTest} for the opposite (property explicitly set to true)
 * case.
 *
 * <p>An unauthenticated {@code GET /} with an {@code Accept: text/html} header is used to force
 * session creation without needing a real login flow: {@code anyRequest().authenticated()} (see
 * {@link SecurityConfig}) denies the request, and Spring Security's default {@code
 * HttpSessionRequestCache} calls {@code request.getSession()} to stash the original request
 * before redirecting to {@code /login} — that session creation is what makes the servlet
 * container emit the {@code Set-Cookie} on this same 302 response. The explicit {@code
 * Accept: text/html} matters: {@code HttpSessionRequestCache}'s default request matcher only
 * saves (and thus only creates a session for) requests it judges to be browser navigations —
 * {@link TestRestTemplate}'s default {@code Accept} header (driven by its registered message
 * converters, not {@code text/html}) does not qualify, so without this header the same 302 comes
 * back with no session/cookie at all. Redirect-following is disabled on the {@link
 * TestRestTemplate} (reusing {@link RestClientConfig#noRedirectRequestFactory}) so the 302's own
 * headers are what gets asserted on, not whatever {@code /login} itself returns.
 *
 * <p>This verifies what Tomcat actually emits on the wire once binding has already happened; it
 * cannot catch a mistake in the production YAML's placeholder wiring itself, since {@code
 * backend/src/test/resources/application.yml} shadows {@code
 * backend/src/main/resources/application.yml} for this {@code @SpringBootTest} context — that
 * wiring is covered separately by {@link SessionCookieConfigBindingTest}.
 */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
class SessionCookieSecureDefaultTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void sessionCookieOmitsSecureAttributeWhenSessionCookieSecureIsUnset() {
        ResponseEntity<String> response = getRootAsUnauthenticatedBrowser(restTemplate);

        String sessionCookie = sessionCookieHeader(response);
        assertThat(sessionCookie).containsIgnoringCase("HttpOnly");
        assertThat(sessionCookie).doesNotContainIgnoringCase("Secure");
    }

    /**
     * Shared by {@link SessionCookieSecureEnabledTest}: disables redirect-following on the given
     * {@link TestRestTemplate}'s underlying {@code RestTemplate} and issues a browser-like
     * (Accept: text/html) unauthenticated {@code GET /}, returning the 302 response as-is so the
     * caller can inspect its {@code Set-Cookie} header.
     */
    static ResponseEntity<String> getRootAsUnauthenticatedBrowser(TestRestTemplate restTemplate) {
        restTemplate
                .getRestTemplate()
                .setRequestFactory(
                        RestClientConfig.noRedirectRequestFactory(Duration.ofSeconds(5), Duration.ofSeconds(5)));

        HttpHeaders requestHeaders = new HttpHeaders();
        requestHeaders.setAccept(List.of(MediaType.TEXT_HTML));
        return restTemplate.exchange("/", HttpMethod.GET, new HttpEntity<>(requestHeaders), String.class);
    }

    static String sessionCookieHeader(ResponseEntity<String> response) {
        List<String> setCookies = response.getHeaders().get(HttpHeaders.SET_COOKIE);
        assertThat(setCookies)
                .as("Set-Cookie headers on the unauthenticated redirect to /login")
                .isNotNull();
        return setCookies.stream()
                .filter(cookie -> cookie.startsWith("JSESSIONID"))
                .findFirst()
                .orElseThrow(() -> new AssertionError("no JSESSIONID cookie in Set-Cookie headers: " + setCookies));
    }
}
