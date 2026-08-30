package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

/**
 * Regression coverage for how {@code server.servlet.session.cookie.*} in the production {@code
 * backend/src/main/resources/application.yml} actually binds — i.e. whether the {@code
 * ${SESSION_COOKIE_SECURE:false}} placeholder resolves the way the YAML's own comments claim.
 * {@link SessionCookieSecureDefaultTest} and {@link SessionCookieSecureEnabledTest} check the
 * opposite end (what Tomcat puts on the wire once binding has already happened, via a real {@code
 * @SpringBootTest} context) — neither of them can catch a mistake in the production YAML itself,
 * because {@code backend/src/test/resources/application.yml} is on the test classpath and fully
 * shadows the production file for any {@code @SpringBootTest} context. That test-only file has no
 * {@code server.servlet.session.cookie.*} keys at all, so a context-based test only ever exercises
 * Spring Boot/Tomcat's own built-in defaults and never the production placeholder wiring — this is
 * exactly the gap PR #36 review found (an injected {@code SESSION_COOKIE_SECURE=true} env var made
 * no difference to {@code SessionCookieSecureDefaultTest}'s result).
 *
 * <p>Loading {@code src/main/resources/application.yml} into a real Spring context (e.g. via
 * {@code @SpringBootTest(properties = "spring.config.additional-location=...")}) was considered
 * and rejected: that file's {@code spring.datasource.*} block is fully environment-variable-driven
 * and, unlike the test file, has no safe fallback ({@code
 * ${SPRING_DATASOURCE_PASSWORD}}/{@code ${SPRING_DATASOURCE_URL:jdbc:postgresql://localhost:5432/vulncheck}})
 * — pulling it into any Spring context used by a test run would reopen exactly the "tests can
 * silently touch the real dev database" hole that {@code src/test/resources/application.yml}
 * hardcodes {@code vulncheck_test} to prevent (see that file's own header comment). Instead, this
 * test loads and binds the production YAML directly with {@link YamlPropertySourceLoader} — no
 * {@code ApplicationContext} is started, so it stays fast and never touches any database.
 */
class SessionCookieConfigBindingTest {

    private static final String PRODUCTION_APPLICATION_YML = "src/main/resources/application.yml";

    @Test
    void secureDefaultsToFalseWhenSessionCookieSecureIsUnset() throws Exception {
        ServerProperties serverProperties = bindServerProperties(Map.of());

        assertThat(serverProperties.getServlet().getSession().getCookie().getSecure())
                .as("server.servlet.session.cookie.secure with SESSION_COOKIE_SECURE unset")
                .isNotNull()
                .isFalse();
        assertThat(serverProperties.getServlet().getSession().getCookie().getHttpOnly())
                .as("server.servlet.session.cookie.http-only")
                .isTrue();
    }

    @Test
    void secureIsTrueWhenSessionCookieSecureIsSetToTrue() throws Exception {
        ServerProperties serverProperties = bindServerProperties(Map.of("SESSION_COOKIE_SECURE", "true"));

        assertThat(serverProperties.getServlet().getSession().getCookie().getSecure())
                .as("server.servlet.session.cookie.secure with SESSION_COOKIE_SECURE=true")
                .isTrue();
        assertThat(serverProperties.getServlet().getSession().getCookie().getHttpOnly())
                .as("server.servlet.session.cookie.http-only")
                .isTrue();
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment}
     * (stripped of the real process's system properties/environment, so this test's own
     * environment can never leak in and mask a bug) and binds {@code server.*} the same way Spring
     * Boot does at startup. When {@code envVars} is non-empty it is added as a {@link
     * MapPropertySource} ahead of the YAML source, standing in for real OS environment variables:
     * placeholder resolution (e.g. {@code ${SESSION_COOKIE_SECURE:false}}) looks up the literal key
     * name across property sources rather than going through relaxed binding, so the key here must
     * match the placeholder name exactly.
     */
    private static ServerProperties bindServerProperties(Map<String, String> envVars) throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);

        if (!envVars.isEmpty()) {
            environment.getPropertySources().addFirst(new MapPropertySource("test-env-vars", Map.copyOf(envVars)));
        }

        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        List<PropertySource<?>> loaded =
                loader.load("application", new FileSystemResource(PRODUCTION_APPLICATION_YML));
        loaded.forEach(propertySource -> environment.getPropertySources().addLast(propertySource));

        return Binder.get(environment).bind("server", Bindable.of(ServerProperties.class)).get();
    }
}
