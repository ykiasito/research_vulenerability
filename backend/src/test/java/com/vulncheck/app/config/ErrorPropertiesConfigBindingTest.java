package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

/**
 * Regression coverage for the {@code server.error.*} block that closed-mode backlog item 411
 * pins in the production {@code backend/src/main/resources/application.yml} — {@code
 * include-stacktrace: never}, {@code include-exception: false}, {@code include-message: never},
 * {@code include-binding-errors: never} — so a 500 response can never leak a stack trace,
 * exception class name, exception message, or request-binding validation detail through the
 * custom {@code templates/error/*.html} pages.
 *
 * <p>{@code CustomErrorPageTest} (a {@code @SpringBootTest}) cannot cover this: {@code
 * backend/src/test/resources/application.yml} is on the test classpath and fully shadows the
 * production file for any {@code @SpringBootTest} context (same gap {@link
 * SessionCookieConfigBindingTest}'s javadoc documents for {@code server.servlet.session.cookie.*}
 * — see that javadoc for why {@code spring.config.additional-location} was considered and
 * rejected). The test-only YAML has no {@code server.error.*} keys at all, so a context-based
 * test only ever exercises Spring Boot's own built-in defaults (which today happen to already be
 * {@code never}/{@code false}) and never actually reads the production YAML's explicit pins —
 * a future Spring Boot upgrade that changed those defaults would silently regress the production
 * behavior without any test catching it. This test instead loads and binds the production YAML
 * directly with {@link YamlPropertySourceLoader}, exactly like {@link
 * SessionCookieConfigBindingTest#bindServerProperties} — no {@code ApplicationContext} is
 * started, so it stays fast and never touches any database.
 */
class ErrorPropertiesConfigBindingTest {

    private static final String PRODUCTION_APPLICATION_YML = "src/main/resources/application.yml";

    @Test
    void productionYamlPinsErrorResponseToNeverLeakInternals() throws Exception {
        ErrorProperties errorProperties = bindServerProperties().getError();

        assertThat(errorProperties.getIncludeStacktrace())
                .as("server.error.include-stacktrace")
                .isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
        assertThat(errorProperties.isIncludeException())
                .as("server.error.include-exception")
                .isFalse();
        assertThat(errorProperties.getIncludeMessage())
                .as("server.error.include-message")
                .isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
        assertThat(errorProperties.getIncludeBindingErrors())
                .as("server.error.include-binding-errors")
                .isEqualTo(ErrorProperties.IncludeAttribute.NEVER);
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment}
     * (stripped of the real process's system properties/environment, matching {@link
     * SessionCookieConfigBindingTest#bindServerProperties}) and binds {@code server.*} the same
     * way Spring Boot does at startup.
     */
    private static ServerProperties bindServerProperties() throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);

        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        List<PropertySource<?>> loaded =
                loader.load("application", new FileSystemResource(PRODUCTION_APPLICATION_YML));
        loaded.forEach(propertySource -> environment.getPropertySources().addLast(propertySource));

        return Binder.get(environment).bind("server", Bindable.of(ServerProperties.class)).get();
    }
}
