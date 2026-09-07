package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.web.ErrorProperties;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.Environment;
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
 * test only ever exercises Spring Boot's own built-in defaults and never actually reads the
 * production YAML's explicit pins. This test instead loads and binds the production YAML
 * directly with {@link YamlPropertySourceLoader}, exactly like {@link
 * SessionCookieConfigBindingTest#bindServerProperties} — no {@code ApplicationContext} is
 * started, so it stays fast and never touches any database.
 *
 * <p><b>Important limitation of the binding assertions alone</b> ({@link
 * #productionYamlPinsErrorResponseToNeverLeakInternals()}): today's Spring Boot framework
 * defaults for these four properties already happen to be {@code never}/{@code false}, the same
 * as the production pins. That means the bound-value assertions are vacuous against the one
 * regression this file exists to catch — if someone later removed the entire {@code
 * server.error:} block from the production YAML (reasoning "it's redundant, it already matches
 * the default"), {@link Binder} would simply fall back to the framework default, the bound values
 * would stay {@code never}/{@code false}, and this test would stay green. It would only catch a
 * <em>future Spring Boot upgrade that changed the defaults</em> while the YAML block still
 * existed — not the YAML block being deleted outright. Detecting key deletion is the job of
 * {@link #productionYamlDeclaresErrorPinsExplicitlyRatherThanRelyingOnFrameworkDefaults()} below,
 * which asserts directly on {@link Environment#containsProperty} against the raw (unbound)
 * production YAML source — that assertion fails the moment any of the four keys is removed from
 * {@code application.yml}, regardless of what the framework default happens to be at the time.
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
     * Asserts that the four {@code server.error.*} keys are actually present in the production
     * YAML itself, rather than the pinned values only happening to match Spring Boot's built-in
     * defaults. System property/system environment sources have already been stripped out of the
     * environment ({@link #loadProductionEnvironment()}), so {@link Environment#containsProperty}
     * here can only be satisfied by a key that {@code src/main/resources/application.yml} declares
     * explicitly — unlike {@link #productionYamlPinsErrorResponseToNeverLeakInternals()}'s bound-value
     * assertions, deleting one of these keys from the YAML makes this test fail even though the
     * framework default for the deleted key is identical to the pinned value.
     */
    @Test
    void productionYamlDeclaresErrorPinsExplicitlyRatherThanRelyingOnFrameworkDefaults() throws Exception {
        Environment environment = loadProductionEnvironment();

        assertThat(environment.containsProperty("server.error.include-stacktrace"))
                .as("server.error.include-stacktrace is declared explicitly in production application.yml")
                .isTrue();
        assertThat(environment.containsProperty("server.error.include-exception"))
                .as("server.error.include-exception is declared explicitly in production application.yml")
                .isTrue();
        assertThat(environment.containsProperty("server.error.include-message"))
                .as("server.error.include-message is declared explicitly in production application.yml")
                .isTrue();
        assertThat(environment.containsProperty("server.error.include-binding-errors"))
                .as("server.error.include-binding-errors is declared explicitly in production application.yml")
                .isTrue();

        assertThat(environment.getProperty("server.error.include-stacktrace")).isEqualTo("never");
        assertThat(environment.getProperty("server.error.include-exception")).isEqualTo("false");
        assertThat(environment.getProperty("server.error.include-message")).isEqualTo("never");
        assertThat(environment.getProperty("server.error.include-binding-errors")).isEqualTo("never");
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment}
     * (stripped of the real process's system properties/environment, matching {@link
     * SessionCookieConfigBindingTest#bindServerProperties}) and binds {@code server.*} the same
     * way Spring Boot does at startup.
     */
    private static ServerProperties bindServerProperties() throws Exception {
        return Binder.get(loadProductionEnvironment())
                .bind("server", Bindable.of(ServerProperties.class))
                .get();
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment},
     * stripped of the real process's system properties/environment so this test's own environment
     * can never leak in and mask a bug (e.g. via {@link Environment#containsProperty}).
     */
    private static StandardEnvironment loadProductionEnvironment() throws Exception {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        environment.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);

        YamlPropertySourceLoader loader = new YamlPropertySourceLoader();
        List<PropertySource<?>> loaded =
                loader.load("application", new FileSystemResource(PRODUCTION_APPLICATION_YML));
        loaded.forEach(propertySource -> environment.getPropertySources().addLast(propertySource));

        return environment;
    }
}
