package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;

/**
 * Regression coverage for how {@code app.item-processing-pool-size} and {@code
 * spring.datasource.hikari.maximum-pool-size} in the production {@code
 * backend/src/main/resources/application.yml} actually bind (item 167, 2026-09-01,
 * {@code docs/spec/closed-mode-plan.md} §3-3 A4/§7 P2/P4) — i.e. whether the {@code
 * ${ITEM_PROCESSING_POOL_SIZE:8}}/{@code ${SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE:10}}
 * placeholders resolve to the same defaults the two hardcoded values they replaced used to have,
 * and that an overriding env var actually takes effect. Same rationale/technique as {@link
 * SessionCookieConfigBindingTest}: {@code backend/src/test/resources/application.yml} fully
 * shadows the production file for any {@code @SpringBootTest} context and doesn't set either of
 * these keys, so a context-based test could only ever observe Spring Boot's/HikariCP's own
 * built-in defaults, never the production placeholder wiring itself. This test loads and binds
 * the production YAML directly with {@link YamlPropertySourceLoader} instead — no {@code
 * ApplicationContext} is started, so it stays fast and never touches any database.
 */
class PoolSizeConfigBindingTest {

    private static final String PRODUCTION_APPLICATION_YML = "src/main/resources/application.yml";

    @Test
    void itemProcessingPoolSizeDefaultsToEightWhenUnset() throws Exception {
        assertThat(bindInt(Map.of(), "app.item-processing-pool-size"))
                .as("app.item-processing-pool-size with ITEM_PROCESSING_POOL_SIZE unset")
                .isEqualTo(8);
    }

    @Test
    void itemProcessingPoolSizeHonorsEnvOverride() throws Exception {
        assertThat(bindInt(Map.of("ITEM_PROCESSING_POOL_SIZE", "16"), "app.item-processing-pool-size"))
                .as("app.item-processing-pool-size with ITEM_PROCESSING_POOL_SIZE=16")
                .isEqualTo(16);
    }

    @Test
    void hikariMaximumPoolSizeDefaultsToTenWhenUnset() throws Exception {
        assertThat(bindInt(Map.of(), "spring.datasource.hikari.maximum-pool-size"))
                .as("spring.datasource.hikari.maximum-pool-size with "
                        + "SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE unset")
                .isEqualTo(10);
    }

    @Test
    void hikariMaximumPoolSizeHonorsEnvOverride() throws Exception {
        assertThat(bindInt(
                        Map.of("SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE", "20"),
                        "spring.datasource.hikari.maximum-pool-size"))
                .as("spring.datasource.hikari.maximum-pool-size with "
                        + "SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE=20")
                .isEqualTo(20);
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment}
     * (stripped of the real process's system properties/environment, so this test's own
     * environment can never leak in and mask a bug) and binds the given key the same way Spring
     * Boot does at startup. When {@code envVars} is non-empty it is added as a {@link
     * MapPropertySource} ahead of the YAML source, standing in for real OS environment variables
     * — see {@link SessionCookieConfigBindingTest#bindServerProperties} for why the map's keys
     * must match each placeholder name exactly rather than relying on relaxed binding.
     */
    private static int bindInt(Map<String, String> envVars, String propertyKey) throws Exception {
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

        return Binder.get(environment).bind(propertyKey, Bindable.of(Integer.class)).get();
    }
}
