package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.scheduling.support.CronExpression;

/**
 * Regression coverage for PR #75 REVISE (round 2) item 2: {@link CpeDictionaryScheduledResync}'s
 * {@code @Scheduled}/{@code @Value} placeholders (e.g. {@code
 * ${app.cpe-scheduled-resync-cron:0 30 1 * * SUN}}) and the production {@code
 * backend/src/main/resources/application.yml} keys they reference ({@code
 * app.cpe-scheduled-resync-cron}, {@code app.cpe-scheduled-resync-enabled}) both currently default
 * to the exact same literal. That coincidence means a typo in either the annotation's property
 * name or the YAML key would go completely unnoticed by any test that only ever exercises the
 * unset-env-var default case: the annotation's own hardcoded fallback would silently produce the
 * "correct" value even though the YAML key it was supposed to reference doesn't resolve to
 * anything, and only the {@code CPE_SCHEDULED_RESYNC_CRON}/{@code CPE_SCHEDULED_RESYNC_ENABLED}
 * override path would be dead — a schedule that never fires (or a resync that can never be turned
 * on) with no error anywhere. This test forces the mismatch to surface by asserting the override
 * path too.
 *
 * <p>Follows the same technique as {@code
 * com.vulncheck.app.config.SessionCookieConfigBindingTest} (see that class's own javadoc for why):
 * loads {@code src/main/resources/application.yml} directly with {@link YamlPropertySourceLoader}
 * into a bare {@link StandardEnvironment} stripped of the real process's system
 * properties/environment (so this test's own environment can never leak in and mask a bug) — no
 * {@code ApplicationContext} is started, so it stays fast and never touches any database, and the
 * test-only {@code src/test/resources/application.yml} (which has no {@code app.cpe-*} keys at
 * all and would fully shadow the production file in any {@code @SpringBootTest} context) never
 * enters the picture.
 *
 * <p>Rather than binding via property key names (which would only prove the YAML itself parses),
 * this test pulls the raw {@code ${...}} placeholder strings straight off {@link
 * CpeDictionaryScheduledResync}'s own {@code @Scheduled} annotation and {@code enabled} field's
 * {@code @Value} annotation via reflection, then resolves those exact strings against the loaded
 * environment with {@link StandardEnvironment#resolveRequiredPlaceholders}. That is the same
 * resolution Spring itself performs when wiring the real bean, so a property-name mismatch between
 * the annotation and the YAML key surfaces here as a resolved value that silently ignores the env
 * var override, exactly as it would in production.
 */
class CpeScheduledResyncConfigBindingTest {

    private static final String PRODUCTION_APPLICATION_YML = "src/main/resources/application.yml";

    @Test
    void cronDefaultsToSundayOneThirtyUtcWhenEnvVarUnset() throws Exception {
        String resolvedCron = resolvePlaceholder(resyncWeeklyCronPlaceholder(), Map.of());

        assertThat(resolvedCron)
                .as("app.cpe-scheduled-resync-cron with CPE_SCHEDULED_RESYNC_CRON unset")
                .isEqualTo("0 30 1 * * SUN");
        assertThatCode(() -> CronExpression.parse(resolvedCron)).doesNotThrowAnyException();
    }

    @Test
    void cronIsOverriddenWhenCpeScheduledResyncCronEnvVarIsSet() throws Exception {
        String resolvedCron = resolvePlaceholder(
                resyncWeeklyCronPlaceholder(), Map.of("CPE_SCHEDULED_RESYNC_CRON", "0 15 4 * * TUE"));

        assertThat(resolvedCron)
                .as("app.cpe-scheduled-resync-cron with CPE_SCHEDULED_RESYNC_CRON=0 15 4 * * TUE")
                .isEqualTo("0 15 4 * * TUE");
        assertThatCode(() -> CronExpression.parse(resolvedCron)).doesNotThrowAnyException();
    }

    @Test
    void enabledDefaultsToFalseWhenEnvVarUnset() throws Exception {
        String resolved = resolvePlaceholder(enabledFieldPlaceholder(), Map.of());

        assertThat(resolved)
                .as("app.cpe-scheduled-resync-enabled with CPE_SCHEDULED_RESYNC_ENABLED unset")
                .isEqualTo("false");
    }

    @Test
    void enabledIsTrueWhenCpeScheduledResyncEnabledEnvVarIsSetToTrue() throws Exception {
        String resolved = resolvePlaceholder(
                enabledFieldPlaceholder(), Map.of("CPE_SCHEDULED_RESYNC_ENABLED", "true"));

        assertThat(resolved)
                .as("app.cpe-scheduled-resync-enabled with CPE_SCHEDULED_RESYNC_ENABLED=true")
                .isEqualTo("true");
    }

    private static String resyncWeeklyCronPlaceholder() throws NoSuchMethodException {
        Method method = CpeDictionaryScheduledResync.class.getMethod("resyncWeekly");
        return method.getAnnotation(Scheduled.class).cron();
    }

    private static String enabledFieldPlaceholder() throws NoSuchFieldException {
        Field field = CpeDictionaryScheduledResync.class.getDeclaredField("enabled");
        return field.getAnnotation(Value.class).value();
    }

    /**
     * Loads the production {@code application.yml} into a bare {@link StandardEnvironment} (see
     * this class's own javadoc) and resolves {@code rawPlaceholder} (e.g. {@code
     * ${app.cpe-scheduled-resync-cron:0 30 1 * * SUN}}) against it exactly the way Spring resolves
     * {@code @Scheduled}/{@code @Value} placeholders at bean-creation time. When {@code envVars} is
     * non-empty it is added as a {@link MapPropertySource} ahead of the YAML source, standing in
     * for real OS environment variables.
     */
    private static String resolvePlaceholder(String rawPlaceholder, Map<String, String> envVars) throws Exception {
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

        return environment.resolveRequiredPlaceholders(rawPlaceholder);
    }
}
