package com.vulncheck.app.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.pattern.ValidatePattern;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * Regression gate for closed-mode backlog item 291: Spring Boot's {@code FlywayAutoConfiguration}
 * applies {@code spring.flyway.ignore-migration-patterns} with <em>replace</em>, not <em>merge</em>,
 * semantics — setting that property at all discards Flyway's own built-in default ({@code
 * *:future}), even if the intent was only to add one more pattern alongside it. See the {@code
 * spring.flyway.ignore-migration-patterns} comment block in {@code
 * backend/src/test/resources/application.yml} (item 285/291) for why both {@code "*:future"} and
 * {@code "repeatable:missing"} are load-bearing and must both stay present — each protects a
 * different direction (closed-mode trailing master vs. master/test not having closed-mode's
 * repeatable strip migration). Because both are load-bearing, the property being unset entirely is
 * itself the regression this gate must catch, not a tolerated fallback state.
 *
 * <p>This test asserts the <em>effective</em> runtime {@link Flyway} configuration rather than
 * parsing YAML, so it observes Spring Boot's actual replace/merge behavior directly instead of just
 * the literal text of {@code application.yml}.
 */
@SpringBootTest
class FlywayIgnoreMigrationPatternsTest {

    @Autowired
    private Flyway flyway;

    @Test
    void effectiveIgnoreMigrationPatternsRetainsBothRequiredPatterns() {
        ValidatePattern[] patterns = flyway.getConfiguration().getIgnoreMigrationPatterns();

        List<String> patternStrings = Arrays.stream(patterns).map(ValidatePattern::toString).toList();

        assertThat(patternStrings)
                .as(
                        "effective spring.flyway.ignore-migration-patterns — both \"*:future\" and"
                                + " \"repeatable:missing\" must be present (see application.yml's comment"
                                + " block, item 285/291); Spring Boot's ignore-migration-patterns replaces"
                                + " rather than merges, so either one going missing is a real regression")
                .contains("*:future", "repeatable:missing");
    }
}
