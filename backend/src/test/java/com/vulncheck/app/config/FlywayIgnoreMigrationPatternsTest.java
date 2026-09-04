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
 * *:future}, see {@code FlywayModel.defaults()}), even if the intent was only to add one more
 * pattern alongside it. Item 285's original fix (a single {@code "repeatable:missing"} value) hit
 * exactly this trap and was caught by senior-reviewer during PR#202's REVISE round; the corrected
 * form lists {@code *:future} explicitly (PR#203).
 *
 * <p>This test asserts the <em>effective</em> runtime configuration rather than parsing YAML, so it
 * stays correct whether or not {@code spring.flyway.ignore-migration-patterns} is set at all in
 * {@code backend/src/test/resources/application.yml}: with the property unset, Flyway's own {@code
 * *:future} default is what must show up here; with the property set, whatever list is configured
 * must still include {@code *:future} explicitly. Either way, a future edit that drops {@code
 * *:future} (the exact regression this backlog item exists to prevent) fails this test.
 */
@SpringBootTest
class FlywayIgnoreMigrationPatternsTest {

    @Autowired
    private Flyway flyway;

    @Test
    void effectiveIgnoreMigrationPatternsRetainsFutureTolerance() {
        ValidatePattern[] patterns = flyway.getConfiguration().getIgnoreMigrationPatterns();

        List<String> patternStrings = Arrays.stream(patterns).map(ValidatePattern::toString).toList();

        assertThat(patternStrings)
                .as(
                        "effective spring.flyway.ignore-migration-patterns (Flyway's own \"*:future\" default"
                                + " when the property is unset, or whatever list application.yml replaces it"
                                + " with when it is set)")
                .contains("*:future");
    }
}
