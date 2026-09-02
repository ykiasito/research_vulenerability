package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * Closed-mode B3 (backlog item 193, {@code docs/spec/closed-mode-plan.md} §3-2/§5-4): every
 * live-HTTP-shaped test this file used to have (Solr candidate search, groupId/artifactId
 * splitting, maven-metadata.xml fallback, retry/escaping/XXE-hardening behavior) tested
 * functionality that no longer exists — {@link MavenCentralRegistryClient#lookup} is now a fixed
 * no-op (Maven Central never got a closed-mode mirror, see that class's own javadoc). What remains
 * is that fixed contract.
 */
class MavenCentralRegistryClientTest {

    private final MavenCentralRegistryClient client = new MavenCentralRegistryClient();

    @Test
    void alwaysReturnsEmpty() {
        Optional<RegistryMatch> result = client.lookup("com.google.code.gson:gson", "2.10.1");

        assertThat(result).isEmpty();
    }

    @Test
    void ecosystemIsStillMaven() {
        assertThat(client.ecosystem()).isEqualTo("maven");
    }
}
