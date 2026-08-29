package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.util.Optional;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Regression coverage for the Maven Central groupId-disambiguation logic, using the exact
 * response shapes captured live from search.maven.org during 2026-08-23 testing. Expectations are
 * declared in call order rather than matched by exact query string (Solr query encoding isn't
 * worth pinning down precisely here) — {@link MavenCentralRegistryClient#lookup} always issues
 * exactly one relevance-ranked "candidate" search, followed by zero or more version-scoped
 * {@code gav}-core checks (one pass over every candidate), followed by zero or more
 * {@code maven-metadata.xml} fallback checks (a second pass over only the top few candidates, run
 * only if none of them confirmed via Solr) — so declaration order reliably corresponds to call
 * order.
 */
class MavenCentralRegistryClientTest {

    private RestClient.Builder restClientBuilder;
    private MockRestServiceServer server;
    private MavenCentralRegistryClient client;

    @BeforeEach
    void setUp() {
        restClientBuilder = RestClient.builder();
        server = MockRestServiceServer.bindTo(restClientBuilder).build();
        client = new MavenCentralRegistryClient(restClientBuilder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsExactVersionForTheOnlyCandidate() {
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("search.maven.org")))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.google.code.gson", "gson", 44)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.google.code.gson:gson");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void prefersTheHigherVersionCountCandidateOverTopRelevanceWhenGroupIdMigratedAway() {
        // Real case observed live: Jackson's classic groupId (com.fasterxml.jackson.core, 120+
        // historical releases) still published 2.15.2, but the project's newer tools.jackson.core
        // groupId (a handful of releases so far) now outranks it by relevance and never published
        // that older version at all. versionCount ordering puts the classic groupId first, so it's
        // the *only* one checked — one HTTP call, not a relevance-order fallback chain.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("tools.jackson.core", "jackson-databind", 8),
                        artifactDoc("com.fasterxml.jackson.core", "jackson-databind", 120)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON)); // com.fasterxml..., checked first, confirms

        Optional<RegistryMatch> result = client.lookup("jackson-databind", "2.15.2");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.fasterxml.jackson.core:jackson-databind");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void prefersTheEstablishedPackageOverAWrapperThatRepublishesTheSameVersionNumbers() {
        // Real case observed live: dev.galasa:gson is an OSGi-wrapped republish of upstream gson
        // that mirrors its exact version numbers (versionCount 3), so "first candidate whose
        // version matches" alone couldn't tell it apart from the genuine com.google.code.gson:gson
        // (versionCount 44) — this was an actual, observed misidentification before the
        // versionCount-ordering fix. Relevance order (as returned by Maven Central) still lists
        // the wrapper first; versionCount ordering must override that.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("dev.galasa", "gson", 3),
                        artifactDoc("com.google.code.gson", "gson", 44)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON)); // real gson, checked first, confirms

        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.google.code.gson:gson");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void prefersTheCanonicalGroupIdEqualsArtifactIdConventionOverAHigherVersionCountWrapper() {
        // Real case observed live: com.guicedee.services republishes many Apache-Commons-style
        // libraries under its own group with a suspiciously high versionCount (446, from
        // aggregating releases across many wrapped libraries) — versionCount ordering alone would
        // rank it above the real commons-io:commons-io (versionCount 35), which follows the
        // classic pre-2010s convention of groupId == artifactId. That convention must win first.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.guicedee.services", "commons-io", 446),
                        artifactDoc("commons-io", "commons-io", 35)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON)); // real commons-io, checked first, confirms

        Optional<RegistryMatch> result = client.lookup("commons-io", "2.11.0");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("commons-io:commons-io");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void fallsBackToTheHighestVersionCountCandidateUnconfirmedWhenNoCandidateConfirmsTheVersion() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.example", "some-tool", 5)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        // Solr's gav core didn't confirm, so the maven-metadata.xml fallback is also consulted
        // (see MavenCentralRegistryClient#versionExists) — here it doesn't have "9.9.9" either.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("repo1.maven.org")))
                .andRespond(withSuccess(mavenMetadataXml("1.0.0", "2.0.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("some-tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.example:some-tool");
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void confirmsViaMavenMetadataXmlWhenSolrsIndexLagsBehindANewlyPublishedVersion() {
        // Real case observed live (golden-300 job191, 2026-08-30): search.maven.org's Solr index
        // lagged behind the authoritative maven-metadata.xml for a newly-published version (e.g.
        // org.springframework:spring-core:7.1.0-M1), leaving a real version reported unconfirmed
        // and confidence stuck at 0.5. The maven-metadata.xml fallback should independently confirm
        // it, restoring confidence 0.95.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("org.springframework", "spring-core", 200)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("search.maven.org")))
                .andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.allOf(
                        Matchers.containsString("repo1.maven.org"),
                        Matchers.containsString("/maven2/org/springframework/spring-core/maven-metadata.xml"))))
                .andRespond(withSuccess(mavenMetadataXml("7.0.5", "7.1.0-M1"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("spring-core", "7.1.0-M1");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("org.springframework:spring-core");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void treatsA404FromTheMavenMetadataXmlFallbackAsAnImmediateNonRetryableAnswer() {
        // REVISE (senior review 2026-08-30, PR #8): fetchMetadataXml used to throw for ANY
        // non-2xx status, including 404 -- a confirmed, deterministic "this coordinate/version
        // doesn't exist" answer, not a transient failure -- and the retry loop caught that
        // IllegalStateException like it would any other failure, retrying up to 3 times. Only one
        // maven-metadata.xml request is expected here: if it were retried, MockRestServiceServer
        // would reject the next (unexpected) request outright and fail this test loudly.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.example", "some-tool", 5)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("repo1.maven.org")))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        Optional<RegistryMatch> result = client.lookup("some-tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void onlyChecksTheMavenMetadataXmlFallbackForTheTopFewCandidatesWhenNoneConfirmViaSolr() {
        // 4 candidates, none confirmed by Solr -- the (roughly twice as costly) maven-metadata.xml
        // fallback pass must only run against the top METADATA_FALLBACK_CANDIDATE_LIMIT (3), not
        // all 4, so the fallback's added cost doesn't double the cost of the whole candidate pool.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.example", "tool-a", 40),
                        artifactDoc("com.example", "tool-b", 30),
                        artifactDoc("com.example", "tool-c", 20),
                        artifactDoc("com.example", "tool-d", 10)), MediaType.APPLICATION_JSON));
        // Pass 1: Solr checked for all 4 candidates, none confirm.
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        // Pass 2: only the top 3 (by versionCount) get the maven-metadata.xml fallback -- tool-d is
        // never checked. If it were, MockRestServiceServer would reject that 8th request outright
        // (no matching expectation left) and fail this test loudly.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("/maven2/com/example/tool-a/maven-metadata.xml")))
                .andRespond(withSuccess(mavenMetadataXml("1.0.0"), MediaType.APPLICATION_XML));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("/maven2/com/example/tool-b/maven-metadata.xml")))
                .andRespond(withSuccess(mavenMetadataXml("1.0.0"), MediaType.APPLICATION_XML));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("/maven2/com/example/tool-c/maven-metadata.xml")))
                .andRespond(withSuccess(mavenMetadataXml("1.0.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.example:tool-a");
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        server.verify();
    }

    @Test
    void refusesToFetchMavenMetadataXmlWhenTheCoordinateContainsADotDotSegment() {
        // groupId/artifactId reaching fetchMetadataXml via lookupByCoordinate come straight from a
        // ':'-split CSV product_name column with no upstream validation. "com.example..evil" is
        // built entirely from otherwise-allowed characters (letters and dots), so this specifically
        // exercises the dedicated ".." rejection rather than the general character-set check below.
        // Only the Solr gav check is expected: if fetchMetadataXml didn't reject this, the
        // unexpected repo1.maven.org request would fail this test loudly.
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("com.example..evil:some-tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        server.verify();
    }

    @Test
    void refusesToFetchMavenMetadataXmlWhenTheCoordinateContainsAnInvalidCharacter() {
        // A product_name column value with a slash or blank space in it (e.g. free-text CSV data,
        // not a real Maven coordinate) must never reach repo1.maven.org at all -- only the Solr gav
        // check is expected here, same reasoning as the ".." test above.
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("com/example:some tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        server.verify();
    }

    @Test
    void returnsEmptyWhenNoCandidateArtifactsAreFound() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("totally-unknown-artifact", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void returnsEmptyWithoutThrowingOnHttpFailure() {
        // The client retries up to 3 total attempts on failure (see
        // MavenCentralRegistryClient#solrSearchWithRetry), so a persistent failure means three
        // requests, not one.
        server.expect(method(HttpMethod.GET)).andRespond(withServerError());
        server.expect(method(HttpMethod.GET)).andRespond(withServerError());
        server.expect(method(HttpMethod.GET)).andRespond(withServerError());

        Optional<RegistryMatch> result = client.lookup("gson", "2.10.1");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void recoversFromATransientFailureOnRetry() {
        // Real case observed live: a transient timeout checking the genuine candidate's version
        // (e.g. org.hibernate:hibernate-core) fell through to an unconfirmed wrapper-package
        // result instead. A retry after the first failure should recover the confirmed match.
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(candidateSearchResponse(
                        artifactDoc("com.example", "some-tool", 5)), MediaType.APPLICATION_JSON));
        server.expect(method(HttpMethod.GET)).andRespond(withServerError());
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("some-tool", "9.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void splitsAFullMavenCoordinateIntoGroupIdAndArtifactIdInsteadOfSearchingTheCombinedForm() {
        // Real case observed live: searching Maven Central's relevance-ranked `a:` core with the
        // combined "com.google.guava:guava" form returns numFound 0. The coordinate is already
        // unambiguous, so this must skip the candidate search entirely and go straight to a
        // g:/a:/v:-scoped gav check instead — never the combined groupId:artifactId form.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.allOf(
                        Matchers.containsString("search.maven.org"),
                        Matchers.containsString("g:%22com.google.guava%22"),
                        Matchers.containsString("a:%22guava%22"),
                        Matchers.not(Matchers.containsString("com.google.guava%3Aguava")),
                        Matchers.not(Matchers.containsString("com.google.guava:guava")))))
                .andRespond(withSuccess(gavResponse(1), MediaType.APPLICATION_JSON));

        Optional<RegistryMatch> result = client.lookup("com.google.guava:guava", "31.1-jre");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.google.guava:guava");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void fallsBackToAnUnconfirmedCoordinateMatchWhenTheGivenVersionDoesNotExist() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(gavResponse(0), MediaType.APPLICATION_JSON));
        // Solr's gav core didn't confirm, so the maven-metadata.xml fallback is also consulted —
        // here it doesn't have "999.999" either (a genuinely nonexistent version).
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo(Matchers.containsString("repo1.maven.org")))
                .andRespond(withSuccess(mavenMetadataXml("31.1-jre", "32.0.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("com.google.guava:guava", "999.999");

        assertThat(result).isPresent();
        assertThat(result.get().packageName()).isEqualTo("com.google.guava:guava");
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    private String artifactDoc(String groupId, String artifactId, int versionCount) {
        return "{\"g\":\"" + groupId + "\",\"a\":\"" + artifactId + "\",\"latestVersion\":\"9.9.9\",\"versionCount\":" + versionCount + "}";
    }

    private String candidateSearchResponse(String... docs) {
        return "{\"response\":{\"numFound\":" + docs.length + ",\"start\":0,\"docs\":[" + String.join(",", docs) + "]}}";
    }

    private String gavResponse(int matchCount) {
        if (matchCount == 0) {
            return "{\"response\":{\"numFound\":0,\"start\":0,\"docs\":[]}}";
        }
        return "{\"response\":{\"numFound\":1,\"start\":0,\"docs\":[{\"g\":\"x\",\"a\":\"y\",\"v\":\"z\"}]}}";
    }

    private String mavenMetadataXml(String... versions) {
        StringBuilder versionsXml = new StringBuilder();
        for (String version : versions) {
            versionsXml.append("<version>").append(version).append("</version>");
        }
        return "<metadata><groupId>x</groupId><artifactId>y</artifactId><versioning>"
                + "<versions>" + versionsXml + "</versions></versioning></metadata>";
    }
}
