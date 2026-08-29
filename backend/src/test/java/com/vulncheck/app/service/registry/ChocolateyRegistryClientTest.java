package com.vulncheck.app.service.registry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

class ChocolateyRegistryClientTest {

    private static final String ENTRY_XML_TEMPLATE = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            + "<entry xmlns:d=\"http://schemas.microsoft.com/ado/2007/08/dataservices\" "
            + "xmlns:m=\"http://schemas.microsoft.com/ado/2007/08/dataservices/metadata\" "
            + "xmlns=\"http://www.w3.org/2005/Atom\">"
            + "<title type=\"text\">%s</title>"
            + "<m:properties><d:Version>%s</d:Version></m:properties>"
            + "</entry>";

    private static final String FEED_HEADER = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"
            + "<feed xmlns:d=\"http://schemas.microsoft.com/ado/2007/08/dataservices\" "
            + "xmlns:m=\"http://schemas.microsoft.com/ado/2007/08/dataservices/metadata\" "
            + "xmlns=\"http://www.w3.org/2005/Atom\">"
            + "<title type=\"text\">Packages</title>";

    private static final String FEED_FOOTER = "</feed>";

    private static final String NEXT_LINK =
            "<link rel=\"next\" href=\"https://community.chocolatey.org/api/v2/FindPackagesById()?"
                    + "id='x'&amp;$skiptoken=40\" />";

    /** Builds a FindPackagesById()-shaped fallback feed with the given versions, one {@code
     *  <entry>} per version, optionally truncated (a {@code rel="next"} link present, as this feed
     *  emits when a package has more than 40 published versions — see class javadoc). */
    private static String fallbackFeed(boolean truncated, String... versions) {
        StringBuilder sb = new StringBuilder(FEED_HEADER);
        for (String version : versions) {
            sb.append("<entry><m:properties><d:Version>").append(version).append("</d:Version></m:properties></entry>");
        }
        if (truncated) {
            sb.append(NEXT_LINK);
        }
        sb.append(FEED_FOOTER);
        return sb.toString();
    }

    private static final String EMPTY_FALLBACK_FEED = fallbackFeed(false);

    private MockRestServiceServer server;
    private ChocolateyRegistryClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        client = new ChocolateyRegistryClient(builder.build(), ExternalRegistryRateLimiter.disabledForTesting());
    }

    @Test
    void confirmsAnExactVersionMatchFromTheFlagshipChocolateyCliCase() {
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/Packages(Id='chocolatey',Version='2.5.1')"))
                .andRespond(withSuccess(String.format(ENTRY_XML_TEMPLATE, "chocolatey", "2.5.1"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("chocolatey", "2.5.1");

        assertThat(result).isPresent();
        assertThat(result.get().ecosystem()).isEqualTo("chocolatey");
        assertThat(result.get().packageName()).isEqualTo("chocolatey");
        assertThat(result.get().purl()).isEqualTo("pkg:chocolatey/chocolatey@2.5.1");
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        server.verify();
    }

    @Test
    void normalizesAMultiWordProductNameToALowercaseHyphenatedId() {
        // "OBS Studio" -> "obs-studio" — the whole point of routing whitespace-containing names to
        // this client (see RegistryRoutingPolicy) rather than skipping every registry outright.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/Packages(Id='obs-studio',Version='29.1.3')"))
                .andRespond(withSuccess(String.format(ENTRY_XML_TEMPLATE, "obs-studio", "29.1.3"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("OBS Studio", "29.1.3");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        server.verify();
    }

    @Test
    void returnsEmptyWhenThePackageOrVersionDoesNotExistAndTheExistenceFallbackFeedIsConfirmedEmpty() {
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/Packages(Id='totally-unknown-package',Version='1.0.0')"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/FindPackagesById()?id='totally-unknown-package'&$select=Version"))
                .andRespond(withSuccess(EMPTY_FALLBACK_FEED, MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("totally-unknown-package", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void rejectsAProductNameThatFailsTheIdWhitelistWithoutIssuingAnyHttpRequest() {
        // The confirmed live injection is against $filter, which this client never builds — but the
        // whitelist below is checked BEFORE any URL is built, as an independent layer. No
        // server.expect(...) is registered at all here: MockRestServiceServer fails the test if any
        // unexpected request is made, so this also proves zero network calls happen.
        Optional<RegistryMatch> result = client.lookup("chocolatey' or '1'='1", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void rejectsAProductNameContainingODataSyntaxCharactersLikeParenthesesOrCommas() {
        Optional<RegistryMatch> result = client.lookup("foo),Version='x", "1.0.0");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void doesNotResolveExternalEntitiesInTheXmlResponseXxeHardening() {
        // A response body carrying a DOCTYPE with an external entity — disallow-doctype-decl=true
        // means the parser rejects the DOCTYPE outright (parse failure), rather than resolving
        // &xxe; and leaking local file contents into the parsed "confirmed version" field.
        String malicious = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE entry [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<entry xmlns:d=\"http://schemas.microsoft.com/ado/2007/08/dataservices\" "
                + "xmlns:m=\"http://schemas.microsoft.com/ado/2007/08/dataservices/metadata\">"
                + "<m:properties><d:Version>&xxe;</d:Version></m:properties></entry>";
        server.expect(method(HttpMethod.GET)).andRespond(withSuccess(malicious, MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("chocolatey", "2.5.1");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void treatsAResponseVersionMismatchAsUnconfirmedRatherThanTrustingTheHttpStatusAlone() {
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(String.format(ENTRY_XML_TEMPLATE, "chocolatey", "2.5.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("chocolatey", "2.5.1");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void capsResponseBodySizeReadIntoMemory() {
        // Defense in depth: even though this client only ever requests the small exact-version
        // path, an oversized response body must not be read into memory in full — measured live
        // that a bulk (non-exact) query shape can return hundreds of KB.
        String oversized = "<?xml version=\"1.0\"?><entry>"
                + "x".repeat(600 * 1024)
                + "</entry>";
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(new ByteArrayResource(oversized.getBytes(StandardCharsets.UTF_8)), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("chocolatey", "2.5.1");

        assertThat(result).isEmpty();
        server.verify();
    }

    @Test
    void returnsEmptyForABlankOrNullProductNameOrVersionWithoutAnyHttpRequest() {
        assertThat(client.lookup("", "1.0.0")).isEmpty();
        assertThat(client.lookup(null, "1.0.0")).isEmpty();
        assertThat(client.lookup("chocolatey", "")).isEmpty();
        assertThat(client.lookup("chocolatey", null)).isEmpty();
        server.verify();
    }

    @Test
    void confirmsPackageExistenceButLeavesVersionUnconfirmedWhenCsvVersionIsAbsentFromTheFallbackFeed() {
        // Real case this existence-fallback was built for: the exact-key lookup 404s (Chocolatey's
        // catalog doesn't have this exact version string), but the id itself is real — reported as
        // an unconfirmed match (0.5 / exactVersionConfirmed=false), not a total miss.
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/Packages(Id='handbrake',Version='1.9.9')"))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andExpect(requestTo("https://community.chocolatey.org/api/v2/FindPackagesById()?id='handbrake'&$select=Version"))
                .andRespond(withSuccess(fallbackFeed(false, "1.6.1", "1.7.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("handbrake", "1.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        // The ORIGINAL CSV version stays in the purl — never substituted with a feed version:
        assertThat(result.get().purl()).isEqualTo("pkg:chocolatey/handbrake@1.9.9");
        server.verify();
    }

    @Test
    void doesNotPopulateVersionsFromATruncatedFallbackFeedToAvoidFalseNegativesInTheCache() {
        // handbrake/krita both have >40 published versions in reality, and their own current
        // version was confirmed live to fall past page 1 — a partial versions() list here would
        // make RegistryLookupCache#reuseForVersion wrongly answer "doesn't exist" for some other
        // item's real version that just happens to live on page 2+.
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(fallbackFeed(true, "1.6.1", "1.7.0"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("handbrake", "1.9.9");

        assertThat(result).isPresent();
        assertThat(result.get().versions()).isEmpty();
        server.verify();
    }

    @Test
    void acceptsAPrefixExtensionVersionMatchButKeepsTheOriginalCsvVersionString() {
        // advanced-ip-scanner-shaped case: the CSV recorded a truncated 3-component version, the
        // feed's real release has a 4th build component — this is treated as confirmed, but the
        // returned purl still carries the CSV's own (shorter) version string, not the feed's.
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(fallbackFeed(false, "2.5.4594.1"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("advanced-ip-scanner", "2.5.4594");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isTrue();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.95");
        assertThat(result.get().purl()).isEqualTo("pkg:chocolatey/advanced-ip-scanner@2.5.4594");
        server.verify();
    }

    @Test
    void treatsAnAmbiguousPrefixExtensionMatchAcrossMultipleFeedVersionsAsUnconfirmedRatherThanPickingOne() {
        // CSV "1.32" prefix-extension-matches both "1.32.803" and "1.32.774" — must not guess.
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(fallbackFeed(false, "1.32.803", "1.32.774"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("some-app", "1.32");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        assertThat(result.get().purl()).isEqualTo("pkg:chocolatey/some-app@1.32");
        server.verify();
    }

    @Test
    void rejectsTrailingComponentStrippingOrNearestVersionMatchingEvenWhenAPrefixRelationshipExistsInReverse() {
        // Guards against ever reintroducing "strip the CSV version's trailing component(s) and
        // treat that as a match" (or "nearest version"): here the FEED version is a prefix of the
        // CSV version, the reverse of the legal extension direction (feedVersion.startsWith(csv +
        // ".")) — this must NOT be confirmed.
        server.expect(method(HttpMethod.GET)).andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(method(HttpMethod.GET))
                .andRespond(withSuccess(fallbackFeed(false, "2.5.4594"), MediaType.APPLICATION_XML));

        Optional<RegistryMatch> result = client.lookup("advanced-ip-scanner", "2.5.4594.1");

        assertThat(result).isPresent();
        assertThat(result.get().exactVersionConfirmed()).isFalse();
        assertThat(result.get().confidence()).isEqualByComparingTo("0.5");
        server.verify();
    }

    @Test
    void ecosystemIsChocolatey() {
        assertThat(client.ecosystem()).isEqualTo("chocolatey");
    }
}
