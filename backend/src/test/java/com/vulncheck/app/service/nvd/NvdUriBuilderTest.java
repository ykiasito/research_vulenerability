package com.vulncheck.app.service.nvd;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import org.junit.jupiter.api.Test;

/**
 * Task-backlog items 254/255: this is now the single place the brace/percent/plus encoding
 * behavior shared by {@link com.vulncheck.app.service.vuln.NvdVulnerabilitySource}, {@link
 * com.vulncheck.app.service.vuln.NvdKeywordVulnerabilitySource}, {@link
 * com.vulncheck.app.service.NvdCpeSyncService}, and the test-only {@code
 * NvdMirrorAbVerificationRunner} is exercised — those four classes' own tests no longer duplicate
 * these edge cases (they cover their own call-site-specific parameter shapes instead, e.g. which
 * param names/values they pass and how they map a response, and trust this class's own coverage
 * for the general encoding correctness).
 */
class NvdUriBuilderTest {

    private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    @Test
    void buildsAPlainUriWithNoSpecialCharacters() {
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("cpeName", "cpe:2.3:a:apache:log4j:1.2.14:*:*:*:*:*:*:*")
                .queryParam("resultsPerPage", 2000)
                .queryParam("startIndex", 0)
                .build();

        assertThat(uri.toString()).isEqualTo(BASE_URL
                + "?cpeName=cpe:2.3:a:apache:log4j:1.2.14:*:*:*:*:*:*:*"
                + "&resultsPerPage=2000&startIndex=0");
    }

    @Test
    void encodesAnUnencodedAmpersandInAStringValueInsteadOfInjectingAnExtraQueryParam() {
        // A version cell like "1.0&resultsPerPage=1" must not be able to inject its own
        // resultsPerPage ahead of the real one (silent result-truncation vector, PR#158 REVISE
        // item 1) -- confirms the "&" itself is percent-encoded, not passed through literally.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("cpeName", "cpe:2.3:a:apache:log4j:1.0&resultsPerPage=1:*:*:*:*:*:*:*")
                .queryParam("resultsPerPage", 2000)
                .build();

        assertThat(uri.toString()).contains("%26resultsPerPage%3D1");
        // getRawQuery(), not getQuery() -- the latter percent-decodes, which would defeat this
        // assertion's whole point (confirming the *encoded* form only has one resultsPerPage).
        assertThat(uri.getRawQuery()).containsOnlyOnce("resultsPerPage=2000");
    }

    @Test
    void balancedBraceValueIsPercentEncodedInsteadOfThrowing() {
        // An MSI ProductCode GUID like "{90160000-008C}" left unencoded by a naive
        // UriComponentsBuilder#queryParam()+encode() call (URI *template* encoding leaves "{"/"}"
        // alone) used to trip the single-argument java.net.URI constructor with "Illegal character
        // in query" -- confirms this class's own per-value encoding (UriUtils#encodeQueryParam, no
        // URI templating involved) percent-encodes both braces instead of throwing.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("cpeName", "cpe:2.3:a:apache:log4j:1.0 {90160000-008C}:*:*:*:*:*:*:*")
                .build();

        assertThat(uri.toString()).contains("%7B90160000-008C%7D");
    }

    @Test
    void unbalancedBraceValueIsPercentEncodedInsteadOfThrowing() {
        // A CSV column truncated mid-value (e.g. "Office {90160000") can carry a lone, unbalanced
        // brace -- unlike a URI-templating approach (which represents an unexpanded variable using
        // this exact "{...}" syntax and can therefore get confused by a value that happens to look
        // like one, see this class's own javadoc), per-value percent-encoding has no such ambiguity:
        // whatever literal "{" is in the value just gets percent-encoded, balanced or not.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("cpeName", "cpe:2.3:a:apache:log4j:Office {90160000:*:*:*:*:*:*:*")
                .build();

        assertThat(uri.toString()).contains("%7B90160000");
        assertThat(uri.toString()).doesNotContain("{90160000");
    }

    @Test
    void aValueThatIsExactlyUriTemplateShapedIsStillPercentEncodedCorrectly() {
        // The bug this class's javadoc documents finding while writing this very test suite: a
        // value that is, on its own, an exact "{token}" shape (e.g. a version cell that is only a
        // bare GUID) defeated the previous expand-then-encode approach, which left it as literal,
        // unencoded "{token}" text -- indistinguishable, to that approach, from a genuinely
        // still-unexpanded template variable. Per-value encoding has no such blind spot.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("cpeName", "{90160000-008C-0000-1000-0000000FF1CE}")
                .build();

        assertThat(uri.getRawQuery()).isEqualTo("cpeName=%7B90160000-008C-0000-1000-0000000FF1CE%7D");
    }

    @Test
    void literalPercentSignValueIsPercentEncodedInsteadOfMisreadAsAnExistingEscape() {
        // Free-text like "Foo 50%" must have its "%" percent-encoded to "%25" rather than being
        // misread as the start of an existing percent-escape or tripping the URI constructor.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("keywordSearch", "Foo 50%")
                .build();

        assertThat(uri.toString()).contains("Foo%2050%25");
    }

    @Test
    void literalPlusSignValueIsPercentEncodedRatherThanLeftAmbiguousWithASpace() {
        // Task-backlog item 255: UriComponentsBuilder#encode() alone leaves "+" untouched (RFC 3986
        // doesn't reserve it in a query value), but a server that form-decodes the query string
        // reads an un-escaped "+" as a literal space -- "Microsoft Visual C++ Redistributable"
        // would otherwise become effectively "Microsoft Visual C  Redistributable" server-side.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("keywordSearch", "Microsoft Visual C++ Redistributable")
                .build();

        assertThat(uri.toString()).contains("Microsoft%20Visual%20C%2B%2B%20Redistributable");
        assertThat(uri.toString()).doesNotContain("C++");
    }

    @Test
    void queryFlagAddsABareNameWithNoValue() {
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("keywordSearch", "log4j")
                .queryFlag("keywordExactMatch")
                .queryParam("resultsPerPage", 20)
                .build();

        assertThat(uri.getRawQuery()).isEqualTo("keywordSearch=log4j&keywordExactMatch&resultsPerPage=20");
    }

    @Test
    void multipleStringParamsAreEachIndependentlyEncodedAndKeepTheirOwnValue() {
        // Guards against two different queryParam(String, String) calls' values getting mixed up
        // or one clobbering the other (e.g. a shared mutable encoding buffer reused incorrectly) --
        // each call's own value must survive to exactly its own parameter, still separately
        // percent-encoded, in the order added.
        URI uri = NvdUriBuilder.fromHttpUrl(BASE_URL)
                .queryParam("first", "{alpha}")
                .queryParam("second", "{beta}")
                .build();

        assertThat(uri.getRawQuery()).isEqualTo("first=%7Balpha%7D&second=%7Bbeta%7D");
    }
}
