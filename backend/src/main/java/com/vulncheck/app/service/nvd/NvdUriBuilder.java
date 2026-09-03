package com.vulncheck.app.service.nvd;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Single shared place to build a request {@link URI} against an NVD REST API endpoint (CVE 2.0 or
 * CPE 2.0), consolidating an encoding fix that had to be independently discovered and applied to
 * four different call sites across three separate PRs (task-backlog item 254): {@link
 * com.vulncheck.app.service.vuln.NvdVulnerabilitySource}, {@link
 * com.vulncheck.app.service.vuln.NvdKeywordVulnerabilitySource}, {@link
 * com.vulncheck.app.service.NvdCpeSyncService}, and the test-only {@code
 * NvdMirrorAbVerificationRunner} each built their own {@link UriComponentsBuilder} chain with the
 * same fix copy-pasted (PR#158 -&gt; PR#163 -&gt; PR#165) rather than sharing one implementation —
 * this class is that one implementation.
 *
 * <h2>Why {@link #queryParam(String, String)} percent-encodes {@code value} itself, manually,
 * rather than leaning on {@code UriComponentsBuilder}'s own {@code .encode()}</h2>
 * A CSV-supplied value (CPE version cell, product/package name used as an NVD keyword search
 * term) can legitimately contain characters that break naive query-string construction — an
 * unencoded {@code "&"} (e.g. a version cell like {@code "1.0&resultsPerPage=1"}) would inject its
 * own query parameter ahead of this class's real one (a silent result-truncation vector, not SSRF
 * — the host/path are always a fixed constant — but still lets CSV input override {@code
 * resultsPerPage}/{@code startIndex}); a literal {@code "%"} (free-text like {@code "Foo 50%"})
 * must become {@code "%25"} rather than being misread as the start of an existing percent-escape;
 * a literal {@code "+"} (task-backlog item 255, see below) must become {@code "%2B"}.
 *
 * <p>The first version of this class (and every one of the four call sites it replaces) instead
 * used {@code UriComponentsBuilder}'s own <em>URI template</em> feature — pass the value through a
 * {@code "{var}"} placeholder, then call {@code .expand(Map)} before {@code .encode()} — because
 * calling {@code .encode()} directly on a builder holding the raw value verbatim leaves {@code
 * "{"}/{@code "}"} unescaped (they're URI template syntax, not data, until expanded) and trips the
 * single-argument {@code java.net.URI} constructor with "Illegal character in query" the moment a
 * CSV value happens to contain a literal brace (e.g. an MSI ProductCode GUID like {@code
 * "{90160000-008C-0000-1000-0000000FF1CE}"}, which shows up verbatim in Windows
 * installed-software listings). <b>That expand-then-encode approach has its own residual gap,
 * found while writing this class's own test suite</b>: if the value being substituted is, on its
 * own, an exact URI-template-shaped string (e.g. a version cell that is <em>only</em> {@code
 * "{SOME-TOKEN}"} with nothing else around it — a real, plausible shape for the GUID example
 * above), the post-substitution query string still looks to Spring's template machinery like an
 * as-yet-unexpanded variable reference, and {@code .encode()} — by design, since that is exactly
 * what makes expand-then-encode work for every *other* case — leaves genuine unexpanded template
 * syntax alone rather than percent-encoding it. There is no way to tell "genuinely still a
 * template placeholder" apart from "a value that happens to look like one" using this API, so this
 * class does not use URI templating at all: {@link #queryParam(String, String)} percent-encodes
 * {@code value} itself via {@link UriUtils#encodeQueryParam}, and {@link #build()} assembles the
 * already-encoded query string directly (via {@link UriComponentsBuilder#build(boolean)} with
 * {@code encoded=true}, so nothing downstream re-interprets or re-encodes it).
 *
 * <h2>The {@code "+"} gap (task-backlog item 255)</h2>
 * {@link UriUtils#encodeQueryParam} treats {@code "+"} as unreserved in a query value (RFC 3986
 * doesn't reserve it there), so a literal {@code "+"} in a CSV value — e.g. {@code "Microsoft
 * Visual C++ Redistributable"} — would otherwise be carried into the final URI unescaped. Several
 * HTTP servers (and NVD's own API, unconfirmed either way but not worth the risk) interpret an
 * un-escaped {@code "+"} in a query string using {@code application/x-www-form-urlencoded}
 * decoding rules, where {@code "+"} means a literal space — which would turn a search for {@code
 * "C++"} into effectively {@code "C  "} server-side. {@link #queryParam(String, String)} closes
 * this by percent-encoding every literal {@code "+"} in the already-encoded value to {@code
 * "%2B"}. This only ever touches a genuine data {@code "+"}: {@link UriUtils#encodeQueryParam}
 * itself never *produces* a literal {@code "+"} as output when percent-encoding any other
 * character (it always emits {@code %XX}).
 */
public final class NvdUriBuilder {

    private final String baseUrl;
    private final List<String> rawQuerySegments = new ArrayList<>();

    private NvdUriBuilder(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    /** Starts a new builder against a fixed NVD endpoint URL (never itself CSV/user-supplied — the
     *  two callers of this pass one of their own {@code private static final} API URL constants). */
    public static NvdUriBuilder fromHttpUrl(String baseUrl) {
        return new NvdUriBuilder(baseUrl);
    }

    /**
     * Adds a query parameter whose value may be CSV/user-supplied text (a CPE version cell, a
     * product/package name, a free-text keyword) — see this class's own javadoc for exactly which
     * encoding pitfalls this protects against. {@code value} is never null (every existing call
     * site already null/blank-checks its own CSV-derived value before reaching this method).
     * {@code name} is always one of this class's own callers' fixed parameter-name literals (e.g.
     * {@code "cpeName"}), never itself CSV/user-supplied, so it is not run through the same
     * encoding — a literal assumption relied on elsewhere in this class.
     */
    public NvdUriBuilder queryParam(String name, String value) {
        String encoded = UriUtils.encodeQueryParam(value, StandardCharsets.UTF_8).replace("+", "%2B");
        rawQuerySegments.add(name + "=" + encoded);
        return this;
    }

    /** Adds a query parameter whose value is always a programmatically-computed number (e.g.
     *  {@code resultsPerPage}/{@code startIndex}) — never CSV/user-supplied, so it needs none of
     *  {@link #queryParam(String, String)}'s encoding. */
    public NvdUriBuilder queryParam(String name, int value) {
        rawQuerySegments.add(name + "=" + value);
        return this;
    }

    /** Adds a bare boolean flag parameter with no value at all (e.g. NVD's {@code
     *  keywordExactMatch}, which is present-or-absent rather than {@code true}/{@code false}). */
    public NvdUriBuilder queryFlag(String name) {
        rawQuerySegments.add(name);
        return this;
    }

    /** Assembles the final {@link URI} from {@code baseUrl} plus every query segment added above,
     *  all of which are already fully encoded by the time they reach here — {@code encoded=true}
     *  tells {@link UriComponentsBuilder} to trust that and not re-encode (which would otherwise
     *  double-encode every {@code %XX} escape into {@code %25XX}). */
    public URI build() {
        String query = String.join("&", rawQuerySegments);
        return UriComponentsBuilder.fromHttpUrl(baseUrl)
                .query(query)
                .build(true)
                .toUri();
    }
}
