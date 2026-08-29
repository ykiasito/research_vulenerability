package com.vulncheck.app.service.registry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Pattern;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Stage1 Tier1 lookup against Chocolatey's community package feed
 * (https://community.chocolatey.org/api/v2/), an OData v2 (Atom/XML) endpoint structurally
 * identical to a NuGet v2 gallery. Added to recover the desktop-installer population (OBS Studio,
 * HandBrake, Slack, Docker Desktop, ...) that the other 10 registries — all language/library
 * package managers — never had any chance of identifying, since Windows desktop software is
 * exactly Chocolatey's own catalog.
 *
 * <p><b>This endpoint is confirmed live-vulnerable to OData {@code $filter} injection</b>
 * ({@code $filter=tolower(Id) eq 'x' or '1' eq '1'} returns an always-true HTTP 200). Product
 * names here come straight from user-uploaded CSV data, so this client deliberately never builds
 * a {@code $filter} query at all. A prior review separately confirmed both {@code
 * FindPackagesById}'s {@code id} parameter and {@code Search}'s {@code searchTerm} parameter
 * return HTTP 400 (rejected outright) on the same tautology-injection payload that the vulnerable
 * {@code $filter} parameter accepts with 200 — this client only ever issues the two request
 * shapes below, never a {@code $filter} query, and the normalized id is whitelist-validated
 * against {@link #ID_PATTERN} before it is ever placed into a URL, as a second, independent
 * layer.
 *
 * <p>Two request shapes, in order, per lookup:
 * <ol>
 *   <li>The path-addressed exact-key form {@code Packages(Id='<id>',Version='<version>')}, which
 *       OData parses as a literal key predicate (not a boolean expression). A 2xx here means the
 *       feed itself confirms this exact (id, version) pair.
 *   <li>Only when that returns non-2xx: ONE existence-fallback call, {@code
 *       FindPackagesById()?id='<id>'&amp;$select=Version} (same whitelist-validated id, no {@code
 *       $filter}), which lists every version this id has ever published. {@code $select=Version}
 *       keeps the response to just the version list rather than every package field — measured
 *       ~50KB for a real package's full history, versus 219KB unfiltered for the same query
 *       ({@code FindPackagesById()?id='sharex'} with no {@code $select}). This is what
 *       distinguishes "the id doesn't exist at all" (feed returns a confirmed-empty
 *       {@code <feed>}, zero {@code <entry>} elements — this OData feed answers HTTP 200 either
 *       way, so emptiness has to be read from the parsed body, not the status code) from "the id
 *       exists but not at this exact version string" (informs the unconfirmed-match contract
 *       below).
 * </ol>
 *
 * <p>The fallback feed paginates at 40 entries, with a {@code <link rel="next" .../>} element
 * present only when truncated. A package with more than 40 published versions (e.g. HandBrake,
 * Krita — confirmed live) can have its current version fall on page 2+, entirely absent from this
 * single-page fallback response. Rather than following pagination (which would turn "one fallback
 * call" into an unbounded number), a truncated response's version list is treated as incomplete
 * evidence only for {@link RegistryMatch#versions()} — populated when the list is known-complete
 * (no {@code rel="next"} link), left as {@code List.of()} when truncated, since a partial list
 * feeding {@link RegistryLookupCache#reuseForVersion} would otherwise produce a false
 * "this version doesn't exist" answer for some other item asking about a real version that
 * happens to live past page 1.
 *
 * <p>When the id exists but the CSV's exact version string isn't among the (possibly
 * page-1-only) versions returned, this reports a match with {@code exactVersionConfirmed=false}
 * at {@link #VERSION_UNCONFIRMED_CONFIDENCE} — same contract other {@link PackageRegistryLookup}
 * implementations already use, see e.g. {@code NpmRegistryClient}. One narrow exception: a
 * strictly component-EXTENSION prefix match ({@code feedVersion.startsWith(csvVersion + ".")},
 * e.g. CSV {@code "2.5.4594"} against a feed version {@code "2.5.4594.1"}) is treated as confirmed
 * when exactly one feed version matches that way; an AMBIGUOUS prefix match (more than one feed
 * version extends the CSV version) falls back to the same unconfirmed treatment rather than
 * guessing which one is meant. In every case — exact, prefix-extension, or unconfirmed — the
 * ORIGINAL CSV version string is what ends up in the returned {@code purl}; the feed's own version
 * string is never substituted in.
 *
 * <p>The response body is Atom/XML, the first XML-format response any registry client here has to
 * parse (every other one is JSON) — parsed with an explicitly XXE-hardened {@link
 * DocumentBuilderFactory} (DOCTYPE declarations disallowed outright, external general/parameter
 * entity resolution disabled) rather than relying on whatever a library's defaults happen to be.
 * The response body is also read into memory under a hard cap ({@link #MAX_RESPONSE_BYTES}) as
 * defense in depth: this runs under an 8-way concurrent item-processing executor, and even the
 * larger {@code $select=Version}-filtered fallback response measured a small fraction of that cap.
 *
 * <p><b>Out of scope, deliberately not implemented here</b>: resolving a CSV product name to the
 * WRONG Chocolatey id (e.g. "android-studio" vs. the real id "androidstudio", "slack-desktop" vs.
 * "slack", "windows-terminal" vs. "microsoft-windows-terminal") would need a {@code Search()}-based
 * fuzzy id-resolution fallback — a separate, larger feature needing its own relevance gating and a
 * whitelist permissive enough for {@code searchTerm} (which, unlike {@link #ID_PATTERN}, may
 * legitimately contain spaces). Filed here as a follow-up note, not built in this pass.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class ChocolateyRegistryClient implements PackageRegistryLookup {

    private static final String ECOSYSTEM = "chocolatey";

    private static final String BASE_URL = "https://community.chocolatey.org/api/v2/";

    /** Chocolatey/NuGet package id grammar is permissive but well short of arbitrary OData syntax
     *  characters (no quote, space, parenthesis, comma, ...) — this is checked BEFORE any URL is
     *  built, not just relied on for correctness, since it is this client's primary defense
     *  against the confirmed {@code $filter} injection surface on this feed (see class javadoc). */
    private static final Pattern ID_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    private static final BigDecimal VERSION_CONFIRMED_CONFIDENCE = new BigDecimal("0.95");

    /** Confidence for an existence-fallback match where the id is confirmed to exist but the
     *  CSV's exact version string could not be confirmed among the feed's published versions —
     *  mirrors the unconfirmed-match confidence other {@link PackageRegistryLookup} implementations
     *  already use (e.g. {@code NpmRegistryClient}). */
    private static final BigDecimal VERSION_UNCONFIRMED_CONFIDENCE = new BigDecimal("0.5");

    /** Hard cap on how much of the HTTP response body is ever read into memory for a single
     *  lookup — see class javadoc for the measured 219KB worst case this defends against. */
    private static final int MAX_RESPONSE_BYTES = 512 * 1024;

    private static final String ODATA_DATA_NS = "http://schemas.microsoft.com/ado/2007/08/dataservices";

    private static final String ATOM_NS = "http://www.w3.org/2005/Atom";

    private final RestClient externalApiRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;

    @Override
    public Optional<RegistryMatch> lookup(String productName, String version) {
        if (productName == null || productName.isBlank() || version == null || version.isBlank()) {
            return Optional.empty();
        }
        String id = normalize(productName);
        if (!ID_PATTERN.matcher(id).matches()) {
            log.debug("Chocolatey lookup skipped for product '{}': normalized id '{}' fails the id whitelist",
                    productName, id);
            return Optional.empty();
        }

        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            ExactKeyAttempt attempt = externalApiRestClient.get()
                    .uri(BASE_URL + "Packages(Id='{id}',Version='{version}')", id, version)
                    .exchange((request, response) -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            return new ExactKeyAttempt(false, Optional.empty());
                        }
                        byte[] body = readBounded(response.getBody(), MAX_RESPONSE_BYTES);
                        return new ExactKeyAttempt(true, parseConfirmedMatch(body, productName, id, version));
                    });
            if (attempt.was2xx()) {
                return attempt.match();
            }
            // Exact-key lookup came back non-2xx — try the existence-fallback call (class javadoc)
            // before concluding the package doesn't exist at all.
            return lookupViaExistenceFallback(productName, id, version);
        } catch (Exception e) {
            log.debug("Chocolatey registry lookup failed for product={} id={}", productName, id, e);
            return Optional.empty();
        }
    }

    /** @param was2xx whether the exact-key request itself returned 2xx — distinct from whether a
     *                match was ultimately confirmed, since a 2xx-but-unparseable/mismatched
     *                response (see {@link #parseConfirmedMatch}) is deliberately NOT retried via
     *                the fallback (that response already answered the exact-key question). */
    private record ExactKeyAttempt(boolean was2xx, Optional<RegistryMatch> match) {
    }

    /**
     * ONE existence-fallback request (class javadoc) issued only after the exact-key lookup itself
     * came back non-2xx. Distinguishes "this id doesn't exist in the catalog at all" (feed
     * confirmed empty, zero {@code <entry>} elements) from "the id exists, just not at this exact
     * version string" (returns an unconfirmed match, or a confirmed one via an unambiguous
     * prefix-extension version match — see {@link #parseFallbackMatch}).
     */
    private Optional<RegistryMatch> lookupViaExistenceFallback(String productName, String id, String version) {
        try {
            rateLimiter.awaitTurn(ECOSYSTEM);
            return externalApiRestClient.get()
                    .uri(BASE_URL + "FindPackagesById()?id='{id}'&$select=Version", id)
                    .exchange((request, response) -> {
                        if (!response.getStatusCode().is2xxSuccessful()) {
                            return Optional.<RegistryMatch>empty();
                        }
                        byte[] body = readBounded(response.getBody(), MAX_RESPONSE_BYTES);
                        return parseFallbackMatch(body, productName, id, version);
                    });
        } catch (Exception e) {
            log.debug("Chocolatey existence-fallback lookup failed for product={} id={}", productName, id, e);
            return Optional.empty();
        }
    }

    /** Lowercase + collapse-whitespace-to-hyphen, e.g. "OBS Studio" -> "obs-studio", "Advanced IP
     *  Scanner" -> "advanced-ip-scanner" — Chocolatey package ids are lowercase-hyphenated by
     *  convention. Purely mechanical: this does not guarantee a hit (e.g. the real "Chocolatey
     *  CLI" package id is "chocolatey", not "chocolatey-cli"), only that the candidate id is
     *  well-formed enough to be worth a single exact-key request. */
    private String normalize(String productName) {
        // Locale.ROOT deliberately, not the JVM default locale: this string feeds a
        // whitelist-validated URL id (see class javadoc's injection-defense discussion), so it must
        // not vary by locale (e.g. Turkish's dotless-i lowercasing "I" to "ı", not "i").
        return WHITESPACE.matcher(productName.trim().toLowerCase(Locale.ROOT)).replaceAll("-");
    }

    /**
     * Parses the Atom entry response and only treats this as a confirmed match if the feed's own
     * {@code d:Version} element agrees with the version requested — a 200 on the exact-key URL
     * should always agree, so a mismatch is treated conservatively as no match at all, same as a
     * parse failure, rather than trusted on the HTTP status alone.
     */
    private Optional<RegistryMatch> parseConfirmedMatch(byte[] body, String productName, String id, String version) {
        Optional<String> feedVersion = parseVersionElement(body);
        if (feedVersion.isEmpty() || !feedVersion.get().equalsIgnoreCase(version)) {
            log.debug("Chocolatey response for id={} did not confirm version={} (feed reported {})",
                    id, version, feedVersion.orElse("<none>"));
            return Optional.empty();
        }
        String purl = "pkg:chocolatey/" + id + "@" + version;
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, VERSION_CONFIRMED_CONFIDENCE, true));
    }

    /**
     * Parses the existence-fallback feed and decides the match, per the rules laid out in the
     * class javadoc:
     * <ul>
     *   <li>zero {@code <entry>} elements (confirmed-empty feed, not just a non-2xx status) — the
     *       id doesn't exist at all, {@code Optional.empty()};
     *   <li>the CSV version string appears verbatim (case-insensitively) among the feed's own
     *       {@code d:Version} values — confirmed, {@link #VERSION_CONFIRMED_CONFIDENCE};
     *   <li>exactly one feed version is a strict component-extension of the CSV version ({@code
     *       feedVersion.startsWith(csvVersion + ".")}) — also confirmed, same confidence; more than
     *       one such candidate is ambiguous and falls through to the next case rather than guessing;
     *   <li>otherwise — the id exists but this exact version couldn't be confirmed, {@link
     *       #VERSION_UNCONFIRMED_CONFIDENCE} with {@code exactVersionConfirmed=false}.
     * </ul>
     * In every non-empty case, the returned {@code purl} carries the ORIGINAL CSV {@code version}
     * string, never a version string read off the feed — this method only ever confirms or fails
     * to confirm the caller's own version, it does not correct it.
     */
    private Optional<RegistryMatch> parseFallbackMatch(byte[] body, String productName, String id, String version) {
        FallbackFeed feed = parseFallbackFeed(body);
        if (feed == null) {
            // Parse failure — conservative, same treatment as the exact-key path: no match rather
            // than trusting the HTTP status alone.
            return Optional.empty();
        }
        if (feed.entryCount() == 0) {
            log.debug("Chocolatey existence-fallback confirmed id={} does not exist (empty feed)", id);
            return Optional.empty();
        }

        List<String> versions = feed.versions();
        // versions() is only safe to hand back to RegistryLookupCache when the feed's own
        // pagination confirms this was the complete list — see class javadoc's pagination
        // discussion and RegistryLookupCache#reuseForVersion.
        List<String> versionsForMatch = feed.truncated() ? List.of() : versions;
        String purl = "pkg:chocolatey/" + id + "@" + version;

        boolean exact = versions.stream().anyMatch(v -> v.equalsIgnoreCase(version));
        if (exact) {
            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, VERSION_CONFIRMED_CONFIDENCE, true, versionsForMatch));
        }

        List<String> prefixExtensionMatches = versions.stream()
                .filter(v -> v.startsWith(version + "."))
                .toList();
        if (prefixExtensionMatches.size() == 1) {
            log.debug("Chocolatey existence-fallback id={} requestedVersion={} confirmed via unambiguous "
                    + "prefix-extension match to feed version={}", id, version, prefixExtensionMatches.get(0));
            return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, VERSION_CONFIRMED_CONFIDENCE, true, versionsForMatch));
        }
        if (prefixExtensionMatches.size() > 1) {
            log.debug("Chocolatey existence-fallback id={} requestedVersion={} has an AMBIGUOUS prefix-extension "
                    + "match against multiple feed versions={} — not picking one, reporting unconfirmed",
                    id, version, prefixExtensionMatches);
        }
        return Optional.of(new RegistryMatch(ECOSYSTEM, productName, purl, VERSION_UNCONFIRMED_CONFIDENCE, false, versionsForMatch));
    }

    /**
     * XXE-hardened Atom/XML parse of the response body. A fresh {@link DocumentBuilderFactory} is
     * built per call rather than shared as a static field: {@code DocumentBuilderFactory}/{@code
     * DocumentBuilder} are not documented as thread-safe, and this client runs under an 8-way
     * concurrent item-processing executor — the cost of building one is negligible next to the
     * network round trip and rate-limiter wait this method is already behind.
     */
    private Optional<String> parseVersionElement(byte[] body) {
        try {
            DocumentBuilder builder = newHardenedDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body));

            NodeList versionNodes = doc.getElementsByTagNameNS(ODATA_DATA_NS, "Version");
            if (versionNodes.getLength() == 0) {
                return Optional.empty();
            }
            String text = versionNodes.item(0).getTextContent();
            return text == null || text.isBlank() ? Optional.empty() : Optional.of(text.trim());
        } catch (Exception e) {
            log.debug("Chocolatey response XML parse failed", e);
            return Optional.empty();
        }
    }

    /** entryCount() is the ground truth for "does this id exist at all" (see class javadoc — this
     *  feed answers HTTP 200 either way); versions() is every {@code d:Version} text found, in
     *  document order; truncated() is whether a {@code <link rel="next" .../>} was present, i.e.
     *  whether versions() is known to be the id's COMPLETE published-version list or only page 1. */
    private record FallbackFeed(int entryCount, List<String> versions, boolean truncated) {
    }

    /** Multi-entry counterpart to {@link #parseVersionElement} — deliberately a separate method
     *  rather than a repurposed one: that method's {@code item(0)} only ever makes sense for the
     *  exact-key response's single entry, and silently doing the same here would just report the
     *  first of potentially dozens of published versions. Returns {@code null} (not an empty
     *  {@link FallbackFeed}) on a parse failure, so the caller can tell "confirmed empty" apart
     *  from "couldn't tell". */
    private FallbackFeed parseFallbackFeed(byte[] body) {
        try {
            DocumentBuilder builder = newHardenedDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body));

            int entryCount = doc.getElementsByTagNameNS(ATOM_NS, "entry").getLength();

            NodeList versionNodes = doc.getElementsByTagNameNS(ODATA_DATA_NS, "Version");
            List<String> versions = new ArrayList<>();
            for (int i = 0; i < versionNodes.getLength(); i++) {
                String text = versionNodes.item(i).getTextContent();
                if (text != null && !text.isBlank()) {
                    versions.add(text.trim());
                }
            }

            return new FallbackFeed(entryCount, versions, hasNextLink(doc));
        } catch (Exception e) {
            log.debug("Chocolatey existence-fallback response XML parse failed", e);
            return null;
        }
    }

    /** True if the feed carries an Atom {@code <link rel="next" .../>} — this feed's own signal
     *  that its 40-entry-per-page cap truncated the version list (see class javadoc). */
    private boolean hasNextLink(Document doc) {
        NodeList links = doc.getElementsByTagNameNS(ATOM_NS, "link");
        for (int i = 0; i < links.getLength(); i++) {
            NamedNodeMap attributes = links.item(i).getAttributes();
            Node rel = attributes == null ? null : attributes.getNamedItem("rel");
            if (rel != null && "next".equals(rel.getNodeValue())) {
                return true;
            }
        }
        return false;
    }

    /** Builds a fresh, XXE-hardened {@link DocumentBuilder} — see {@link #parseVersionElement}'s
     *  javadoc for why a fresh one is built per call rather than shared. Shared by every XML parse
     *  in this class so the hardening settings only ever exist in one place. */
    private DocumentBuilder newHardenedDocumentBuilder() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // XXE hardening — explicit, not relying on library/JDK defaults (see class javadoc):
        // disallow DOCTYPE declarations outright (also blocks billion-laughs-style entity
        // expansion, since there is no DTD at all to declare entities in), and independently
        // disable external general/parameter entity resolution in case a future JDK/parser ever
        // tolerates a DOCTYPE despite the setting above.
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        // Namespace-aware, since the meaningful elements here (d:Version, Atom entry/link) are only
        // findable via their namespace URIs, not their plain local names.
        factory.setNamespaceAware(true);
        return factory.newDocumentBuilder();
    }

    /** Reads {@code in} fully into memory, failing fast if it would exceed {@code maxBytes} —
     *  see {@link #MAX_RESPONSE_BYTES}'s javadoc for why this cap exists even on the small
     *  exact-version response shape this client requests. */
    private static byte[] readBounded(InputStream in, int maxBytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream(8192);
        byte[] buffer = new byte[8192];
        int total = 0;
        int read;
        while ((read = in.read(buffer)) != -1) {
            total += read;
            if (total > maxBytes) {
                throw new IOException("Chocolatey response exceeded " + maxBytes + " byte cap");
            }
            out.write(buffer, 0, read);
        }
        return out.toByteArray();
    }

    @Override
    public String ecosystem() {
        return ECOSYSTEM;
    }
}
