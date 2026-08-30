package com.vulncheck.app.service.csaf;

import com.fasterxml.jackson.databind.JsonNode;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * Shared, vendor-agnostic CSAF {@code product_tree} parser — see
 * {@code docs/spec/csaf-vendor-advisory-plan.md} §4: the JSON shape here is OASIS/ISO-standardized
 * (CSAF 2.0), so parsing it once and reusing it across every vendor sync service (Siemens, Red Hat)
 * avoids redundantly re-parsing the same standard twice — unlike the per-vendor *meaning* of a
 * product name, which stays unshared (see {@code CsafVulnerabilitySource}).
 *
 * <p>Structural gaps a naive "walk branches[], read the leaf" implementation misses (plan §1-5,
 * and the Phase 2 go/no-go review's item 2/3):
 * <ol>
 *   <li>{@code product_tree.relationships[]} (e.g. {@code category: "default_component_of"}) encodes
 *   a *combination* product — "component X as installed on platform Y" — via a synthesized {@code
 *   full_product_name.product_id} that never appears anywhere in {@code branches[]} itself. {@code
 *   product_status} entries can reference this synthesized id directly (the canonical Red Hat "RHEL
 *   9's openssl" case), so resolving it is required, not optional, for correctness.</li>
 *   <li>Architecture-only variant branches (e.g. one leaf per x86_64/aarch64/s390x of the same
 *       component+version) are folded into a single {@code csaf_products} row — see {@link
 *       #fold} — since {@code csaf_products}/{@code csaf_product_status} would otherwise grow by a
 *       small-integer multiple for no benefit this app's matching logic needs (plan §3-1's volume
 *       control).</li>
 *   <li><b>purl-derived naming (Phase 2 go/no-go review, item 2 — CRITICAL, fixes a real bug Siemens
 *   already ships):</b> when {@code product_identification_helper.purl} is present, {@link
 *   #resolveLeaf} derives {@code component_name}/{@code component_version} by parsing the purl
 *   itself (e.g. {@code pkg:rpm/redhat/openssl@3.0.7-24.el9_2?arch=x86_64} -&gt; name={@code
 *   openssl}, version={@code 3.0.7-24.el9_2}) instead of falling back to the leaf's raw {@code
 *   product.name}. For Red Hat's RPM-shaped leaves that raw name is the full NEVRA string (e.g.
 *   {@code openssl-1:3.0.7-24.el9_2.x86_64}), which measured {@code similarity('openssl',
 *   'openssl-1:3.0.7-24.el9_2.x86_64') = 0.258} — below this app's 0.35 matching threshold — a
 *   structural miss against ~87% of Red Hat's real product rows, not an edge case. Confirmed live
 *   2026-08-27 against the full 27,930-document Red Hat advisories archive that every real {@code
 *   product_version}/{@code product_version_range} leaf sampled (530,517 of 530,517, i.e. 100% in a
 *   ~9,310-document sample) carries a purl, so this is the dominant path for Red Hat. Confirmed live
 *   the same day that Siemens' real corpus (831 advisories) carries NO purl anywhere (see {@code
 *   CsafProductTreeWalkerTest}'s javadoc) — so for every existing Siemens document this new branch
 *   is simply never taken, and the pre-existing ancestor/leaf-name fallback below is untouched byte
 *   for byte in its own decision logic. The original raw leaf name is preserved on {@link
 *   ResolvedProduct#rawLeafName()} (persisted to {@code csaf_products.raw_leaf_name}) purely for
 *   debugging/display — matching is always against the purl-derived name/version when a purl is
 *   present.</li>
 *   <li><b>debuginfo/debugsource skip (Phase 2 go/no-go review, item 3):</b> {@link #resolveLeaf}
 *   returns {@code null} (silently dropped by {@link #walkBranches}, which never adds it to the
 *   output map) for any product whose derived name ends in {@code -debuginfo} or {@code
 *   -debugsource} — real RPM packages Red Hat ships CSAF data for, but never present in a customer's
 *   actual install/CSV (measured ~32% of Red Hat's raw product rows). A relationship referencing a
 *   skipped id resolves to "unresolved product_reference" and is itself skipped, same as any other
 *   dangling reference.</li>
 * </ol>
 *
 * <p><b>Fold key and architecture (Phase 2 go/no-go review, item 3):</b> {@link #fold} collapses on
 * {@code (component_name, component_version, platform_name)} — unchanged from Phase 1. This alone is
 * enough to fold Red Hat's architecture variants once purl-derived naming (above) is in place,
 * because a purl's {@code ?arch=...} qualifier is never part of its version segment (the purl spec
 * keeps qualifiers strictly after the version) — {@link #parsePurl} only ever reads the segment
 * between {@code @} and the first {@code ?}/{@code #}, so the parsed version is already
 * architecture-free without any extra stripping step in {@link #fold} itself. The full purl
 * (including its {@code ?arch=...} qualifier) is still kept on {@link ResolvedProduct#purl()} for
 * reference, per the review's "keep it available elsewhere if useful" note.
 */
@Component
@Slf4j
public class CsafProductTreeWalker {

    /** One resolved product — either a plain leaf from {@code branches[]}, or a synthesized
     *  component-in-platform combination from {@code relationships[]}.
     *
     *  @param rawLeafName the CSAF leaf's own, unmodified {@code product.name} — e.g. the full NEVRA
     *                      string for an RPM ({@code openssl-1:3.0.7-24.el9_2.x86_64}) — kept purely
     *                      for debugging/display (plan §3, Phase 2 review item 2). Never used for
     *                      matching; {@link #componentName} is what {@code CsafVulnerabilitySource}
     *                      queries against. */
    public record ResolvedProduct(String componentName, String componentVersion, String platformName, String cpe, String purl, String rawLeafName) {
    }

    /**
     * @param productsByCanonicalId the (post-fold) rows to persist into {@code csaf_products},
     *                               keyed by the canonical CSAF product_id chosen for that
     *                               (component, version, platform) tuple.
     * @param productIdRemap every original CSAF product_id seen in {@code branches[]}/{@code
     *                        relationships[]} (including ids that are already canonical, mapped to
     *                        themselves) — callers resolving a {@code product_status}/{@code
     *                        remediations} entry's product_id must look it up here first to land on
     *                        the row actually present in {@code csaf_products}. A skipped debuginfo/
     *                        debugsource product_id is absent from this map entirely — callers must
     *                        treat "no remap entry" the same as any other dangling reference.
     */
    public record WalkResult(Map<String, ResolvedProduct> productsByCanonicalId, Map<String, String> productIdRemap) {
    }

    public WalkResult walk(JsonNode productTree) {
        Map<String, ResolvedProduct> byOriginalId = new LinkedHashMap<>();
        walkBranches(productTree.path("branches"), new ArrayDeque<>(), byOriginalId);
        resolveRelationships(productTree.path("relationships"), byOriginalId);
        return fold(byOriginalId);
    }

    private void walkBranches(JsonNode branches, Deque<JsonNode> ancestors, Map<String, ResolvedProduct> out) {
        for (JsonNode branch : branches) {
            JsonNode productLeaf = branch.path("product");
            if (productLeaf.isObject() && productLeaf.hasNonNull("product_id")) {
                ResolvedProduct resolved = resolveLeaf(branch, productLeaf, ancestors);
                if (resolved != null) {
                    out.put(productLeaf.path("product_id").asText(), resolved);
                }
            }
            JsonNode children = branch.path("branches");
            if (children.isArray() && !children.isEmpty()) {
                ancestors.push(branch);
                walkBranches(children, ancestors, out);
                ancestors.pop();
            }
        }
    }

    /** @return the resolved product, or {@code null} if this leaf is a debuginfo/debugsource
     *          package that should be dropped entirely (Phase 2 review item 3). */
    private ResolvedProduct resolveLeaf(JsonNode leafBranch, JsonNode productLeaf, Deque<JsonNode> ancestors) {
        String rawLeafName = productLeaf.path("name").asText(null);
        String category = leafBranch.path("category").asText(null);

        JsonNode helper = productLeaf.path("product_identification_helper");
        String cpe = helper.path("cpe").asText(null);
        String purl = helper.path("purl").asText(null);

        String componentName;
        String componentVersion;

        ParsedPurl parsedPurl = parsePurl(purl);
        if (parsedPurl != null) {
            // Phase 2 review item 2 — purl-derived naming is the primary path whenever present;
            // see the class javadoc for why this is correctness-critical for Red Hat and a no-op
            // for Siemens (which never carries a purl in its real corpus).
            componentName = parsedPurl.name();
            componentVersion = parsedPurl.version();
        } else {
            // Unchanged fallback logic from Phase 1 (byte-for-byte the same decision this method
            // made before purl support existed) — still the only path for Siemens.
            componentName = null;
            if ("product_name".equals(category)) {
                componentName = leafBranch.path("name").asText(null);
            } else {
                for (JsonNode ancestor : ancestors) {
                    if ("product_name".equals(ancestor.path("category").asText(null))) {
                        componentName = ancestor.path("name").asText(null);
                        break;
                    }
                }
            }
            if (componentName == null) {
                // No product_name ancestor found (an unusual tree shape) — fall back to the leaf's
                // own product.name rather than leaving this row unmatchable against anything.
                componentName = rawLeafName;
            }
            componentVersion = ("product_version".equals(category) || "product_version_range".equals(category))
                    ? leafBranch.path("name").asText(null)
                    : null;
        }

        if (isDebugPackage(componentName) || isDebugPackage(rawLeafName)) {
            return null;
        }

        return new ResolvedProduct(componentName, componentVersion, null, cpe, purl, rawLeafName);
    }

    /** Real RPM packages Red Hat ships CSAF data for but that never appear in a customer's actual
     *  install/CSV (Phase 2 review item 3, ~32% of Red Hat's raw product rows measured live).
     *
     *  <p><b>Senior review REVISE item 9 (2026-08-27):</b> a suffix-only check ({@code
     *  endsWith("-debuginfo")}) missed 22,509 real rows (1.3% of the corpus) that carry an additional
     *  architecture suffix AFTER the debug marker, e.g. {@code kernel-debuginfo-common-x86_64}. Matching
     *  {@code -debuginfo-}/{@code -debugsource-} as an INFIX (not just a suffix) catches that case
     *  while deliberately NOT matching a real, legitimate package like {@code
     *  elfutils-debuginfod-client} — its substring is {@code debuginfod-} (the extra trailing {@code
     *  d}), never {@code debuginfo-}, so the more specific infix pattern (which requires the marker be
     *  followed immediately by a hyphen) correctly leaves it alone where a naive "contains debuginfo
     *  anywhere" check would have wrongly dropped it. */
    private boolean isDebugPackage(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase(Locale.ROOT);
        return lower.endsWith("-debuginfo") || lower.endsWith("-debugsource")
                || lower.contains("-debuginfo-") || lower.contains("-debugsource-");
    }

    private void resolveRelationships(JsonNode relationships, Map<String, ResolvedProduct> byOriginalId) {
        for (JsonNode relationship : relationships) {
            JsonNode fullProductName = relationship.path("full_product_name");
            String syntheticId = fullProductName.path("product_id").asText(null);
            if (syntheticId == null) {
                continue;
            }
            String componentRef = relationship.path("product_reference").asText(null);
            String platformRef = relationship.path("relates_to_product_reference").asText(null);
            ResolvedProduct component = componentRef != null ? byOriginalId.get(componentRef) : null;
            if (component == null) {
                // Also covers a component that resolveLeaf dropped as debuginfo/debugsource —
                // it's simply absent from byOriginalId, indistinguishable from any other dangling
                // reference, and correctly skipped either way.
                log.debug("CSAF relationship references unresolved product_reference={} — skipping", componentRef);
                continue;
            }
            ResolvedProduct platform = platformRef != null ? byOriginalId.get(platformRef) : null;

            JsonNode helper = fullProductName.path("product_identification_helper");
            String cpe = helper.path("cpe").asText(component.cpe());
            String purl = helper.path("purl").asText(component.purl());

            byOriginalId.put(syntheticId, new ResolvedProduct(
                    component.componentName(), component.componentVersion(),
                    platform != null ? platform.componentName() : null, cpe, purl, component.rawLeafName()));
        }
    }

    /** Collapses every original product_id that resolved to the same (component_name,
     *  component_version, platform_name) tuple into one canonical row — see the class javadoc. The
     *  first-encountered original id for a given tuple becomes that tuple's canonical CSAF
     *  product_id (iteration order is insertion order — {@link LinkedHashMap} throughout — so this
     *  is deterministic run to run for the same document). */
    private WalkResult fold(Map<String, ResolvedProduct> byOriginalId) {
        Map<String, String> canonicalIdByTuple = new LinkedHashMap<>();
        Map<String, ResolvedProduct> productsByCanonicalId = new LinkedHashMap<>();
        Map<String, String> remap = new LinkedHashMap<>();

        for (Map.Entry<String, ResolvedProduct> entry : byOriginalId.entrySet()) {
            String originalId = entry.getKey();
            ResolvedProduct product = entry.getValue();
            String tupleKey = tupleKey(product);
            String canonicalId = canonicalIdByTuple.computeIfAbsent(tupleKey, k -> originalId);
            if (canonicalId.equals(originalId)) {
                productsByCanonicalId.put(canonicalId, product);
            }
            remap.put(originalId, canonicalId);
        }

        return new WalkResult(productsByCanonicalId, remap);
    }

    private String tupleKey(ResolvedProduct product) {
        return safe(product.componentName()) + "|" + safe(product.componentVersion()) + "|" + safe(product.platformName());
    }

    private String safe(String value) {
        return value == null ? "" : value;
    }

    /** Parsed {@code pkg:type/namespace/name@version?qualifiers#subpath} — only {@code name} and
     *  {@code version} are needed here; qualifiers (including {@code arch}) and subpath are
     *  deliberately discarded rather than folded into either field (see the class javadoc's "Fold
     *  key and architecture" note). */
    private record ParsedPurl(String name, String version) {
    }

    private ParsedPurl parsePurl(String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        String body = purl;
        int hashIdx = body.indexOf('#');
        if (hashIdx >= 0) {
            body = body.substring(0, hashIdx);
        }
        int qIdx = body.indexOf('?');
        if (qIdx >= 0) {
            body = body.substring(0, qIdx);
        }
        if (!body.startsWith("pkg:")) {
            return null;
        }
        body = body.substring("pkg:".length());
        int atIdx = body.lastIndexOf('@');
        if (atIdx < 0 || atIdx == body.length() - 1) {
            return null; // no version segment — nothing usable to derive a version from
        }
        String namespaceAndName = body.substring(0, atIdx);
        String versionSegment = body.substring(atIdx + 1);
        int slashIdx = namespaceAndName.lastIndexOf('/');
        String namePart = slashIdx >= 0 ? namespaceAndName.substring(slashIdx + 1) : namespaceAndName;
        String name = percentDecode(namePart);
        String version = percentDecode(versionSegment);
        if (name == null || name.isBlank() || version == null || version.isBlank()) {
            return null;
        }
        return new ParsedPurl(name, version);
    }

    /** purl (per its spec) only ever percent-encodes with {@code %XX} — a literal {@code +} (which
     *  does show up in real version strings, e.g. build metadata) must NOT be decoded to a space the
     *  way {@link URLDecoder} would for {@code application/x-www-form-urlencoded} text, so {@code +}
     *  is escaped first to survive the round trip unchanged. */
    private String percentDecode(String value) {
        if (value == null || value.indexOf('%') < 0) {
            return value;
        }
        try {
            return URLDecoder.decode(value.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }
}
