package com.vulncheck.app.service.csaf;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.service.csaf.CsafProductTreeWalker.ResolvedProduct;
import com.vulncheck.app.service.csaf.CsafProductTreeWalker.WalkResult;
import org.junit.jupiter.api.Test;

/**
 * {@code product_tree} shapes below are real, captured live 2026-08-27 — Siemens ProductCERT's CSAF
 * feed (SSA-620799, SSA-779699 — see {@code SiemensCsafSyncServiceTest} for the full documents these
 * come from) and, for the Phase 2 (Red Hat) tests, real fragments of RHSA-2003:315 (quagga), trimmed
 * from the real {@code csaf_advisories_2026-08-25.tar.zst} archive — see each test's own comment for
 * which. The one exception is {@link #resolvesARelationshipsComponentOfPlatformCombination} — a live
 * check of all 831 advisories in Siemens' feed on 2026-08-27 found zero uses of {@code
 * product_tree.relationships[]} anywhere in Siemens' real corpus (unlike Red Hat's documented usage,
 * confirmed live in RHSA-2003:315 itself, per the plan's §1-5), so that one test uses a hand-built
 * fixture instead, shaped to match the CSAF 2.0 spec's {@code relationships[]} example precisely.
 *
 * <p><b>Phase 2 go/no-go review item 2 regression coverage:</b> confirmed live 2026-08-27 that
 * neither SSA-620799 nor SSA-779699 (nor any of Siemens' 831 real advisories, per a live corpus
 * check) carries a {@code purl} anywhere — every Siemens test below therefore exercises ONLY the
 * pre-existing ancestor/leaf-name fallback path, unchanged. {@link
 * #fallsBackToTheAncestorProductNameBranchWhenNoPurlIsPresentSiemensRegression} makes this explicit
 * (the other Siemens tests above already prove it implicitly — they are the exact same assertions
 * that passed before this fix, still passing unmodified).
 */
class CsafProductTreeWalkerTest {

    private final CsafProductTreeWalker walker = new CsafProductTreeWalker();
    private final ObjectMapper objectMapper = new ObjectMapper();

    private JsonNode json(String text) throws Exception {
        return objectMapper.readTree(text);
    }

    @Test
    void resolvesTwoSiblingProductsUnderTheirOwnProductNameBranches() throws Exception {
        // Real product_tree from SSA-620799 (SENTRON Powercenter 1000/1100).
        JsonNode productTree = json("""
                {
                  "branches": [
                    {
                      "branches": [
                        {
                          "branches": [
                            {
                              "category": "product_version_range",
                              "name": "vers:all/*",
                              "product": {
                                "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)",
                                "product_id": "1",
                                "product_identification_helper": { "model_numbers": ["7KN1110-0MC00"] }
                              }
                            }
                          ],
                          "category": "product_name",
                          "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)"
                        },
                        {
                          "branches": [
                            {
                              "category": "product_version_range",
                              "name": "vers:all/*",
                              "product": {
                                "name": "SENTRON Powercenter 1100 (7KN1111-0MC00)",
                                "product_id": "2"
                              }
                            }
                          ],
                          "category": "product_name",
                          "name": "SENTRON Powercenter 1100 (7KN1111-0MC00)"
                        }
                      ],
                      "category": "vendor",
                      "name": "Siemens"
                    }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        assertThat(result.productsByCanonicalId()).hasSize(2);
        ResolvedProduct p1 = result.productsByCanonicalId().get("1");
        assertThat(p1.componentName()).isEqualTo("SENTRON Powercenter 1000 (7KN1110-0MC00)");
        assertThat(p1.componentVersion()).isEqualTo("vers:all/*");
        assertThat(p1.platformName()).isNull();
        ResolvedProduct p2 = result.productsByCanonicalId().get("2");
        assertThat(p2.componentName()).isEqualTo("SENTRON Powercenter 1100 (7KN1111-0MC00)");
        assertThat(result.productIdRemap()).containsEntry("1", "1").containsEntry("2", "2");
    }

    @Test
    void fallsBackToTheAncestorProductNameBranchWhenNoPurlIsPresentSiemensRegression() throws Exception {
        // Phase 2 go/no-go review item 2 — explicit regression proof, not just "existing tests still
        // pass": same real SSA-620799 shape as the test above, asserted to take the SAME fallback
        // path (ancestor product_name branch lookup) it always did, byte for byte, now that purl
        // parsing exists as an alternative path this document simply never triggers (no purl
        // anywhere in this — or any real Siemens — product_identification_helper, confirmed live).
        JsonNode productTree = json("""
                {
                  "branches": [
                    { "branches": [
                        { "branches": [
                            { "category": "product_version_range", "name": "vers:all/*",
                              "product": { "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)", "product_id": "1",
                                "product_identification_helper": { "model_numbers": ["7KN1110-0MC00"] } } }
                          ], "category": "product_name", "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)" }
                      ], "category": "vendor", "name": "Siemens" }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        ResolvedProduct product = result.productsByCanonicalId().get("1");
        // componentName came from the ANCESTOR product_name branch, not the leaf's own product.name
        // (identical in this case, but resolved via the fallback's ancestor-walk, not a purl).
        assertThat(product.componentName()).isEqualTo("SENTRON Powercenter 1000 (7KN1110-0MC00)");
        assertThat(product.componentVersion()).isEqualTo("vers:all/*");
        assertThat(product.purl()).isNull();
        // rawLeafName (new field, item 2) is populated regardless of whether a purl exists.
        assertThat(product.rawLeafName()).isEqualTo("SENTRON Powercenter 1000 (7KN1110-0MC00)");
    }

    @Test
    void resolvesAProductVersionRangeBranchName() throws Exception {
        // Real product_tree fragment from SSA-779699 (Mendix) — a "< V8.18.13" range name, a
        // shape distinct from the "vers:" scheme used elsewhere in the same corpus.
        JsonNode productTree = json("""
                {
                  "branches": [
                    {
                      "name": "Siemens",
                      "category": "vendor",
                      "branches": [
                        {
                          "name": "Mendix Applications using Mendix 8",
                          "category": "product_name",
                          "branches": [
                            {
                              "name": "< V8.18.13",
                              "category": "product_version_range",
                              "product": { "product_id": "1", "name": "Mendix Applications using Mendix 8" }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        ResolvedProduct product = result.productsByCanonicalId().get("1");
        assertThat(product.componentName()).isEqualTo("Mendix Applications using Mendix 8");
        assertThat(product.componentVersion()).isEqualTo("< V8.18.13");
    }

    @Test
    void resolvesARelationshipsComponentOfPlatformCombination() throws Exception {
        // Hand-built per the CSAF 2.0 spec's own relationships[] shape (no real Siemens example
        // exists — see the class javadoc) — "openssl" as a default_component_of "RHEL 9".
        JsonNode productTree = json("""
                {
                  "branches": [
                    {
                      "category": "vendor",
                      "name": "Example Vendor",
                      "branches": [
                        {
                          "category": "product_name",
                          "name": "openssl",
                          "branches": [
                            {
                              "category": "product_version",
                              "name": "1.1.1k",
                              "product": { "product_id": "CSAFPID-openssl-1.1.1k", "name": "openssl 1.1.1k" }
                            }
                          ]
                        },
                        {
                          "category": "product_name",
                          "name": "Example Enterprise Linux 9",
                          "branches": [
                            {
                              "category": "product_version",
                              "name": "9",
                              "product": { "product_id": "CSAFPID-eel-9", "name": "Example Enterprise Linux 9" }
                            }
                          ]
                        }
                      ]
                    }
                  ],
                  "relationships": [
                    {
                      "category": "default_component_of",
                      "product_reference": "CSAFPID-openssl-1.1.1k",
                      "relates_to_product_reference": "CSAFPID-eel-9",
                      "full_product_name": {
                        "product_id": "CSAFPID-eel-9-openssl-1.1.1k",
                        "name": "openssl 1.1.1k as a component of Example Enterprise Linux 9"
                      }
                    }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        ResolvedProduct combo = result.productsByCanonicalId().get("CSAFPID-eel-9-openssl-1.1.1k");
        assertThat(combo).isNotNull();
        assertThat(combo.componentName()).isEqualTo("openssl");
        assertThat(combo.componentVersion()).isEqualTo("1.1.1k");
        assertThat(combo.platformName()).isEqualTo("Example Enterprise Linux 9");
        // The two plain (non-combination) products are still resolved on their own.
        assertThat(result.productsByCanonicalId()).containsKeys("CSAFPID-openssl-1.1.1k", "CSAFPID-eel-9");
    }

    // --- Phase 2 go/no-go review items 2/3: real Red Hat product_tree fragments, captured live
    // 2026-08-27 from the real csaf_advisories_2026-08-25.tar.zst archive, RHSA-2003:315 (quagga).
    // Trimmed to 3 of its real leaves (quagga i386, quagga x86_64, quagga-debuginfo i386) and their
    // real relationships[] entries to "Red Hat Enterprise Linux AS version 3" (product_id "3AS") —
    // every remaining field is verbatim, not hand-simplified.

    private static final String QUAGGA_TREE_NO_RELATIONSHIPS = """
            {
              "branches": [
                {
                  "branches": [
                    { "branches": [
                        { "category": "product_name", "name": "Red Hat Enterprise Linux AS version 3",
                          "product": { "name": "Red Hat Enterprise Linux AS version 3", "product_id": "3AS",
                            "product_identification_helper": { "cpe": "cpe:/o:redhat:enterprise_linux:3::as" } } }
                      ], "category": "product_family", "name": "Red Hat Enterprise Linux" },
                    { "branches": [
                        { "category": "product_version", "name": "quagga-0:0.96.2-8.3E.x86_64",
                          "product": { "name": "quagga-0:0.96.2-8.3E.x86_64", "product_id": "quagga-0:0.96.2-8.3E.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=x86_64" } } }
                      ], "category": "architecture", "name": "x86_64" },
                    { "branches": [
                        { "category": "product_version", "name": "quagga-debuginfo-0:0.96.2-8.3E.i386",
                          "product": { "name": "quagga-debuginfo-0:0.96.2-8.3E.i386", "product_id": "quagga-debuginfo-0:0.96.2-8.3E.i386",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga-debuginfo@0.96.2-8.3E?arch=i386" } } },
                        { "category": "product_version", "name": "quagga-0:0.96.2-8.3E.i386",
                          "product": { "name": "quagga-0:0.96.2-8.3E.i386", "product_id": "quagga-0:0.96.2-8.3E.i386",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=i386" } } }
                      ], "category": "architecture", "name": "i386" }
                  ],
                  "category": "vendor", "name": "Red Hat"
                }
              ]
            }
            """;

    private static final String QUAGGA_TREE_WITH_RELATIONSHIPS = """
            {
              "branches": [
                {
                  "branches": [
                    { "branches": [
                        { "category": "product_name", "name": "Red Hat Enterprise Linux AS version 3",
                          "product": { "name": "Red Hat Enterprise Linux AS version 3", "product_id": "3AS",
                            "product_identification_helper": { "cpe": "cpe:/o:redhat:enterprise_linux:3::as" } } }
                      ], "category": "product_family", "name": "Red Hat Enterprise Linux" },
                    { "branches": [
                        { "category": "product_version", "name": "quagga-0:0.96.2-8.3E.x86_64",
                          "product": { "name": "quagga-0:0.96.2-8.3E.x86_64", "product_id": "quagga-0:0.96.2-8.3E.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=x86_64" } } }
                      ], "category": "architecture", "name": "x86_64" },
                    { "branches": [
                        { "category": "product_version", "name": "quagga-debuginfo-0:0.96.2-8.3E.i386",
                          "product": { "name": "quagga-debuginfo-0:0.96.2-8.3E.i386", "product_id": "quagga-debuginfo-0:0.96.2-8.3E.i386",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga-debuginfo@0.96.2-8.3E?arch=i386" } } },
                        { "category": "product_version", "name": "quagga-0:0.96.2-8.3E.i386",
                          "product": { "name": "quagga-0:0.96.2-8.3E.i386", "product_id": "quagga-0:0.96.2-8.3E.i386",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=i386" } } }
                      ], "category": "architecture", "name": "i386" }
                  ],
                  "category": "vendor", "name": "Red Hat"
                }
              ],
              "relationships": [
                { "category": "default_component_of",
                  "full_product_name": { "name": "quagga-0:0.96.2-8.3E.i386 as a component of Red Hat Enterprise Linux AS version 3",
                    "product_id": "3AS:quagga-0:0.96.2-8.3E.i386" },
                  "product_reference": "quagga-0:0.96.2-8.3E.i386", "relates_to_product_reference": "3AS" },
                { "category": "default_component_of",
                  "full_product_name": { "name": "quagga-0:0.96.2-8.3E.x86_64 as a component of Red Hat Enterprise Linux AS version 3",
                    "product_id": "3AS:quagga-0:0.96.2-8.3E.x86_64" },
                  "product_reference": "quagga-0:0.96.2-8.3E.x86_64", "relates_to_product_reference": "3AS" },
                { "category": "default_component_of",
                  "full_product_name": { "name": "quagga-debuginfo-0:0.96.2-8.3E.i386 as a component of Red Hat Enterprise Linux AS version 3",
                    "product_id": "3AS:quagga-debuginfo-0:0.96.2-8.3E.i386" },
                  "product_reference": "quagga-debuginfo-0:0.96.2-8.3E.i386", "relates_to_product_reference": "3AS" }
              ]
            }
            """;

    @Test
    void derivesComponentNameAndVersionFromAPurlInsteadOfTheRawNevraLeafName() throws Exception {
        // Phase 2 go/no-go review item 2 (CRITICAL): without this fix, componentName would be the
        // raw leaf "quagga-0:0.96.2-8.3E.x86_64" (no product_name ancestor exists in a Red Hat
        // product_tree) — measured similarity('openssl', 'openssl-1:...x86_64') = 0.258 for the
        // analogous real case, below this app's 0.35 threshold. With the fix, componentName is the
        // clean purl-derived "quagga" instead.
        WalkResult result = walker.walk(json(QUAGGA_TREE_NO_RELATIONSHIPS));

        ResolvedProduct product = result.productsByCanonicalId().get("quagga-0:0.96.2-8.3E.x86_64");
        assertThat(product).isNotNull();
        assertThat(product.componentName()).isEqualTo("quagga");
        assertThat(product.componentVersion()).isEqualTo("0.96.2-8.3E");
        // The raw NEVRA name is preserved separately for debugging/display, never used for matching.
        assertThat(product.rawLeafName()).isEqualTo("quagga-0:0.96.2-8.3E.x86_64");
        assertThat(product.purl()).isEqualTo("pkg:rpm/redhat/quagga@0.96.2-8.3E?arch=x86_64");
    }

    @Test
    void dropsDebuginfoProductsEntirely() throws Exception {
        // Phase 2 go/no-go review item 3 — real RPM packages Red Hat ships CSAF data for but that
        // never appear in a customer's actual install/CSV (~32% of Red Hat's raw product rows).
        WalkResult result = walker.walk(json(QUAGGA_TREE_NO_RELATIONSHIPS));

        assertThat(result.productsByCanonicalId()).doesNotContainKey("quagga-debuginfo-0:0.96.2-8.3E.i386");
        assertThat(result.productIdRemap()).doesNotContainKey("quagga-debuginfo-0:0.96.2-8.3E.i386");
        // The non-debug sibling under the same architecture branch is unaffected.
        assertThat(result.productIdRemap()).containsKey("quagga-0:0.96.2-8.3E.i386");
    }

    @Test
    void foldsRealArchitectureVariantsIntoOneRowBecausePurlDerivedVersionNeverIncludesTheArchQualifier() throws Exception {
        // Phase 2 go/no-go review item 3 — x86_64 and i386 are distinct raw product_ids AND distinct
        // raw leaf names (NEVRA embeds arch), so the OLD naive naming would never fold them (measured
        // 1.01x reduction on real Red Hat data). Once purl-derived (name, version) drops the arch
        // qualifier entirely (it lives only in the purl's "?arch=..." part, never the version
        // segment), the existing (name, version, platform) fold key folds them with no extra logic.
        WalkResult result = walker.walk(json(QUAGGA_TREE_NO_RELATIONSHIPS));

        // "3AS" (the platform's own product_name leaf) resolves as a product in its own right, plus
        // exactly one row for quagga (2 arch variants, folded to 1) — quagga-debuginfo was dropped
        // entirely, so 2 total, not 3.
        assertThat(result.productsByCanonicalId()).hasSize(2);
        ResolvedProduct product = result.productsByCanonicalId().get("quagga-0:0.96.2-8.3E.x86_64");
        assertThat(product).isNotNull();
        assertThat(product.componentName()).isEqualTo("quagga");
        assertThat(product.componentVersion()).isEqualTo("0.96.2-8.3E");
        assertThat(result.productIdRemap())
                .containsKey("quagga-0:0.96.2-8.3E.x86_64")
                .containsKey("quagga-0:0.96.2-8.3E.i386");
        assertThat(result.productIdRemap().get("quagga-0:0.96.2-8.3E.x86_64"))
                .isEqualTo(result.productIdRemap().get("quagga-0:0.96.2-8.3E.i386"));
    }

    @Test
    void resolvesARealRedHatComponentOfPlatformRelationshipWithPurlDerivedNamingAndDebuginfoSkip() throws Exception {
        // Combines all three Phase 2 fixes against one real document shape: relationships[]
        // resolution (Phase 1), purl-derived naming (item 2), and debuginfo drop (item 3) —
        // including the debuginfo relationship's synthesized id, which must resolve to nothing
        // (its component was already dropped at the branches[] level) rather than error out.
        WalkResult result = walker.walk(json(QUAGGA_TREE_WITH_RELATIONSHIPS));

        // Both arch variants, now WITH a platform, still fold to one canonical combination row —
        // the platform is identical for both ("Red Hat Enterprise Linux AS version 3"), so adding it
        // to the fold key doesn't reopen the arch-variant duplication the naming fix just closed.
        long comboRows = result.productsByCanonicalId().values().stream()
                .filter(p -> "Red Hat Enterprise Linux AS version 3".equals(p.platformName()))
                .count();
        assertThat(comboRows).isEqualTo(1);
        ResolvedProduct combo = result.productsByCanonicalId().values().stream()
                .filter(p -> "Red Hat Enterprise Linux AS version 3".equals(p.platformName()))
                .findFirst().orElseThrow();
        assertThat(combo.componentName()).isEqualTo("quagga");
        assertThat(combo.componentVersion()).isEqualTo("0.96.2-8.3E");

        // The debuginfo relationship's synthesized id never resolves to a row at all — its component
        // reference was dropped at the branches[] level, so resolveRelationships treats it as any
        // other dangling reference (logged, not an error).
        assertThat(result.productIdRemap()).doesNotContainKey("3AS:quagga-debuginfo-0:0.96.2-8.3E.i386");
    }

    // --- Senior review REVISE item 9 (2026-08-27): infix debuginfo/debugsource matching -------------

    @Test
    void dropsADebugPackageThatHasAnArchitectureSuffixAfterTheDebugMarker() throws Exception {
        // Real leak case measured live: 22,509 rows (1.3% of the real corpus) — a suffix-only check
        // (endsWith("-debuginfo")) misses this because the name doesn't END in "-debuginfo", it has
        // "-common-x86_64" tacked on afterward.
        JsonNode productTree = json("""
                {
                  "branches": [
                    { "category": "product_version", "name": "kernel-debuginfo-common-x86_64-0:1.0-1.el9",
                      "product": { "product_id": "P1", "name": "kernel-debuginfo-common-x86_64-0:1.0-1.el9" } }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        assertThat(result.productsByCanonicalId()).isEmpty();
        assertThat(result.productIdRemap()).doesNotContainKey("P1");
    }

    @Test
    void doesNotDropTheRealPackageElfutilsDebuginfodClientDespiteContainingTheSubstringDebuginfo() throws Exception {
        // elfutils-debuginfod-client is a real, legitimate package (the elfutils debuginfod client
        // tool) — its substring is "debuginfod-" (note the trailing "d"), never "debuginfo-", so the
        // infix fix must not treat it as a debug package. A naive "contains debuginfo anywhere" fix
        // would have wrongly dropped this (6 real rows, per the senior review's measurement).
        JsonNode productTree = json("""
                {
                  "branches": [
                    { "category": "product_version", "name": "elfutils-debuginfod-client-0:0.190-1.el9",
                      "product": { "product_id": "P2", "name": "elfutils-debuginfod-client-0:0.190-1.el9" } }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        assertThat(result.productsByCanonicalId()).containsKey("P2");
        assertThat(result.productIdRemap()).containsKey("P2");
    }

    @Test
    void foldsProductsThatShareTheSameComponentNameVersionAndPlatformIntoOneCanonicalRow() throws Exception {
        // Two architecture-only variants (x86_64/aarch64) of the exact same component+version,
        // both with no platform — should collapse into a single csaf_products row (plan §3's
        // volume-control decision), with both original ids remapped to the first-seen canonical one.
        JsonNode productTree = json("""
                {
                  "branches": [
                    {
                      "category": "product_name",
                      "name": "widget",
                      "branches": [
                        {
                          "category": "architecture",
                          "name": "x86_64",
                          "branches": [
                            {
                              "category": "product_version",
                              "name": "1.0",
                              "product": { "product_id": "P-X86", "name": "widget 1.0 x86_64" }
                            }
                          ]
                        },
                        {
                          "category": "architecture",
                          "name": "aarch64",
                          "branches": [
                            {
                              "category": "product_version",
                              "name": "1.0",
                              "product": { "product_id": "P-ARM", "name": "widget 1.0 aarch64" }
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }
                """);

        WalkResult result = walker.walk(productTree);

        assertThat(result.productsByCanonicalId()).hasSize(1);
        assertThat(result.productIdRemap()).containsEntry("P-X86", "P-X86").containsEntry("P-ARM", "P-X86");
    }
}
