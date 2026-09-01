package com.vulncheck.app.service.csaf;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.CsafAdvisory;
import com.vulncheck.app.entity.CsafProduct;
import com.vulncheck.app.entity.CsafProductStatus;
import com.vulncheck.app.repository.CsafAdvisoryRepository;
import com.vulncheck.app.repository.CsafProductRepository;
import com.vulncheck.app.repository.CsafProductStatusRepository;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.transaction.annotation.Transactional;

/**
 * Exercises {@link CsafDocumentUpsertService} against a real Postgres instance (native
 * ON-CONFLICT/DELETE-then-INSERT SQL, same rationale as {@code VulnerabilityRepositoryTest}).
 * Fixtures are the real SSA-779699 (multi-CVE) and SSA-620799 (known_not_affected) CSAF documents,
 * captured live from {@code https://cert-portal.siemens.com/productcert/csaf/} on 2026-08-27 —
 * boilerplate {@code document.notes} entries (legal disclaimer, general recommendations) are
 * trimmed for readability since {@link CsafDocumentUpsertService} never reads them, but every
 * field it DOES read (tracking, product_tree, vulnerabilities, product_status, remediations,
 * scores) is verbatim.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CsafDocumentUpsertServiceTest {

    @Autowired
    private CsafAdvisoryRepository csafAdvisoryRepository;

    @Autowired
    private CsafProductRepository csafProductRepository;

    @Autowired
    private CsafProductStatusRepository csafProductStatusRepository;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private CsafDocumentUpsertService service() {
        return new CsafDocumentUpsertService(
                csafAdvisoryRepository, csafProductRepository, csafProductStatusRepository, new CsafProductTreeWalker());
    }

    private static final String SSA_779699 = """
            {
              "document": {
                "title": "SSA-779699: Two Incorrect Authorization Vulnerabilities in Mendix",
                "tracking": {
                  "id": "SSA-779699",
                  "status": "final",
                  "version": "1",
                  "initial_release_date": "2021-11-09T00:00:00Z",
                  "current_release_date": "2021-11-09T00:00:00Z"
                },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": {
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
                      },
                      {
                        "name": "Mendix Applications using Mendix 9",
                        "category": "product_name",
                        "branches": [
                          {
                            "name": "< V9.6.2",
                            "category": "product_version_range",
                            "product": { "product_id": "2", "name": "Mendix Applications using Mendix 9" }
                          }
                        ]
                      }
                    ]
                  }
                ]
              },
              "vulnerabilities": [
                {
                  "cve": "CVE-2021-42025",
                  "product_status": { "known_affected": ["1", "2"] },
                  "scores": [
                    { "cvss_v3": { "baseScore": 5.3, "baseSeverity": "MEDIUM" }, "products": ["1", "2"] }
                  ],
                  "remediations": [
                    { "product_ids": ["1"], "category": "vendor_fix",
                      "details": "Update to V8.18.13 or later version and redeploy your application",
                      "url": "https://docs.mendix.com/releasenotes/studio-pro/8" },
                    { "product_ids": ["2"], "category": "vendor_fix",
                      "details": "Update to V9.6.2 or V9.7.0 or later version and redeploy your application",
                      "url": "https://docs.mendix.com/releasenotes/studio-pro/9" },
                    { "product_ids": ["1", "2"], "category": "workaround",
                      "details": "avoid using file documents that contain sensitive information" }
                  ]
                },
                {
                  "cve": "CVE-2021-42026",
                  "product_status": { "known_affected": ["1", "2"] },
                  "scores": [
                    { "cvss_v3": { "baseScore": 3.1, "baseSeverity": "LOW" }, "products": ["1", "2"] }
                  ],
                  "remediations": [
                    { "product_ids": ["1"], "category": "vendor_fix",
                      "details": "Update to V8.18.13 or later version and redeploy your application",
                      "url": "https://docs.mendix.com/releasenotes/studio-pro/8" },
                    { "product_ids": ["2"], "category": "vendor_fix",
                      "details": "Update to V9.6.2 or V9.7.0 or later version and redeploy your application",
                      "url": "https://docs.mendix.com/releasenotes/studio-pro/9" }
                  ]
                }
              ]
            }
            """;

    private static final String SSA_620799 = """
            {
              "document": {
                "title": "SSA-620799: Denial of Service Vulnerability During BLE Pairing in SENTRON Powercenter 1000/1100",
                "tracking": {
                  "id": "SSA-620799",
                  "status": "final",
                  "version": "2",
                  "initial_release_date": "2024-12-10T00:00:00Z",
                  "current_release_date": "2025-06-10T00:00:00Z"
                },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": {
                "branches": [
                  {
                    "branches": [
                      {
                        "branches": [
                          {
                            "category": "product_version_range",
                            "name": "vers:all/*",
                            "product": { "name": "SENTRON Powercenter 1000 (7KN1110-0MC00)", "product_id": "1" }
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
                            "product": { "name": "SENTRON Powercenter 1100 (7KN1111-0MC00)", "product_id": "2" }
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
              },
              "vulnerabilities": [
                {
                  "cve": "CVE-2024-6657",
                  "product_status": { "known_not_affected": ["1", "2"] }
                }
              ]
            }
            """;

    private JsonNode parse(String text) throws Exception {
        return objectMapper.readTree(text);
    }

    @Test
    void upsertsAMultiCveAdvisoryWithIndependentPerCveProductStatusRows() throws Exception {
        String trackingId = service().upsertCsafDocument("siemens", parse(SSA_779699));

        assertThat(trackingId).isEqualTo("SSA-779699");

        CsafAdvisory advisory = csafAdvisoryRepository.findById(new com.vulncheck.app.entity.CsafAdvisoryId("siemens", "SSA-779699"))
                .orElseThrow();
        assertThat(advisory.getTrackingStatus()).isEqualTo("final");
        assertThat(advisory.getTitle()).contains("Mendix");
        // Worst-case CVSS across both bundled CVEs (5.3 > 3.1).
        assertThat(advisory.getCvssScore().doubleValue()).isEqualTo(5.3);
        assertThat(advisory.getCvssSeverity()).isEqualTo("MEDIUM");

        List<CsafProduct> products = csafProductRepository.findByVendorAndAdvisoryId("siemens", "SSA-779699");
        assertThat(products).hasSize(2);
        assertThat(products).extracting(CsafProduct::getComponentName)
                .containsExactlyInAnyOrder("Mendix Applications using Mendix 8", "Mendix Applications using Mendix 9");

        // The core §3 schema point: (vulnerability x product), not (advisory x product) — 2 CVEs x
        // 2 products = 4 independent status rows, not 2.
        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-779699".equals(s.getAdvisoryId()))
                .toList();
        assertThat(statuses).hasSize(4);
        assertThat(statuses).extracting(CsafProductStatus::getCveId)
                .containsExactlyInAnyOrder("CVE-2021-42025", "CVE-2021-42025", "CVE-2021-42026", "CVE-2021-42026");
        assertThat(statuses).allMatch(s -> "known_affected".equals(s.getStatus()));

        // Vendor-native remediation text lands on fixed_version/remediation_url — not a parsed
        // semver — for the product it applies to.
        CsafProductStatus mendix8ForCve25 = statuses.stream()
                .filter(s -> s.getCveId().equals("CVE-2021-42025") && "1".equals(s.getCsafProductId()))
                .findFirst().orElseThrow();
        assertThat(mendix8ForCve25.getFixedVersion()).isEqualTo("Update to V8.18.13 or later version and redeploy your application");
        assertThat(mendix8ForCve25.getRemediationUrl()).isEqualTo("https://docs.mendix.com/releasenotes/studio-pro/8");
    }

    @Test
    void upsertsAKnownNotAffectedEntry() throws Exception {
        service().upsertCsafDocument("siemens", parse(SSA_620799));

        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-620799".equals(s.getAdvisoryId()))
                .toList();
        assertThat(statuses).hasSize(2);
        assertThat(statuses).allMatch(s -> "known_not_affected".equals(s.getStatus()));
        assertThat(statuses).allMatch(s -> "CVE-2024-6657".equals(s.getCveId()));
    }

    // REVISE item 6 (senior review 2026-08-27): two original product_ids that fold to the SAME
    // canonical product (identical component_name/component_version/platform_name — same shape as
    // CsafProductTreeWalker's architecture-variant folding) must not produce two identical
    // (cve, canonical product, status) rows when the advisory lists both original ids under the same
    // product_status/CVE.
    private static final String SSA_FOLDED_DUPLICATE = """
            {
              "document": {
                "title": "SSA-FOLDED-TEST: test-only fixture for folded-product-id dedup",
                "tracking": { "id": "SSA-FOLDED-TEST", "status": "final", "version": "1",
                  "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "name": "Siemens", "category": "vendor", "branches": [
                { "name": "Widget Gadget", "category": "product_name", "branches": [
                  { "name": "1.0", "category": "product_version",
                    "product": { "product_id": "widget-x86", "name": "Widget Gadget 1.0 (x86)" } },
                  { "name": "1.0", "category": "product_version",
                    "product": { "product_id": "widget-arm", "name": "Widget Gadget 1.0 (arm)" } }
                ] }
              ] } ] },
              "vulnerabilities": [
                { "cve": "CVE-2026-00002",
                  "product_status": { "known_affected": ["widget-x86", "widget-arm"] } }
              ]
            }
            """;

    @Test
    void foldedProductIdsListedTogetherUnderTheSameStatusProduceOnlyOneRow() throws Exception {
        service().upsertCsafDocument("siemens", parse(SSA_FOLDED_DUPLICATE));

        // Both original ids resolve to the same (component_name="Widget Gadget", version="1.0",
        // platform=null) tuple, so they fold to one csaf_products row...
        List<CsafProduct> products = csafProductRepository.findByVendorAndAdvisoryId("siemens", "SSA-FOLDED-TEST");
        assertThat(products).hasSize(1);

        // ...and must therefore produce exactly one status row, not two identical ones.
        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-FOLDED-TEST".equals(s.getAdvisoryId()))
                .toList();
        assertThat(statuses).hasSize(1);
        assertThat(statuses.get(0).getCveId()).isEqualTo("CVE-2026-00002");
        assertThat(statuses.get(0).getStatus()).isEqualTo("known_affected");
    }

    // REVISE item 3 (senior review 2026-08-27): a resolved canonical product NEVER referenced by any
    // product_status entry must not be persisted at all (measured live: 46.6% of real csaf_products
    // rows were unreferenced, wasting slots in CsafVulnerabilitySource's LIMIT-30 candidate window).
    private static final String SSA_UNREFERENCED_PRODUCT = """
            {
              "document": {
                "title": "SSA-UNREF-TEST: test-only fixture for reference-filtering",
                "tracking": { "id": "SSA-UNREF-TEST", "status": "final", "version": "1",
                  "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "name": "Siemens", "category": "vendor", "branches": [
                { "name": "Widget Gadget", "category": "product_name", "branches": [
                  { "name": "1.0", "category": "product_version",
                    "product": { "product_id": "widget-referenced", "name": "Widget Gadget 1.0" } },
                  { "name": "2.0", "category": "product_version",
                    "product": { "product_id": "widget-unreferenced", "name": "Widget Gadget 2.0" } }
                ] }
              ] } ] },
              "vulnerabilities": [
                { "cve": "CVE-2026-00003",
                  "product_status": { "known_affected": ["widget-referenced"] } }
              ]
            }
            """;

    @Test
    void aResolvedProductNeverReferencedByAnyStatusRowIsNotPersisted() throws Exception {
        service().upsertCsafDocument("siemens", parse(SSA_UNREFERENCED_PRODUCT));

        // widget-unreferenced resolves to a perfectly valid canonical product (CsafProductTreeWalker
        // has no reason to drop it), but no product_status entry anywhere in the document ever
        // mentions it — it must not be persisted.
        List<CsafProduct> products = csafProductRepository.findByVendorAndAdvisoryId("siemens", "SSA-UNREF-TEST");
        assertThat(products).hasSize(1);
        assertThat(products.get(0).getComponentVersion()).isEqualTo("1.0");

        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-UNREF-TEST".equals(s.getAdvisoryId()))
                .toList();
        assertThat(statuses).hasSize(1);
    }

    @Test
    void reSyncingAnAdvisoryReplacesItsProductAndStatusRowsRatherThanDuplicatingThem() throws Exception {
        service().upsertCsafDocument("siemens", parse(SSA_779699));
        service().upsertCsafDocument("siemens", parse(SSA_779699));

        assertThat(csafProductRepository.findByVendorAndAdvisoryId("siemens", "SSA-779699")).hasSize(2);
        long statusCount = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-779699".equals(s.getAdvisoryId()))
                .count();
        assertThat(statusCount).isEqualTo(4);
    }

    // --- Phase 2 (Red Hat) go/no-go review fixtures — real documents captured live 2026-08-27 from
    // the real csaf_advisories_2026-08-25.tar.zst archive, trimmed of boilerplate (notes/references)
    // per this class's own javadoc convention. -------------------------------------------------------

    /** Real RHEA-2014:1175 ("Red Hat Enhancement Advisory: Release of Satellite 6.0"), trimmed to 3
     *  of its real leaves (mongodb src/x86_64, libmongodb x86_64) and their real {@code
     *  default_component_of} relationships to "Red Hat Satellite Capsule 6.0" (product_id {@code
     *  6Server-Capsule60}), and 2 of its real 24 bundled CVEs — chosen specifically because, for
     *  these exact real products, CVE-2012-6619 is genuinely {@code fixed} while CVE-2013-2101 is
     *  genuinely {@code known_not_affected} (confirmed live 2026-08-27 across the full real
     *  25-vulnerability document) — a real, not fabricated, example of §9's required "genuine
     *  per-CVE status matrix" (the same product, different status per CVE). */
    private static final String RHEA_2014_1175 = """
            {
              "document": {
                "title": "Red Hat Enhancement Advisory: Release of Satellite 6.0",
                "tracking": { "id": "RHEA-2014:1175", "status": "final", "version": "2",
                  "initial_release_date": "2014-08-19T00:00:00+00:00", "current_release_date": "2014-08-19T00:00:00+00:00" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": {
                "branches": [ { "branches": [
                    { "category": "product_name", "name": "Red Hat Satellite Capsule 6.0",
                      "product": { "name": "Red Hat Satellite Capsule 6.0", "product_id": "6Server-Capsule60",
                        "product_identification_helper": { "cpe": "cpe:/a:redhat:satellite_capsule:6.0::el6" } } },
                    { "branches": [
                        { "category": "product_version", "name": "mongodb-0:2.4.6-2.el6sat.src",
                          "product": { "name": "mongodb-0:2.4.6-2.el6sat.src", "product_id": "mongodb-0:2.4.6-2.el6sat.src",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/mongodb@2.4.6-2.el6sat?arch=src" } } },
                        { "category": "product_version", "name": "mongodb-0:2.4.6-2.el6sat.x86_64",
                          "product": { "name": "mongodb-0:2.4.6-2.el6sat.x86_64", "product_id": "mongodb-0:2.4.6-2.el6sat.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/mongodb@2.4.6-2.el6sat?arch=x86_64" } } },
                        { "category": "product_version", "name": "libmongodb-0:2.4.6-2.el6sat.x86_64",
                          "product": { "name": "libmongodb-0:2.4.6-2.el6sat.x86_64", "product_id": "libmongodb-0:2.4.6-2.el6sat.x86_64",
                            "product_identification_helper": { "purl": "pkg:rpm/redhat/libmongodb@2.4.6-2.el6sat?arch=x86_64" } } }
                      ], "category": "architecture", "name": "MongoDB" }
                  ], "category": "vendor", "name": "Red Hat" } ],
                "relationships": [
                  { "category": "default_component_of",
                    "full_product_name": { "name": "mongodb-0:2.4.6-2.el6sat.src as a component of Red Hat Satellite Capsule 6.0",
                      "product_id": "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.src" },
                    "product_reference": "mongodb-0:2.4.6-2.el6sat.src", "relates_to_product_reference": "6Server-Capsule60" },
                  { "category": "default_component_of",
                    "full_product_name": { "name": "mongodb-0:2.4.6-2.el6sat.x86_64 as a component of Red Hat Satellite Capsule 6.0",
                      "product_id": "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.x86_64" },
                    "product_reference": "mongodb-0:2.4.6-2.el6sat.x86_64", "relates_to_product_reference": "6Server-Capsule60" },
                  { "category": "default_component_of",
                    "full_product_name": { "name": "libmongodb-0:2.4.6-2.el6sat.x86_64 as a component of Red Hat Satellite Capsule 6.0",
                      "product_id": "6Server-Capsule60:libmongodb-0:2.4.6-2.el6sat.x86_64" },
                    "product_reference": "libmongodb-0:2.4.6-2.el6sat.x86_64", "relates_to_product_reference": "6Server-Capsule60" }
                ]
              },
              "vulnerabilities": [
                { "cve": "CVE-2012-6619",
                  "product_status": { "fixed": [
                      "6Server-Capsule60:libmongodb-0:2.4.6-2.el6sat.x86_64",
                      "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.src",
                      "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.x86_64"
                  ] } },
                { "cve": "CVE-2013-2101",
                  "product_status": { "known_not_affected": [
                      "6Server-Capsule60:libmongodb-0:2.4.6-2.el6sat.x86_64",
                      "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.src",
                      "6Server-Capsule60:mongodb-0:2.4.6-2.el6sat.x86_64"
                  ] } }
              ]
            }
            """;

    @Test
    void upsertsARealRedHatAdvisoryWithGenuinelyDifferentStatusesForTheSameProductAcrossCves() throws Exception {
        String trackingId = service().upsertCsafDocument("redhat", parse(RHEA_2014_1175));

        assertThat(trackingId).isEqualTo("RHEA-2014:1175");

        // purl-derived naming (item 2): component_name is the clean "mongodb"/"libmongodb", never the
        // raw NEVRA leaf name — and the two mongodb arch variants (src, x86_64) fold to one row
        // combined with the platform (item 3), since the purl-derived version never carries arch.
        //
        // Without reference filtering, the walker would resolve 5 distinct canonical rows: the
        // platform's own product_name leaf ("Red Hat Satellite Capsule 6.0" itself, same pattern as
        // "3AS" in CsafProductTreeWalkerTest's real quagga fixture), a "bare" (no-platform) row for
        // each of mongodb/libmongodb, AND a platform-combo row for each of mongodb/libmongodb. Only
        // the two platform-combo rows are ever referenced by a product_status entry below (Red Hat's
        // real product_status always references the relationships[]-synthesized combo id, never the
        // bare component or the bare platform leaf) — senior review REVISE item 3 (2026-08-27) means
        // the 3 unreferenced rows are never persisted at all, leaving exactly 2.
        List<CsafProduct> products = csafProductRepository.findByVendorAndAdvisoryId("redhat", "RHEA-2014:1175");
        assertThat(products).hasSize(2);
        CsafProduct mongodb = products.stream()
                .filter(p -> "mongodb".equals(p.getComponentName()) && "Red Hat Satellite Capsule 6.0".equals(p.getPlatformName()))
                .findFirst().orElseThrow();
        assertThat(mongodb.getComponentVersion()).isEqualTo("2.4.6-2.el6sat");
        assertThat(mongodb.getRawLeafName()).isIn("mongodb-0:2.4.6-2.el6sat.src", "mongodb-0:2.4.6-2.el6sat.x86_64");

        // The core §3/§9 point, with real data: the SAME product genuinely carries a DIFFERENT status
        // depending on which CVE — not just a different product per status.
        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "RHEA-2014:1175".equals(s.getAdvisoryId()))
                .filter(s -> s.getCsafProductId().equals(mongodb.getCsafProductId()))
                .toList();
        assertThat(statuses).hasSize(2);
        assertThat(statuses).extracting(CsafProductStatus::getCveId).containsExactlyInAnyOrder("CVE-2012-6619", "CVE-2013-2101");
        CsafProductStatus fixedRow = statuses.stream().filter(s -> s.getCveId().equals("CVE-2012-6619")).findFirst().orElseThrow();
        CsafProductStatus notAffectedRow = statuses.stream().filter(s -> s.getCveId().equals("CVE-2013-2101")).findFirst().orElseThrow();
        assertThat(fixedRow.getStatus()).isEqualTo("fixed");
        assertThat(notAffectedRow.getStatus()).isEqualTo("known_not_affected");
    }

    // Senior-reviewer REVISE (2026-09-01, PR#79 peer review): a vendor CSAF document's own
    // remediations[].url is just as untrusted as an LLM's citation URL, and reaches the same
    // unescaped th:href sink (CsafVulnerabilitySource#findingUrl -> vulnerabilities.url /
    // job_item_vulnerabilities.citation_url -> jobs/detail.html) once persisted. A disallowed
    // scheme must be dropped to null here at ingestion, same as SafeUrlValidator already does for
    // Stage4/BundledComponent — the free-text remediation details (fixed_version) still persist.
    private static final String SSA_MALICIOUS_REMEDIATION_URL = """
            {
              "document": {
                "title": "SSA-MALICIOUS-TEST: test-only fixture for a hostile remediation url scheme",
                "tracking": { "id": "SSA-MALICIOUS-TEST", "status": "final", "version": "1",
                  "initial_release_date": "2026-01-01T00:00:00Z", "current_release_date": "2026-01-01T00:00:00Z" },
                "distribution": { "tlp": { "label": "WHITE" } }
              },
              "product_tree": { "branches": [ { "name": "Siemens", "category": "vendor", "branches": [
                { "name": "Widget Gadget", "category": "product_name", "branches": [
                  { "name": "1.0", "category": "product_version",
                    "product": { "product_id": "widget-1", "name": "Widget Gadget 1.0" } }
                ] }
              ] } ] },
              "vulnerabilities": [
                { "cve": "CVE-2026-00004",
                  "product_status": { "known_affected": ["widget-1"] },
                  "remediations": [
                    { "product_ids": ["widget-1"], "category": "vendor_fix",
                      "details": "Update to V2.0 or later version",
                      "url": "javascript:alert(document.cookie)" }
                  ]
                }
              ]
            }
            """;

    @Test
    void aRemediationUrlWithADisallowedSchemeIsDroppedRatherThanPersisted() throws Exception {
        service().upsertCsafDocument("siemens", parse(SSA_MALICIOUS_REMEDIATION_URL));

        List<CsafProductStatus> statuses = csafProductStatusRepository.findAll().stream()
                .filter(s -> "SSA-MALICIOUS-TEST".equals(s.getAdvisoryId()))
                .toList();
        assertThat(statuses).hasSize(1);
        // The free-text remediation details still persist — only the URL is dropped.
        assertThat(statuses.get(0).getFixedVersion()).isEqualTo("Update to V2.0 or later version");
        assertThat(statuses.get(0).getRemediationUrl()).isNull();
    }
}
