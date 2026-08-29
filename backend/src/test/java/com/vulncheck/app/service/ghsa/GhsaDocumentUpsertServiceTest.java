package com.vulncheck.app.service.ghsa;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.GhsaAdvisory;
import com.vulncheck.app.repository.GhsaAdvisoryRepository;
import com.vulncheck.app.repository.GhsaAffectedPackageRepository;
import com.vulncheck.app.repository.GhsaAffectedRangeRepository;
import com.vulncheck.app.repository.GhsaAffectedVersionRepository;
import java.time.OffsetDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Every fixture below is a REAL GHSA-reviewed advisory captured live 2026-08-27 (trimmed to the
 * fields this test needs — full documents run several KB each) — same policy as {@code
 * CveOrgVulnerabilitySourceTest}/{@code CsafDocumentUpsertServiceTest} (real products, real released
 * versions). Both baseline (tarball) and delta (raw.githubusercontent.com) ingestion paths hand this
 * service the identical OSV-schema shape (plan §3-1 decision A), so one set of fixtures covers both.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class GhsaDocumentUpsertServiceTest {

    @Autowired
    private GhsaAdvisoryRepository ghsaAdvisoryRepository;
    @Autowired
    private GhsaAffectedPackageRepository ghsaAffectedPackageRepository;
    @Autowired
    private GhsaAffectedRangeRepository ghsaAffectedRangeRepository;
    @Autowired
    private GhsaAffectedVersionRepository ghsaAffectedVersionRepository;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private GhsaDocumentUpsertService service() {
        return new GhsaDocumentUpsertService(
                ghsaAdvisoryRepository, ghsaAffectedPackageRepository, ghsaAffectedRangeRepository, ghsaAffectedVersionRepository);
    }

    /** Real: ImageMagick memory leak, NuGet, single "fixed" event range, CVE alias present. */
    private static final String GHSA_WFX3 = """
            {
              "id": "GHSA-wfx3-6g53-9fgc",
              "modified": "2026-08-26T20:48:48Z",
              "published": "2026-02-25T19:13:32Z",
              "aliases": ["CVE-2026-56368"],
              "summary": "ImageMagick: Memory Leak in multiple coders that write raw pixel data",
              "details": "A memory leak vulnerability exists in multiple coders that write raw pixel data.",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"}],
              "affected": [
                {
                  "package": {"ecosystem": "NuGet", "name": "Magick.NET-Q16-AnyCPU"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "14.10.3"}]}]
                }
              ],
              "database_specific": {"severity": "MODERATE"}
            }
            """;

    /** Real: Django GDALRaster over-read, PyPI, TWO separate affected[] entries for the SAME package
     *  (5.2.x branch and 6.0.x branch) — the multi-range/disjoint-version case (plan §8 item 6/item
     *  4 of the checklist this implementation guards against): OR-across-ranges, not AND. */
    private static final String GHSA_CRHF = """
            {
              "id": "GHSA-crhf-3pfg-w68w",
              "modified": "2026-08-07T20:01:06Z",
              "published": "2026-07-07T15:32:57Z",
              "aliases": ["CVE-2026-53877"],
              "summary": "Django: GDALRaster may over-read heap memory when constructed from bytes",
              "details": "GDALRaster over-reads its in-memory buffer when constructed from a bytes object.",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:L"}],
              "affected": [
                {
                  "package": {"ecosystem": "PyPI", "name": "django"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.2.16"}]}]
                },
                {
                  "package": {"ecosystem": "PyPI", "name": "django"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "6.0.0"}, {"fixed": "6.0.7"}]}]
                }
              ],
              "database_specific": {"severity": "MODERATE"}
            }
            """;

    /** Real: withdrawn advisory (duplicate of GHSA-ppx3-28rw-8fpf), PyPI, "last_affected" event
     *  (inclusive upper bound) rather than "fixed". */
    private static final String GHSA_VG9F_WITHDRAWN = """
            {
              "id": "GHSA-vg9f-q4xh-62r4",
              "modified": "2026-08-25T18:09:14Z",
              "published": "2026-06-15T03:30:32Z",
              "withdrawn": "2026-08-25T18:09:14Z",
              "aliases": [],
              "summary": "Duplicate Advisory: utcp-gql SSRF",
              "details": "This advisory has been withdrawn because it is a duplicate of GHSA-ppx3-28rw-8fpf.",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"}],
              "affected": [
                {
                  "package": {"ecosystem": "PyPI", "name": "utcp-gql"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.1.0"}]}]
                }
              ],
              "database_specific": {"severity": "MODERATE"}
            }
            """;

    /** Real: openwisp-ipam broken object-level authorization — no CVE assigned at all (empty
     *  aliases), exercising the GHSA-ID-only path. */
    private static final String GHSA_X287_NO_CVE = """
            {
              "id": "GHSA-x287-5c68-36wp",
              "modified": "2026-08-26T14:38:10Z",
              "published": "2026-08-26T14:38:10Z",
              "aliases": [],
              "summary": "OpenWISP IPAM has broken object-level authorization in ExportSubnetView",
              "details": "ExportSubnetView omits the organization-membership check its import sibling performs.",
              "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N"}],
              "affected": [
                {
                  "package": {"ecosystem": "PyPI", "name": "openwisp-ipam"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.1"}]}]
                }
              ],
              "database_specific": {"severity": "MODERATE"}
            }
            """;

    /** NOT a live capture (github-reviewed advisories were found, empirically, to essentially never
     *  populate {@code affected[].versions[]} independently of ranges — every sampled real document
     *  during this implementation used ranges only) — a minimal, schema-valid synthetic fixture so
     *  the exact-version-enumeration path (plan §3/§8 item 6(v)) still has coverage. Values are
     *  arbitrary, not tied to a real advisory. */
    private static final String SYNTHETIC_EXACT_VERSIONS = """
            {
              "id": "GHSA-test-exac-tver",
              "modified": "2026-01-01T00:00:00Z",
              "published": "2026-01-01T00:00:00Z",
              "aliases": ["CVE-2026-00099"],
              "summary": "Synthetic fixture for exact-version-list matching",
              "affected": [
                {
                  "package": {"ecosystem": "npm", "name": "example-pkg"},
                  "versions": ["1.2.3", "1.2.4", "1.2.5"]
                }
              ],
              "database_specific": {"severity": "LOW"}
            }
            """;

    @Test
    void upsertsAdvisorySummaryFieldsAndASingleFixedEventRange() throws Exception {
        String ghsaId = service().upsertGhsaAdvisory(objectMapper.readTree(GHSA_WFX3));

        assertThat(ghsaId).isEqualTo("GHSA-wfx3-6g53-9fgc");
        GhsaAdvisory advisory = ghsaAdvisoryRepository.findById("GHSA-wfx3-6g53-9fgc").orElseThrow();
        assertThat(advisory.getCveId()).isEqualTo("CVE-2026-56368");
        assertThat(advisory.getSeverity()).isEqualTo("MODERATE");
        assertThat(advisory.getWithdrawnAt()).isNull();
        assertThat(advisory.getHtmlUrl()).isEqualTo("https://github.com/advisories/GHSA-wfx3-6g53-9fgc");
        assertThat(advisory.getUpdatedAt()).isEqualTo(OffsetDateTime.parse("2026-08-26T20:48:48Z"));

        List<java.util.Map<String, Object>> ranges = jdbcTemplate.queryForList("""
                SELECT ar.range_type, ar.introduced_version, ar.fixed_version, ar.last_affected_version
                FROM ghsa_affected_ranges ar
                JOIN ghsa_affected_packages ap ON ap.id = ar.affected_package_id
                WHERE ap.ghsa_id = 'GHSA-wfx3-6g53-9fgc'
                """);
        assertThat(ranges).hasSize(1);
        assertThat(ranges.get(0)).containsEntry("range_type", "ECOSYSTEM")
                .containsEntry("introduced_version", null) // OSV's introduced:"0" normalizes to NULL
                .containsEntry("fixed_version", "14.10.3")
                .containsEntry("last_affected_version", null);
    }

    @Test
    void mergesTwoAffectedEntriesForTheSamePackageIntoOnePackageRowWithTwoDisjointRanges() throws Exception {
        service().upsertGhsaAdvisory(objectMapper.readTree(GHSA_CRHF));

        List<java.util.Map<String, Object>> packageRows = jdbcTemplate.queryForList(
                "SELECT id FROM ghsa_affected_packages WHERE ghsa_id = 'GHSA-crhf-3pfg-w68w' AND ecosystem = 'pypi'");
        // The UNIQUE (ghsa_id, ecosystem, package_name_normalized) constraint means two affected[]
        // entries for the same "django" package must collapse to exactly one row, not two.
        assertThat(packageRows).hasSize(1);

        List<java.util.Map<String, Object>> ranges = jdbcTemplate.queryForList("""
                SELECT fixed_version, introduced_version FROM ghsa_affected_ranges
                WHERE affected_package_id = ?
                ORDER BY fixed_version
                """, packageRows.get(0).get("id"));
        assertThat(ranges).hasSize(2);
        assertThat(ranges.get(0)).containsEntry("fixed_version", "5.2.16").containsEntry("introduced_version", null);
        assertThat(ranges.get(1)).containsEntry("fixed_version", "6.0.7").containsEntry("introduced_version", "6.0.0");
    }

    @Test
    void withdrawnAdvisoryIsUpsertedWithLastAffectedRangeAndWithdrawnAtSet() throws Exception {
        service().upsertGhsaAdvisory(objectMapper.readTree(GHSA_VG9F_WITHDRAWN));

        GhsaAdvisory advisory = ghsaAdvisoryRepository.findById("GHSA-vg9f-q4xh-62r4").orElseThrow();
        assertThat(advisory.getWithdrawnAt()).isEqualTo(OffsetDateTime.parse("2026-08-25T18:09:14Z"));

        List<java.util.Map<String, Object>> ranges = jdbcTemplate.queryForList("""
                SELECT ar.fixed_version, ar.last_affected_version FROM ghsa_affected_ranges ar
                JOIN ghsa_affected_packages ap ON ap.id = ar.affected_package_id
                WHERE ap.ghsa_id = 'GHSA-vg9f-q4xh-62r4'
                """);
        assertThat(ranges).hasSize(1);
        assertThat(ranges.get(0)).containsEntry("fixed_version", null).containsEntry("last_affected_version", "1.1.0");
    }

    @Test
    void anAdvisoryWithNoCveAliasIsUpsertedWithANullCveId() throws Exception {
        service().upsertGhsaAdvisory(objectMapper.readTree(GHSA_X287_NO_CVE));

        GhsaAdvisory advisory = ghsaAdvisoryRepository.findById("GHSA-x287-5c68-36wp").orElseThrow();
        assertThat(advisory.getCveId()).isNull();
    }

    @Test
    void reUpsertingTheSameAdvisoryReplacesChildRowsRatherThanDuplicatingThem() throws Exception {
        GhsaDocumentUpsertService service = service();
        service.upsertGhsaAdvisory(objectMapper.readTree(GHSA_CRHF));
        service.upsertGhsaAdvisory(objectMapper.readTree(GHSA_CRHF)); // simulates baseline+delta both syncing it

        Long packageCount = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM ghsa_affected_packages WHERE ghsa_id = 'GHSA-crhf-3pfg-w68w'", Long.class);
        Long rangeCount = jdbcTemplate.queryForObject("""
                SELECT COUNT(*) FROM ghsa_affected_ranges ar
                JOIN ghsa_affected_packages ap ON ap.id = ar.affected_package_id
                WHERE ap.ghsa_id = 'GHSA-crhf-3pfg-w68w'
                """, Long.class);
        assertThat(packageCount).isEqualTo(1);
        assertThat(rangeCount).isEqualTo(2);
    }

    @Test
    void exactVersionEnumerationIsStoredIndependentlyOfRanges() throws Exception {
        service().upsertGhsaAdvisory(objectMapper.readTree(SYNTHETIC_EXACT_VERSIONS));

        List<String> versions = jdbcTemplate.queryForList("""
                SELECT av.version FROM ghsa_affected_versions av
                JOIN ghsa_affected_packages ap ON ap.id = av.affected_package_id
                WHERE ap.ghsa_id = 'GHSA-test-exac-tver'
                ORDER BY av.version
                """, String.class);
        assertThat(versions).containsExactly("1.2.3", "1.2.4", "1.2.5");

        Long rangeCount = jdbcTemplate.queryForObject("""
                SELECT COUNT(*) FROM ghsa_affected_ranges ar
                JOIN ghsa_affected_packages ap ON ap.id = ar.affected_package_id
                WHERE ap.ghsa_id = 'GHSA-test-exac-tver'
                """, Long.class);
        assertThat(rangeCount).isZero();
    }

    @Test
    void returnsNullAndUpsertsNothingWhenTheDocumentHasNoId() throws Exception {
        String malformed = """
                { "modified": "2026-01-01T00:00:00Z", "summary": "no id field" }
                """;
        String result = service().upsertGhsaAdvisory(objectMapper.readTree(malformed));

        assertThat(result).isNull();
        assertThat(ghsaAdvisoryRepository.count()).isZero();
    }
}
