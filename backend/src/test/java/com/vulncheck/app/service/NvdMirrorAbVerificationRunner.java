package com.vulncheck.app.service;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.vuln.NvdVulnerabilitySource;
import com.vulncheck.app.service.vuln.SourceResult;
import com.vulncheck.app.service.vuln.VersionUtils;
import com.vulncheck.app.service.vuln.VulnFinding;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

/**
 * Closed-mode backlog item 202's Phase 3b mandatory A/B gate (docs/spec/closed-mode-plan.md
 * §4-2-6): for every {@code golden-300.csv} row with {@code expected_outcome=IDENTIFIED_CPE},
 * runs the real {@link Stage1IdentificationService} to get the exact fully-qualified CPE the app
 * would build (same as {@link NvdVulnerabilitySource#find}), then queries that CPE two ways —
 * (a) the live NVD CVE API ({@link NvdVulnerabilitySource#fetchFromNvdCached}, unkeyed pacing via
 * {@code NvdRateLimiter}, 6.5s/request) and (b) a from-scratch local CPE-applicability query
 * against the {@code nvd_cve_records}/{@code nvd_cve_cpe_match} mirror tables (this class's own
 * {@link #mirrorLookup}, since no production mirror-backed {@code NvdVulnerabilitySource} rewrite
 * exists yet — that rewrite is explicitly out of scope here, see the gate's own wording) — and
 * diffs the two CVE-id sets per row.
 *
 * <p>{@link #mirrorLookup}'s applicability logic is a deliberately independent reimplementation,
 * not shared with {@code NvdCveSyncService}/{@code CpeUtils} beyond the escape-aware CPE-segment
 * parsing this class necessarily duplicates (that method is private on {@link CpeUtils}) — same
 * "don't have the thing under test lean on the code that produced its own input" rationale
 * {@code test-data/verify_nvd_cpe_candidates.py}'s class javadoc cites for not writing back the
 * app's own output as ground truth.
 *
 * <p><b>Known modeling gap, not fixed by this class</b>: {@code nvd_cve_cpe_match} (V39) stores one
 * flattened row per {@code cpeMatch} entry with no node id or AND/OR operator — so a CVE whose real
 * NVD applicability requires two CPEs to <em>both</em> be present (e.g. a specific OS AND a specific
 * app together) cannot be told apart, from this table alone, from an ordinary single-CPE OR match.
 * {@link #mirrorLookup} treats every matching row as independently sufficient (OR semantics only),
 * which is the only thing the current schema supports — see this run's own diff findings for whether
 * that gap actually manifested against golden-300's IDENTIFIED_CPE rows in practice.
 *
 * <p>Uses the same {@code @Transactional} rollback trick as {@link ChocolateyRemovalGolden300RecallTest}
 * (job creation joins this test method's own transaction and is rolled back at the end, never
 * durably written) and the same real-dev-DB {@code @TestPropertySource} as every other class in
 * this package. Disabled by default; re-enable by hand, run once, restore {@code @Disabled}.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Run twice (2026-09-03, closed-mode backlog item 202 Phase 3b gate) against the real dev "
        + "DB. Round 1 (naive '-'-version handling, treating a CPE 2.3 '-' version segment the same "
        + "as '*'): 39/65 rows matched, 26 mismatched. Round 2 (fixed versionApplies to fail-closed "
        + "on '-' -- see that method's own javadoc): 43/65 matched (66%), 22 mismatched -- confirms "
        + "the round-1 '-' handling alone was responsible for 4 of the 26 (Cisco IOS XE, Skype, "
        + "McAfee Total Protection, and the misidentified 'Microsoft Visual Studio' row all cleared). "
        + "GATE NOT PASSED: of the 22 remaining mismatches, ~20% (37/188 liveOnly CVE ids checked) "
        + "trace to a genuine mirror data-freshness gap (the CVE exists in nvd_cve_records but its "
        + "cpeMatch/configurations enrichment hadn't landed yet as of this DB's snapshot -- NVD tags "
        + "a CVE's CPE applicability days-to-weeks after publication, and no delta sync currently "
        + "runs to catch up -- self-explanatory, acceptable). The dominant remaining cause (~80%) is "
        + "NOT freshness and NOT fixable within this schema: nvd_cve_cpe_match (V39) stores one flat "
        + "row per cpeMatch with no node/config-group id, so a CVE whose real NVD applicability is "
        + "expressed via a cross-vendor AND-node (confirmed concretely for CVE-2021-43803/"
        + "CVE-2022-36046 on vercel:next.js paired with a nodejs:node.js vulnerable=false exclusion "
        + "condition; CVE-2025-7233 and siblings on cadsofttools:cadimage/irfanview:flashpix_plugin "
        + "paired with an irfanview:irfanview exclusion; CVE-2007-5274 on sun:jdk paired with a "
        + "mozilla:firefox exclusion) cannot be reproduced by any from-scratch per-(vendor,product) "
        + "flat-table query, this class's own mirrorLookup included -- resolving this needs a schema "
        + "change (node/operator/negate columns) before any cutover, which is out of this task's "
        + "scope. Separately (production bug, not part of the mirror, found only because this A/B "
        + "check surfaced it): NvdVulnerabilitySource#fetchFromNvd's resultsPerPage=200 has no "
        + "startIndex pagination loop, so live results are silently truncated for any CPE whose true "
        + "NVD match count exceeds 200 (confirmed exactly at live=200 for Firefox/Chrome/GitLab) --  "
        + "worth its own backlog item, unrelated to this gate's pass/fail. Left disabled so it can "
        + "never re-fire on a routine mvn test run -- see class javadoc.")
class NvdMirrorAbVerificationRunner {

    private static final Long REAL_USER_ID = 5L;
    /** Deliberately not a real user id (no {@code user_secrets} row can exist for it) — forces
     *  {@link com.vulncheck.app.service.UserApiKeyService#getNvdApiKey} to return empty so every
     *  live call here goes through {@code NvdRateLimiter}'s unkeyed 6.5s/request pacing, exactly as
     *  the task brief for this gate requires, regardless of what key (if any) is registered against
     *  {@link #REAL_USER_ID} at the time this happens to run. */
    private static final Long UNKEYED_USER_ID = -1L;

    @Autowired
    private ResearchJobService researchJobService;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private Stage1IdentificationService stage1IdentificationService;
    @Autowired
    private NvdVulnerabilitySource nvdVulnerabilitySource;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    private record GoldenCpeRow(String rawProductName, String version, String cpeName) {
    }

    @Test
    @Transactional
    void compareLiveAndMirrorForEveryIdentifiedCpeGoldenRow() throws Exception {
        ResearchJob job;
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv")) {
            job = researchJobService.createJob(
                    REAL_USER_ID, "golden-300-nvd-mirror-ab.csv", csv, ColumnMapping.identity(), false);
        }
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(job.getId());

        Set<String> identifiedCpeKeys = loadIdentifiedCpeKeys();
        System.out.println("\n=== golden-300.csv IDENTIFIED_CPE rows: " + identifiedCpeKeys.size() + " ===");

        List<GoldenCpeRow> rows = new ArrayList<>();
        for (ResearchJobItem item : items) {
            if (!identifiedCpeKeys.contains(key(item.getRawProductName(), item.getVersion()))) {
                continue;
            }
            Optional<IdentifiedProduct> identified = stage1IdentificationService.identify(item, REAL_USER_ID);
            if (identified.isEmpty() || identified.get().getCpe() == null) {
                System.out.println("SKIP (Stage1 did not produce a CPE for this row): "
                        + item.getRawProductName() + " " + item.getVersion());
                continue;
            }
            String sourceCpe = identified.get().getCpe();
            CpeUtils.VendorProduct vendorProduct = CpeUtils.parseVendorProduct(sourceCpe);
            String part = CpeUtils.parsePart(sourceCpe);
            String cpeName = CpeUtils.buildCpe(part, vendorProduct.vendor(), vendorProduct.product(), item.getVersion());
            rows.add(new GoldenCpeRow(item.getRawProductName(), item.getVersion(), cpeName));
        }
        System.out.println("=== rows with a real Stage1-produced CPE to A/B: " + rows.size() + " ===\n");

        int matched = 0;
        List<String> mismatchReports = new ArrayList<>();
        for (GoldenCpeRow row : rows) {
            SourceResult liveResult = nvdVulnerabilitySource.fetchFromNvdCached(row.cpeName(), UNKEYED_USER_ID);
            if (!liveResult.succeeded()) {
                mismatchReports.add(row.rawProductName() + " " + row.version() + " [" + row.cpeName()
                        + "]: LIVE QUERY FAILED (network/rate-limit error, see log above) -- not counted as "
                        + "matched or mismatched, treat as inconclusive");
                continue;
            }
            Set<String> liveIds = extractIds(liveResult.findings());
            Set<String> mirrorIds = mirrorLookup(row.cpeName());

            if (liveIds.equals(mirrorIds)) {
                matched++;
                continue;
            }
            Set<String> liveOnly = new TreeSet<>(liveIds);
            liveOnly.removeAll(mirrorIds);
            Set<String> mirrorOnly = new TreeSet<>(mirrorIds);
            mirrorOnly.removeAll(liveIds);

            StringBuilder report = new StringBuilder();
            report.append(row.rawProductName()).append(' ').append(row.version())
                    .append(" [").append(row.cpeName()).append("]\n")
                    .append("    live=").append(liveIds.size()).append(" mirror=").append(mirrorIds.size())
                    .append(" liveOnly=").append(liveOnly).append(" mirrorOnly=").append(mirrorOnly).append('\n');
            for (String cveId : liveOnly) {
                report.append("    liveOnly ").append(cveId).append(": ").append(explainLiveOnly(cveId)).append('\n');
            }
            for (String cveId : mirrorOnly) {
                report.append("    mirrorOnly ").append(cveId).append(": ")
                        .append(explainMirrorOnly(cveId, row.cpeName())).append('\n');
            }
            mismatchReports.add(report.toString());
        }

        System.out.println("\n=== closed-mode backlog item 202 Phase 3b A/B gate result ===");
        System.out.println("total rows compared: " + rows.size());
        System.out.println("matched (identical CVE-id set): " + matched);
        System.out.println("mismatched: " + mismatchReports.size());
        for (String report : mismatchReports) {
            System.out.println("--- MISMATCH ---");
            System.out.println(report);
        }
    }

    /** Looks up every CVE id in {@code nvd_cve_cpe_match} whose (part, vendor, product) matches
     *  {@code cpeName} and whose version-applicability (own OR semantics only, see class javadoc)
     *  covers {@code cpeName}'s own version segment. */
    private Set<String> mirrorLookup(String cpeName) {
        List<String> segments = splitCpeSegments(cpeName);
        String part = segments.get(2);
        String vendor = segments.get(3);
        String product = segments.get(4);
        String itemVersion = segments.get(5);

        List<Map<String, Object>> matchRows = jdbcTemplate.queryForList(
                "SELECT cve_id, criteria, vulnerable, version_start_including, version_start_excluding, "
                        + "version_end_including, version_end_excluding FROM nvd_cve_cpe_match "
                        + "WHERE part = ? AND vendor = ? AND product = ?",
                part, vendor, product);

        Set<String> ids = new TreeSet<>();
        for (Map<String, Object> matchRow : matchRows) {
            if (!Boolean.TRUE.equals(matchRow.get("vulnerable"))) {
                continue;
            }
            if (versionApplies(matchRow, itemVersion)) {
                ids.add((String) matchRow.get("cve_id"));
            }
        }
        return ids;
    }

    /** One {@code cpeMatch} row's applicability against {@code itemVersion} — mirrors NVD's own
     *  documented semantics: if the match's own {@code criteria} carries a concrete (non-{@code *})
     *  version segment, that's an exact-version match with no range fields to consult; a {@code *}
     *  version defers to the four {@code version_*} bound columns (all-null means unconditionally
     *  vulnerable at every version).
     *
     *  <p>REVISE (this run, after the first pass showed every one of Cisco IOS XE's 41 mirror-only
     *  false positives sharing the same {@code criteria} shape): a {@code -} version segment is
     *  CPE 2.3's own "not applicable" marker, not a synonym for {@code *} ("any version") — the
     *  first version of this method wrongly lumped the two together, so a version-less platform
     *  entry like {@code cpe:2.3:o:cisco:ios_xe:-:*:*:*:*:*:*:*} (all four range columns null, since
     *  there is no range to describe for a field that doesn't apply) fell into the "unconditionally
     *  vulnerable at every version" branch and matched every golden-300 row's version indiscriminately.
     *  Real NVD applicability data uses {@code -} on one node of a multi-CPE AND config (e.g. paired
     *  with a real version-bounded companion entry) — exactly the node-grouping this flat table
     *  can't represent (see class javadoc) — so the only safe, fail-closed treatment here is to never
     *  match on a bare {@code -}, not to guess at the paired condition this schema has no column for. */
    private boolean versionApplies(Map<String, Object> matchRow, String itemVersion) {
        String criteria = (String) matchRow.get("criteria");
        List<String> segments = splitCpeSegments(criteria);
        String criteriaVersion = segments.size() > 5 ? segments.get(5) : "*";

        if ("-".equals(criteriaVersion)) {
            return false;
        }
        if (!"*".equals(criteriaVersion)) {
            return criteriaVersion.equalsIgnoreCase(itemVersion);
        }

        String startIncluding = (String) matchRow.get("version_start_including");
        String startExcluding = (String) matchRow.get("version_start_excluding");
        String endIncluding = (String) matchRow.get("version_end_including");
        String endExcluding = (String) matchRow.get("version_end_excluding");

        if (startIncluding != null && VersionUtils.compare(itemVersion, startIncluding) < 0) {
            return false;
        }
        if (startExcluding != null && VersionUtils.compare(itemVersion, startExcluding) <= 0) {
            return false;
        }
        if (endIncluding != null && VersionUtils.compare(itemVersion, endIncluding) > 0) {
            return false;
        }
        if (endExcluding != null && VersionUtils.compare(itemVersion, endExcluding) >= 0) {
            return false;
        }
        return true;
    }

    /** For a CVE id only the live query returned: whether {@code nvd_cve_records} even has it at
     *  all (a genuine mirror data gap -- freshness or an incomplete backfill) versus whether it's
     *  present but this class's {@link #mirrorLookup} just didn't match it (an applicability-logic
     *  difference worth root-causing). */
    private String explainLiveOnly(String cveId) {
        List<Map<String, Object>> record = jdbcTemplate.queryForList(
                "SELECT last_modified_at, published_at FROM nvd_cve_records WHERE cve_id = ?", cveId);
        if (record.isEmpty()) {
            return "not present in nvd_cve_records at all -- mirror data gap (never synced, or CVE "
                    + "created/modified after this DB's backfill snapshot)";
        }
        List<Map<String, Object>> matchRows = jdbcTemplate.queryForList(
                "SELECT part, vendor, product, criteria, vulnerable, version_start_including, "
                        + "version_start_excluding, version_end_including, version_end_excluding "
                        + "FROM nvd_cve_cpe_match WHERE cve_id = ?", cveId);
        return "present in nvd_cve_records (last_modified_at=" + record.get(0).get("last_modified_at")
                + ") but not matched by mirrorLookup -- its own cpe_match rows: " + matchRows;
    }

    /** For a CVE id only the mirror query returned: dumps the exact {@code cpe_match} row(s) that
     *  made {@link #mirrorLookup} include it, for a human to judge whether that's a genuine
     *  applicability-logic bug (e.g. an AND-node condition this flattened table can't represent --
     *  see class javadoc) or a live-side data-freshness difference (NVD's own record has since
     *  changed since this DB's snapshot). */
    private String explainMirrorOnly(String cveId, String cpeName) {
        List<String> segments = splitCpeSegments(cpeName);
        List<Map<String, Object>> matchRows = jdbcTemplate.queryForList(
                "SELECT criteria, vulnerable, version_start_including, version_start_excluding, "
                        + "version_end_including, version_end_excluding FROM nvd_cve_cpe_match "
                        + "WHERE cve_id = ? AND part = ? AND vendor = ? AND product = ?",
                cveId, segments.get(2), segments.get(3), segments.get(4));
        return "matched via " + matchRows;
    }

    private Set<String> extractIds(List<VulnFinding> findings) {
        Set<String> ids = new HashSet<>();
        for (VulnFinding finding : findings) {
            ids.add(finding.cveOrGhsaId());
        }
        return ids;
    }

    /** Escape-aware CPE 2.3 segment split -- a deliberate duplicate of {@code CpeUtils}'s own
     *  private {@code splitCpeSegments} (see class javadoc: this test intentionally doesn't lean on
     *  more of the app's own CPE-handling code than the bare minimum needed to interpret a CPE
     *  string it already has in hand). */
    private static List<String> splitCpeSegments(String cpeString) {
        List<String> segments = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < cpeString.length(); i++) {
            char c = cpeString.charAt(i);
            if (c == '\\' && i + 1 < cpeString.length()) {
                current.append(c).append(cpeString.charAt(i + 1));
                i++;
            } else if (c == ':') {
                segments.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        segments.add(current.toString());
        return segments;
    }

    private Set<String> loadIdentifiedCpeKeys() throws Exception {
        Set<String> keys = new HashSet<>();
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("golden-300.csv");
                CSVParser parser = CSVParser.parse(new InputStreamReader(csv, StandardCharsets.UTF_8),
                        CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true).build())) {
            for (CSVRecord record : parser) {
                if ("IDENTIFIED_CPE".equals(record.get("expected_outcome"))) {
                    keys.add(key(record.get("product_name"), record.get("version")));
                }
            }
        }
        return keys;
    }

    private static String key(String productName, String version) {
        return productName + " " + version;
    }
}
