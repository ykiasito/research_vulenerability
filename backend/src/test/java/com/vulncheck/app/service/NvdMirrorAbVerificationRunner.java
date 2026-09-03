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
import java.time.OffsetDateTime;
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
@Disabled("Round 3 (2026-09-03, closed-mode backlog item 202 Phase 3b gate) NOT YET RUN: the "
        + "mirrorLookup vulnerable=false fix, the NvdVulnerabilitySource#fetchFromNvd startIndex "
        + "pagination fix, and this class's own mirrorOnly/liveOnly gate-classification rewrite are "
        + "all in place (see this class's and NvdVulnerabilitySource's own javadoc for what changed "
        + "and why), but re-running this gate against the real dev DB requires a docker run with the "
        + "real POSTGRES_PASSWORD plus live network calls to nvd.nist.gov -- the auto-mode command "
        + "classifier blocked that invocation for this agent (2026-09-03), so round 3's actual numbers "
        + "are pending a run by an agent/session with that permission. Round 1 (naive '-'-version "
        + "handling, treating a CPE 2.3 '-' version segment the same as '*'): 39/65 rows matched, 26 "
        + "mismatched. Round 2 (fixed versionApplies to fail-closed on '-'): 43/65 matched (66%), 22 "
        + "mismatched, GATE NOT PASSED -- see git history for round 2's full mismatch breakdown (superseded "
        + "by the harness fix in this same file, so round 2's mirrorOnly/liveOnly split specifically is "
        + "stale and should not be quoted going forward). Left disabled so it can never re-fire on a "
        + "routine mvn test run -- see class javadoc.")
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

        // Backfill-completion timestamp, used by classifyLiveOnly's FRESHNESS_STALE bucket (item 4:
        // "last_modified_at older than backfill completion" as a freshness signal). Empty when the
        // baseline backfill itself hasn't finished -- in that case only the FRESHNESS_MISSING bucket
        // (CVE absent from nvd_cve_records altogether) is available as a freshness explanation.
        Optional<OffsetDateTime> backfillCompletedAt = loadBackfillCompletedAt();
        System.out.println("=== backfill completed at: "
                + backfillCompletedAt.map(Object::toString).orElse("(baseline not yet complete)") + " ===\n");

        int matched = 0;
        int totalMirrorOnly = 0;
        int totalLiveOnly = 0;
        int freshnessExplained = 0;
        int dashFailClosedOnly = 0;
        int unexplained = 0;
        List<String> mismatchReports = new ArrayList<>();
        // (row, live findings count) for every successfully-queried row -- item 3's raw material for
        // proposing a display cap (top-N by CVSS + "他M件"): what's the actual distribution of
        // per-row live finding counts across golden-300's IDENTIFIED_CPE rows.
        List<Map.Entry<String, Integer>> liveCountsByRow = new ArrayList<>();

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
            liveCountsByRow.add(Map.entry(row.rawProductName() + " " + row.version(), liveIds.size()));
            System.out.println("row: " + row.rawProductName() + " " + row.version() + " [" + row.cpeName()
                    + "] live=" + liveIds.size() + " mirror=" + mirrorIds.size());

            if (liveIds.equals(mirrorIds)) {
                matched++;
                continue;
            }
            Set<String> liveOnly = new TreeSet<>(liveIds);
            liveOnly.removeAll(mirrorIds);
            Set<String> mirrorOnly = new TreeSet<>(mirrorIds);
            mirrorOnly.removeAll(liveIds);
            totalMirrorOnly += mirrorOnly.size();
            totalLiveOnly += liveOnly.size();

            StringBuilder report = new StringBuilder();
            report.append(row.rawProductName()).append(' ').append(row.version())
                    .append(" [").append(row.cpeName()).append("]\n")
                    .append("    live=").append(liveIds.size()).append(" mirror=").append(mirrorIds.size())
                    .append(" liveOnly=").append(liveOnly).append(" mirrorOnly=").append(mirrorOnly).append('\n');
            for (String cveId : liveOnly) {
                LiveOnlyExplanation explanation = classifyLiveOnly(cveId, row.cpeName(), backfillCompletedAt.orElse(null));
                switch (explanation.cause()) {
                    case FRESHNESS_MISSING, FRESHNESS_STALE -> freshnessExplained++;
                    case DASH_FAIL_CLOSED -> dashFailClosedOnly++;
                    case UNEXPLAINED -> unexplained++;
                }
                report.append("    liveOnly ").append(cveId).append(" [").append(explanation.cause()).append("]: ")
                        .append(explanation.detail()).append('\n');
            }
            for (String cveId : mirrorOnly) {
                report.append("    mirrorOnly ").append(cveId).append(": ")
                        .append(explainMirrorOnly(cveId, row.cpeName())).append('\n');
            }
            mismatchReports.add(report.toString());
        }

        liveCountsByRow.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        int totalLiveFindings = liveCountsByRow.stream().mapToInt(Map.Entry::getValue).sum();
        System.out.println("\n=== per-row live finding count distribution (item 3, for the display-cap "
                + "proposal) ===");
        System.out.println("rows compared: " + liveCountsByRow.size() + ", total live findings summed: "
                + totalLiveFindings + ", average: "
                + (liveCountsByRow.isEmpty() ? 0.0 : (double) totalLiveFindings / liveCountsByRow.size()));
        System.out.println("top 10 rows by live finding count:");
        liveCountsByRow.stream().limit(10)
                .forEach(entry -> System.out.println("    " + entry.getKey() + ": " + entry.getValue()));

        // Gate criterion (item 4): mirrorOnly must be zero (removing the vulnerable=true filter
        // should already drive false positives to zero -- any survivor here is a genuine
        // mirrorLookup/versionApplies bug, not a known limitation) and every liveOnly CVE must be
        // explained by data freshness. dashFailClosedOnly is reported as its own independent bucket
        // per item 4's second requirement, but is NOT counted as "explained" -- it is the known,
        // schema-limited AND-node/versionApplies('-') gap this task's scope explicitly excludes
        // fixing (would need V39's node/operator columns), so it still fails the gate on its own.
        boolean gatePassed = totalMirrorOnly == 0 && unexplained == 0 && dashFailClosedOnly == 0;

        System.out.println("\n=== closed-mode backlog item 202 Phase 3b A/B gate result ===");
        System.out.println("total rows compared: " + rows.size());
        System.out.println("matched (identical CVE-id set): " + matched);
        System.out.println("mismatched: " + mismatchReports.size());
        System.out.println("totalMirrorOnly (false positives, must be 0 to pass): " + totalMirrorOnly);
        System.out.println("totalLiveOnly (mirror-missing CVEs): " + totalLiveOnly);
        System.out.println("  of which freshness-explained (missing from nvd_cve_records, or stale "
                + "last_modified_at): " + freshnessExplained);
        System.out.println("  of which versionApplies '-' fail-closed only (known AND-node schema gap, "
                + "reported separately, does NOT count as explained): " + dashFailClosedOnly);
        System.out.println("  of which unexplained (neither freshness nor the '-' rule): " + unexplained);
        System.out.println("GATE " + (gatePassed ? "PASSED" : "NOT PASSED"));
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

        // No vulnerable=true filter here (removed 2026-09-03, closed-mode backlog item 202 Phase 3b
        // re-run): live NVD's cpeName search doesn't take an isVulnerable parameter, so it returns
        // every CVE that names this CPE in ANY node of its configuration, including vulnerable=false
        // "environment" nodes (e.g. an AND-node pairing a vulnerable component with a non-vulnerable
        // platform/runtime it ships alongside) -- confirmed live for cpe:2.3:a:nodejs:node.js:16.0.0
        // returning CVE-2021-43803/CVE-2022-36046, where node.js itself is the vulnerable:false side
        // of the match. The earlier vulnerable=true-only filter here made mirrorLookup diverge from
        // what live actually returns, which was mischaracterized as a mirror data gap rather than a
        // harness bug against its own A/B baseline.
        Set<String> ids = new TreeSet<>();
        for (Map<String, Object> matchRow : matchRows) {
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

    /** Why a live-only CVE (returned by the live NVD query, not by {@link #mirrorLookup}) diverges
     *  -- see the gate's own pass/fail wording in {@link
     *  #compareLiveAndMirrorForEveryIdentifiedCpeGoldenRow} for how each cause is (or isn't) treated
     *  as "explained". */
    private enum LiveOnlyCause {
        /** {@code nvd_cve_records} has no row for this CVE at all -- never synced, or created/modified
         *  after this DB's backfill snapshot. A freshness gap. */
        FRESHNESS_MISSING,
        /** {@code nvd_cve_records} has a row, but its {@code last_modified_at} predates the baseline
         *  backfill's own completion timestamp -- this CVE's CPE-applicability enrichment plausibly
         *  hadn't landed by the time the backfill snapshot was taken (NVD tags a CVE's CPE
         *  applicability days-to-weeks after publication; no delta sync currently runs to catch up).
         *  A freshness gap. */
        FRESHNESS_STALE,
        /** {@code nvd_cve_records} has a fresh row, and this class found a {@code cpe_match} row for
         *  this CVE/part/vendor/product whose {@code criteria} carries a bare {@code -} version
         *  segment -- {@link #versionApplies}'s deliberate fail-closed treatment (see its own javadoc)
         *  is exactly why {@link #mirrorLookup} didn't match it. This is the known, schema-limited
         *  AND-node gap ({@code nvd_cve_cpe_match} has no node/operator columns to represent a real
         *  NVD applicability condition spanning two paired CPEs) -- NOT fixable within this task's
         *  scope, and NOT counted as "freshness-explained" for gate purposes, but broken out as its
         *  own bucket so its share of the remaining gap is visible. */
        DASH_FAIL_CLOSED,
        /** Neither of the above -- a genuine unexplained applicability-logic difference worth
         *  root-causing on its own, not a known/accepted gap. */
        UNEXPLAINED
    }

    private record LiveOnlyExplanation(LiveOnlyCause cause, String detail) {
    }

    /** Classifies one live-only CVE id per {@link LiveOnlyCause}. Freshness (missing or stale) is
     *  checked first and takes priority over the '-' fail-closed bucket even if both would apply --
     *  a CVE that's simply not fresh yet doesn't need the schema-gap explanation to be accounted for. */
    private LiveOnlyExplanation classifyLiveOnly(String cveId, String cpeName, OffsetDateTime backfillCompletedAt) {
        List<Map<String, Object>> recordRows = jdbcTemplate.queryForList(
                "SELECT last_modified_at FROM nvd_cve_records WHERE cve_id = ?", cveId);
        if (recordRows.isEmpty()) {
            return new LiveOnlyExplanation(LiveOnlyCause.FRESHNESS_MISSING,
                    "not present in nvd_cve_records at all -- mirror data gap (never synced, or CVE "
                            + "created/modified after this DB's backfill snapshot)");
        }
        if (backfillCompletedAt != null) {
            Boolean stale = jdbcTemplate.queryForObject(
                    "SELECT last_modified_at < ? FROM nvd_cve_records WHERE cve_id = ?",
                    Boolean.class, backfillCompletedAt, cveId);
            if (Boolean.TRUE.equals(stale)) {
                return new LiveOnlyExplanation(LiveOnlyCause.FRESHNESS_STALE,
                        "present in nvd_cve_records but last_modified_at predates backfill completion ("
                                + backfillCompletedAt + ") -- CPE-applicability enrichment for this CVE "
                                + "likely hadn't landed by then");
            }
        }

        List<String> segments = splitCpeSegments(cpeName);
        List<Map<String, Object>> matchRows = jdbcTemplate.queryForList(
                "SELECT criteria, vulnerable, version_start_including, version_start_excluding, "
                        + "version_end_including, version_end_excluding FROM nvd_cve_cpe_match "
                        + "WHERE cve_id = ? AND part = ? AND vendor = ? AND product = ?",
                cveId, segments.get(2), segments.get(3), segments.get(4));
        for (Map<String, Object> matchRow : matchRows) {
            List<String> criteriaSegments = splitCpeSegments((String) matchRow.get("criteria"));
            String criteriaVersion = criteriaSegments.size() > 5 ? criteriaSegments.get(5) : "*";
            if ("-".equals(criteriaVersion)) {
                return new LiveOnlyExplanation(LiveOnlyCause.DASH_FAIL_CLOSED,
                        "present and fresh, but its own cpe_match row (" + matchRow.get("criteria")
                                + ") carries a bare '-' version segment that versionApplies fail-closes "
                                + "on -- see versionApplies javadoc, needs a V39 schema change (node/operator "
                                + "columns) to fix properly, out of this task's scope");
            }
        }
        return new LiveOnlyExplanation(LiveOnlyCause.UNEXPLAINED,
                "present in nvd_cve_records (fresh), not matched by mirrorLookup -- its own cpe_match "
                        + "rows for this part/vendor/product: " + matchRows);
    }

    /** Baseline backfill's own completion timestamp ({@code nvd_cve_sync_state.updated_at} at the
     *  point {@code baseline_completed} first flipped true), used as the freshness cutoff for {@link
     *  #classifyLiveOnly}'s {@code FRESHNESS_STALE} bucket. Empty if the baseline hasn't completed at
     *  all yet. Note: {@code updated_at} is also touched by delta-sync ticks (see {@link
     *  com.vulncheck.app.service.NvdCveSyncService#runDeltaTick}), so this is only an exact proxy for
     *  "backfill completion" as long as no delta sync has run since -- true as of this gate's own run
     *  (delta sync isn't currently scheduled, see the disabled-test javadoc), but worth re-checking if
     *  that ever changes. */
    private Optional<OffsetDateTime> loadBackfillCompletedAt() {
        List<Boolean> completedRows = jdbcTemplate.queryForList(
                "SELECT baseline_completed FROM nvd_cve_sync_state WHERE id = 1", Boolean.class);
        if (completedRows.isEmpty() || !Boolean.TRUE.equals(completedRows.get(0))) {
            return Optional.empty();
        }
        return Optional.ofNullable(jdbcTemplate.queryForObject(
                "SELECT updated_at FROM nvd_cve_sync_state WHERE id = 1", OffsetDateTime.class));
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
