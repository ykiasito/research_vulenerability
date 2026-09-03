package com.vulncheck.app.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.service.nvd.CpeUtils;
import com.vulncheck.app.service.nvd.NvdRateLimiter;
import com.vulncheck.app.service.vuln.NvdVulnerabilitySource;
import com.vulncheck.app.service.vuln.SourceResult;
import com.vulncheck.app.service.vuln.VersionUtils;
import com.vulncheck.app.service.vuln.VulnFinding;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashMap;
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
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

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
 * <p><b>Round 3 finding, corrected (2026-09-03)</b>: round 3's original text here claimed the
 * remaining {@code liveOnly} gap "wasn't caused by" the AND-node/{@code -} schema gap, based on
 * DASH_FAIL_CLOSED being 0 across all 65 rows. That claim was invalid — round 3's {@link
 * #classifyLiveOnly} judged freshness via a wall-clock backfill-completion-timestamp comparison
 * that a CVE's own (NVD-side) {@code last_modified_at} is, structurally, almost always older than;
 * a senior-reviewer DB measurement confirmed all 385,847 mirrored records satisfied that "stale"
 * condition. Every {@code liveOnly} CVE was therefore absorbed into the freshness bucket before the
 * {@code -} fail-closed check or the unexplained catch-all ever ran, making DASH_FAIL_CLOSED and
 * UNEXPLAINED structurally unreachable rather than genuinely zero. {@link #classifyLiveOnly} now
 * checks {@code nvd_cve_cpe_match} row presence directly instead of a timestamp (see its own
 * javadoc), so both buckets are reachable again — see the {@code @Disabled} reason below for this
 * round's real numeric breakdown. DASH_FAIL_CLOSED/UNEXPLAINED, whatever their value, remain only
 * computed over the {@code liveOnly} CVEs of already-mismatched rows, so a {@code -} segment on a
 * CVE that {@link #mirrorLookup} and the live query already agreed on (or one attached to a {@code
 * mirrorOnly} CVE) is still invisible to those counters.
 *
 * <p><b>Round 4 finding, corrected (round 5, 2026-09-03)</b>: round 4 above left one {@code
 * liveOnly} CVE — CVE-2026-18301, golden-300's GIMP 2.10.38 row — as {@code UNEXPLAINED}, and
 * classified the other 37 as {@code FRESHNESS_STALE} purely on "zero matching {@code
 * nvd_cve_cpe_match} rows", assumed (never checked against NVD's own authoritative data) to mean
 * "not synced yet" — the same unproven-freshness mistake round 3 made in a different shape. A
 * senior-reviewer direct, unauthenticated, non-destructive query of NVD's public {@code ?cveId=}
 * endpoint for CVE-2026-18301 found its authoritative record's own {@code lastModified=2026-09-02}
 * (NVD had just reanalyzed this CVE) carries exactly one {@code gimp:gimp} {@code cpeMatch} — a
 * fixed {@code criteria} version of {@code 3.2.2}, no range fields — which does not cover
 * golden-300's queried {@code 2.10.38} at all. Live's {@code ?cpeName=} search endpoint (queried by
 * {@link NvdVulnerabilitySource#fetchFromNvdCached} above) simply hadn't caught up with that
 * reanalysis yet and returned this CVE anyway: a live-side search-index lag, not a mirror defect.
 * {@link #classifyLiveOnly} now checks this authoritative {@code ?cveId=} data first (see its own
 * javadoc and {@link #fetchAuthoritativeCveData}) for every {@code liveOnly} CVE, splitting what
 * round 4 lumped into one unproven {@code FRESHNESS_STALE} bucket into a proven {@code
 * LIVE_ONLY_FALSE_POSITIVE}/{@code FRESHNESS_MISSING}/{@code FRESHNESS_LAG}/{@code
 * INGEST_GAP_OR_LOGIC_BUG} breakdown instead.
 *
 * <p><b>Round 5 result (2026-09-03)</b>: the fix above unblocked the real run against the dev DB
 * mirror. 64 of golden-300's 65 {@code IDENTIFIED_CPE} rows produced a successful live query (1 --
 * Notepad++ -- excluded as inconclusive, same as round 4); 51/64 matched exactly, {@code
 * totalMirrorOnly=0} (no false positives). {@code totalLiveOnly=64}, and — contrary to round 3/4's
 * working assumption that this gap was freshness-driven — all 64 of those {@code liveOnly} CVEs
 * classified as {@link LiveOnlyCause#LIVE_ONLY_FALSE_POSITIVE}: for each one, NVD's own
 * authoritative {@code ?cveId=} record has no {@code cpeMatch} covering the queried version at all,
 * meaning live's {@code ?cpeName=} search index returned a CVE its own authoritative record doesn't
 * actually cover — the same search-index-lag/over-broad-match shape round 4 found in isolation for
 * CVE-2026-18301/GIMP, recurring across the entire {@code liveOnly} set in this run rather than
 * being a one-off. {@code freshnessMissing=0}, {@code freshnessLag=0}, {@code
 * dashFailClosedOnly=0}, {@code ingestGapOrLogicBug=0}, {@code unexplained=0} — {@code gatePassed =
 * true}. See the {@code @Disabled} reason below for the full breakdown; this is one measurement
 * against this DB's snapshot and NVD's live state on 2026-09-03, not a standing guarantee for other
 * points in time or other samples.
 *
 * <p><b>Round 5 blocker (2026-09-03)</b>: the first attempt to actually run round 5 against the real
 * dev DB failed on the very first golden-300 row with {@code AEADBadTagException}. Root cause: (a)
 * this class's {@code compareLiveAndMirrorForEveryIdentifiedCpeGoldenRow} test method was passing
 * {@link #REAL_USER_ID} into {@link Stage1IdentificationService#identify}, and that user already has
 * a real NVD API key registered in that DB, encrypted under the app's real, production secret
 * encryption key; (b) this harness's {@code @TestPropertySource} does not (and per (d) below, must
 * not) supply that real key, so {@code UserApiKeyService#getNvdApiKey}'s decryption attempt against
 * whatever dummy/test key is in effect fails hard rather than silently. (c) The fix is not to bring a
 * real key into the test config — it's to stop routing {@code identify} through {@link
 * #REAL_USER_ID} at all: {@code identify} now takes {@link #UNKEYED_USER_ID} instead, the same
 * structurally-keyless id every other live call in this class already uses, so {@code getNvdApiKey}
 * has nothing to decrypt for that call either, regardless of what's registered against user 5 in
 * whatever DB this runs against. {@link #REAL_USER_ID} is now used only where an FK to a real user
 * row is unavoidable, i.e. {@link ResearchJobService#createJob}. (d) A side effect worth recording:
 * rounds 1 through 4 above never hit this exception only because user 5 happened to have no NVD key
 * registered at the time they ran (see the now-removed javadoc paragraph on {@link #REAL_USER_ID}
 * that used to require re-confirming that by hand before every run) — had a key existed then, {@code
 * identify}'s NVD lookups in those rounds would have silently used keyed pacing (~700ms/request)
 * instead of this gate's required unkeyed 6.5s/request, a latent violation of the gate's own pacing
 * requirement that this fix now makes structurally impossible rather than dependent on remembering
 * to check a database row by hand.
 *
 * <p>Uses the same {@code @Transactional} rollback trick as {@link ChocolateyRemovalGolden300RecallTest}
 * (job creation joins this test method's own transaction and is rolled back at the end, never
 * durably written) and the same real-dev-DB {@code @TestPropertySource} as every other class in
 * this package. Disabled by default; re-enable by hand, run once, restore {@code @Disabled}.
 */
@SpringBootTest
// Never override app.secret-encryption-key here, literal or via ${APP_SECRET_ENCRYPTION_KEY} --
// this DB may hold real, production-encrypted secrets (see the class javadoc's "Round 5 blocker"
// and the removed FRESHNESS_STALE-style unproven-assumption mistakes it cites): a test-only key
// here would either fail to decrypt them (as happened) or, worse, silently succeed against
// differently-encrypted data. The fix for the AEADBadTagException below is routing calls through
// UNKEYED_USER_ID instead, not bringing a real/dummy key into this test config.
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=${POSTGRES_PASSWORD}"
})
@Disabled("Round 5 (2026-09-03, senior-reviewer finding on round 4's PR: classifyLiveOnly's "
        + "FRESHNESS_STALE bucket was itself an unproven assumption -- the same failure shape as "
        + "round 3's unreachable-counter bug, see class javadoc) has been run against the real dev "
        + "DB mirror. GATE PASSED. 65 golden-300.csv IDENTIFIED_CPE rows compared (64 with a "
        + "successful live query, 1 -- Notepad++ -- excluded as inconclusive, same exclusion as "
        + "round 4). 51/64 matched exactly (CVE-id sets identical); totalMirrorOnly=0 across the 13 "
        + "mismatched rows (no false positives). totalLiveOnly=64, and this round's authoritative-"
        + "data-first check (rather than round 4's assumption) classified all 64/64 as "
        + "LIVE_ONLY_FALSE_POSITIVE: for every one of these CVEs, NVD's own authoritative ?cveId= "
        + "record has no cpeMatch covering the queried version at all -- live's ?cpeName= search "
        + "endpoint returned each CVE anyway, the same search-index-lag/over-broad-match shape round "
        + "4 found in isolation for CVE-2026-18301/GIMP, here recurring across the entire liveOnly "
        + "set rather than being a one-off. freshnessMissing=0, freshnessLag=0 -- none of the 64 "
        + "liveOnly CVEs were actually freshness gaps once checked against authoritative data, which "
        + "means round 3/4's working assumption that this liveOnly gap was freshness-driven did not "
        + "hold for this sample. dashFailClosedOnly=0, ingestGapOrLogicBug=0, unexplained=0 (every "
        + "authoritative ?cveId= fetch succeeded and was classifiable). Gate criterion "
        + "(totalMirrorOnly==0 && dashFailClosedOnly==0 && ingestGapOrLogicBug==0 && unexplained==0) "
        + "is satisfied: gatePassed=true. This is one measurement against golden-300's 64 "
        + "successfully-queried IDENTIFIED_CPE rows at this DB's snapshot and NVD's live state on "
        + "2026-09-03 -- not a guarantee the same breakdown reproduces at another point in time or "
        + "against a different sample. This round's unit test (NvdMirrorAbVerificationRunnerTest) "
        + "covers the authoritativeConfigurationsCover predicate in isolation with fixture JSON; the "
        + "real-mirror numbers above come from this class's own @Test run, not from that unit test. "
        + "Per-row live finding counts across the 64 successfully queried rows unchanged from round "
        + "4 (live-side query logic wasn't touched by this round's fix): sum 4676, average ~73.1, "
        + "top 3 by count: Google Chrome 127.0.6533.100 (2739), Mozilla Firefox 128.0 (681), GitLab "
        + "17.2.1 (282). Left disabled so it can never re-fire on a routine mvn test run -- see class "
        + "javadoc.")
class NvdMirrorAbVerificationRunner {

    /** Used only as the job-owner foreign key for {@link ResearchJobService#createJob} — job
     *  ownership requires a real, existing {@code users} row. Never pass this to {@link
     *  Stage1IdentificationService#identify} or {@link NvdVulnerabilitySource#fetchFromNvdCached}
     *  (see {@link #UNKEYED_USER_ID}'s own javadoc for why: this user id may have a real, live
     *  encrypted secret registered against it in whatever DB this runs against, and this harness's
     *  test config cannot decrypt that). */
    private static final Long REAL_USER_ID = 5L;
    /** Deliberately not a real user id (no {@code user_secrets} row can exist for it). Passed to
     *  both {@link NvdVulnerabilitySource#fetchFromNvdCached} and {@link
     *  Stage1IdentificationService#identify} so that, structurally and regardless of whatever is or
     *  isn't registered against {@link #REAL_USER_ID} in whatever DB this happens to run against:
     *  (i) every NVD access those two call sites make goes through {@code NvdRateLimiter}'s unkeyed
     *  6.5s/request pacing, exactly as this gate's task brief requires (the other live path, {@link
     *  #fetchAuthoritativeCveData}, takes no user id at all and always paces unkeyed by construction),
     *  and (ii) zero billed Claude calls are possible, since {@code identify} can only reach Stage1
     *  AI arbitration via a registered key this user id structurally cannot have. See the class
     *  javadoc's "Round 5 blocker" section for the incident this design replaced. */
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
    @Autowired
    private RestClient externalApiRestClient;
    @Autowired
    private NvdRateLimiter nvdRateLimiter;

    private static final String NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0";

    /** Memoizes {@link #fetchAuthoritativeCveData} per CVE id across this test run -- the liveOnly
     *  CVEs recur across mismatched golden-300 rows (round 4: 38 liveOnly CVEs across 12 mismatched
     *  rows), and every fetch already pays {@link NvdRateLimiter}'s unkeyed 6.5s pacing, so
     *  refetching the same id would multiply an already-slow run's wall time for no new
     *  information. */
    private final Map<String, AuthoritativeCveData> authoritativeCveCache = new HashMap<>();

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
            Optional<IdentifiedProduct> identified = stage1IdentificationService.identify(item, UNKEYED_USER_ID);
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
        int totalMirrorOnly = 0;
        int totalLiveOnly = 0;
        int liveOnlyFalsePositive = 0;
        int freshnessMissing = 0;
        int freshnessLag = 0;
        int dashFailClosedOnly = 0;
        int ingestGapOrLogicBug = 0;
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
                LiveOnlyExplanation explanation = classifyLiveOnly(cveId, row.cpeName());
                switch (explanation.cause()) {
                    case LIVE_ONLY_FALSE_POSITIVE -> liveOnlyFalsePositive++;
                    case FRESHNESS_MISSING -> freshnessMissing++;
                    case FRESHNESS_LAG -> freshnessLag++;
                    case DASH_FAIL_CLOSED -> dashFailClosedOnly++;
                    case INGEST_GAP_OR_LOGIC_BUG -> ingestGapOrLogicBug++;
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

        // Display-cap proposal (item 3, NOT implemented here -- this class only measures the
        // distribution its own analysis needs): round 3's real numbers (64 rows, sum 4676, average
        // ~73.1/row) show the mean itself is already far past what a per-item findings list can
        // usefully show, and the distribution is heavily right-skewed by a handful of
        // broad-surface products (Google Chrome 2739, Mozilla Firefox 681, GitLab 282 -- vs. an
        // average of ~73 and a long tail of rows with single-digit or zero counts). A cap of the
        // top 10 findings per item, sorted by CVSS score descending, with the remainder collapsed
        // into a "他N件" (N = total - 10) summary line, would show 100% of findings for the
        // majority of rows in this sample (rows with <=10 findings) while keeping the worst-case
        // row (Chrome, N=2729 hidden) from overwhelming the UI.
        // Gate criterion, round 5 (senior-reviewer finding on round 4's PR): mirrorOnly must be zero
        // (removing the vulnerable=true filter should already drive false positives to zero -- any
        // survivor here is a genuine mirrorLookup/versionApplies bug, not a known limitation), and
        // every liveOnly CVE must be explained without assuming freshness -- classifyLiveOnly now
        // checks NVD's own authoritative ?cveId= data first (see its own javadoc). A liveOnly CVE the
        // authoritative record itself doesn't cover (liveOnlyFalsePositive) is a live search-index
        // artifact, not a mirror defect, so it does NOT gate. dashFailClosedOnly (the known,
        // schema-limited AND-node/versionApplies('-') gap this task's scope explicitly excludes
        // fixing) and ingestGapOrLogicBug (a genuine, non-freshness, non-dash gap between a fresh
        // mirror and authoritative data) both still fail the gate -- neither is "explained".
        boolean gatePassed = totalMirrorOnly == 0 && dashFailClosedOnly == 0 && ingestGapOrLogicBug == 0
                && unexplained == 0;

        System.out.println("\n=== closed-mode backlog item 202 Phase 3b A/B gate result ===");
        System.out.println("total rows compared: " + rows.size());
        System.out.println("matched (identical CVE-id set): " + matched);
        System.out.println("mismatched: " + mismatchReports.size());
        System.out.println("totalMirrorOnly (false positives, must be 0 to pass): " + totalMirrorOnly);
        System.out.println("totalLiveOnly (live-only CVEs across mismatched rows): " + totalLiveOnly);
        System.out.println("  of which liveOnlyFalsePositive (authoritative ?cveId= data does NOT cover "
                + "this version -- live search-index artifact, not a mirror defect, does NOT gate): "
                + liveOnlyFalsePositive);
        System.out.println("  of which freshnessMissing (authoritative data covers it, but absent from "
                + "nvd_cve_records entirely): " + freshnessMissing);
        System.out.println("  of which freshnessLag (authoritative data covers it, nvd_cve_records row "
                + "exists but its own last_modified_at is older than authoritative's lastModified): "
                + freshnessLag);
        System.out.println("  of which dashFailClosedOnly (authoritative data covers it, mirror is fresh, "
                + "but its own cpe_match row(s) carry a '-' version segment -- known AND-node schema "
                + "gap, must be 0 to pass): " + dashFailClosedOnly);
        System.out.println("  of which ingestGapOrLogicBug (authoritative data covers it, mirror is "
                + "fresh, no '-' row either -- genuine ingest/logic gap, must be 0 to pass): "
                + ingestGapOrLogicBug);
        System.out.println("  of which unexplained (authoritative ?cveId= fetch itself failed -- cannot "
                + "classify without ground truth, must be 0 to pass): " + unexplained);
        System.out.println("GATE " + (gatePassed ? "PASSED" : "NOT PASSED"));
        for (String report : mismatchReports) {
            System.out.println("--- MISMATCH ---");
            System.out.println(report);
        }
    }

    /** Looks up every CVE id in {@code nvd_cve_cpe_match} whose (part, vendor, product) matches
     *  {@code cpeName} and whose version-applicability (own OR semantics only, see class javadoc)
     *  covers {@code cpeName}'s own version segment.
     *
     *  <p><b>Not a reference implementation for backlog item 241 (B4, the production mirror-backed
     *  {@code NvdVulnerabilitySource} rewrite)</b>: this method fetches every (part, vendor, product)
     *  row with no {@code LIMIT}, no version predicate, and no {@code vulnerable} filter, then
     *  applies {@link #versionApplies} in Java over the full result set — for a broad-surface
     *  product like {@code google:chrome} that's thousands of rows per call. That's an acceptable
     *  simplification for this disposable A/B harness (run once, against a handful of golden-300
     *  rows), but B4 must push version-applicability filtering into SQL (or use a two-stage query)
     *  rather than copying this fetch-everything-then-filter shape as-is. */
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
        return versionInRange(itemVersion, criteriaVersion,
                (String) matchRow.get("version_start_including"),
                (String) matchRow.get("version_start_excluding"),
                (String) matchRow.get("version_end_including"),
                (String) matchRow.get("version_end_excluding"));
    }

    /** The actual version-applicability rule shared by {@link #versionApplies} (mirror DB rows,
     *  snake_case columns) and {@link #authoritativeConfigurationsCover} (live {@code ?cveId=} JSON,
     *  camelCase fields) -- pulled out so both consult the exact same fail-closed-on-{@code -}
     *  semantics rather than two independently-maintained copies drifting apart. Package-private
     *  static, no DB/network access, directly unit-testable. */
    static boolean versionInRange(String itemVersion, String criteriaVersion, String startIncluding,
            String startExcluding, String endIncluding, String endExcluding) {
        if ("-".equals(criteriaVersion)) {
            return false;
        }
        if (!"*".equals(criteriaVersion)) {
            return criteriaVersion.equalsIgnoreCase(itemVersion);
        }
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

    private record AuthoritativeCveData(boolean fetchSucceeded, String lastModified, JsonNode configurations) {
    }

    /** Fetches one CVE's authoritative ground truth via NVD's {@code ?cveId=} endpoint (the single,
     *  fully-current record NVD has for that id) -- unlike {@code ?cpeName=} search, which round 4
     *  found can lag behind a CVE's own {@code lastModified} reanalysis by at least a day (see class
     *  javadoc for the CVE-2026-18301/GIMP case this exists to catch). Memoized via {@link
     *  #authoritativeCveCache}.
     *
     *  <p>Sequential only, through the same shared {@link NvdRateLimiter} (unkeyed, 6.5s/request)
     *  every other live call in this class already goes through -- deliberately not parallelized:
     *  this round's task brief is explicit that parallelizing would trip NVD's 5 req/30s unkeyed
     *  limit and produce a wave of fetch failures that would corrupt the very comparison this class
     *  exists to run.
     *
     *  <p>Any failure to get a usable record back -- network/parse error, zero {@code vulnerabilities}
     *  entries, or a missing/unparseable {@code lastModified} -- is reported as {@code
     *  fetchSucceeded=false} rather than silently treated as "no data" or "covers nothing": {@link
     *  #classifyLiveOnly} turns that into {@link LiveOnlyCause#UNEXPLAINED}, which fails the gate,
     *  per this round's task brief ("取得失敗時はUNEXPLAINED扱いにしてゲートを落とす"). */
    private AuthoritativeCveData fetchAuthoritativeCveData(String cveId) {
        if (authoritativeCveCache.containsKey(cveId)) {
            return authoritativeCveCache.get(cveId);
        }
        AuthoritativeCveData data;
        try {
            URI uri = UriComponentsBuilder.fromHttpUrl(NVD_CVE_API)
                    .queryParam("cveId", cveId)
                    .build()
                    .toUri();
            nvdRateLimiter.awaitTurn(false);
            JsonNode body = externalApiRestClient.get().uri(uri).retrieve().body(JsonNode.class);
            JsonNode vulnerabilities = body == null ? null : body.path("vulnerabilities");
            if (vulnerabilities == null || !vulnerabilities.isArray() || vulnerabilities.isEmpty()) {
                System.out.println("AUTHORITATIVE FETCH: ?cveId=" + cveId
                        + " returned zero vulnerabilities entries -- treating as a fetch failure");
                data = new AuthoritativeCveData(false, null, null);
            } else {
                JsonNode cve = vulnerabilities.get(0).path("cve");
                String lastModified = cve.path("lastModified").asText(null);
                if (lastModified == null) {
                    System.out.println("AUTHORITATIVE FETCH: ?cveId=" + cveId
                            + " response has no cve.lastModified -- treating as a fetch failure");
                    data = new AuthoritativeCveData(false, null, null);
                } else {
                    data = new AuthoritativeCveData(true, lastModified, cve.path("configurations"));
                }
            }
        } catch (Exception e) {
            System.out.println("AUTHORITATIVE FETCH FAILED: ?cveId=" + cveId + " -- " + e);
            data = new AuthoritativeCveData(false, null, null);
        }
        authoritativeCveCache.put(cveId, data);
        return data;
    }

    /** NVD's {@code lastModified} field is ISO-8601 without a zone/offset (e.g. {@code
     *  "2019-10-03T13:15:10.947"}, implicitly UTC) -- same fallback shape {@code
     *  NvdCveSyncService#parseNvdTimestamp} uses, deliberately duplicated rather than reused here
     *  (see class javadoc for why this class doesn't lean on production parsing code beyond the bare
     *  minimum). */
    private static OffsetDateTime parseNvdTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(value).atOffset(ZoneOffset.UTC);
            } catch (DateTimeException e2) {
                return null;
            }
        }
    }

    /** Pure predicate, no DB/network access -- exercised directly by {@code
     *  NvdMirrorAbVerificationRunnerTest} with fixture JSON (this class itself is a disabled,
     *  DB/network-backed integration harness whose own {@code @Test} can't double as that unit
     *  test). Does the authoritative {@code configurations} JSON (from a {@code ?cveId=} response's
     *  {@code cve.configurations}) contain at least one {@code cpeMatch} entry for the given (part,
     *  vendor, product) whose version-applicability covers {@code itemVersion}? Same OR-only,
     *  fail-closed-on-{@code -} semantics as {@link #versionApplies} (see {@link #versionInRange}),
     *  deliberately duplicated field-extraction from the live JSON shape rather than reused, since
     *  it differs from {@link #mirrorLookup}'s flattened DB-row shape. */
    static boolean authoritativeConfigurationsCover(JsonNode configurations, String part, String vendor,
            String product, String itemVersion) {
        for (JsonNode cpeMatch : matchingCriteriaNodes(configurations, part, vendor, product)) {
            List<String> segments = splitCpeSegments(cpeMatch.path("criteria").asText(""));
            String criteriaVersion = segments.size() > 5 ? segments.get(5) : "*";
            if (versionInRange(itemVersion, criteriaVersion,
                    cpeMatch.path("versionStartIncluding").asText(null),
                    cpeMatch.path("versionStartExcluding").asText(null),
                    cpeMatch.path("versionEndIncluding").asText(null),
                    cpeMatch.path("versionEndExcluding").asText(null))) {
                return true;
            }
        }
        return false;
    }

    /** Every {@code cpeMatch} node across {@code configurations[].nodes[]} whose own {@code
     *  criteria} parses to the given (part, vendor, product) -- regardless of version applicability.
     *  Shared by {@link #authoritativeConfigurationsCover} (checks version applicability over this
     *  set) and {@link #authoritativeCriteriaSummary} (dumps this set for the human-readable
     *  report). */
    private static List<JsonNode> matchingCriteriaNodes(JsonNode configurations, String part, String vendor,
            String product) {
        List<JsonNode> result = new ArrayList<>();
        if (configurations == null || configurations.isMissingNode() || configurations.isNull()) {
            return result;
        }
        for (JsonNode config : configurations) {
            for (JsonNode node : config.path("nodes")) {
                for (JsonNode cpeMatch : node.path("cpeMatch")) {
                    List<String> segments = splitCpeSegments(cpeMatch.path("criteria").asText(""));
                    if (segments.size() > 4 && part.equals(segments.get(2)) && vendor.equals(segments.get(3))
                            && product.equals(segments.get(4))) {
                        result.add(cpeMatch);
                    }
                }
            }
        }
        return result;
    }

    /** Human-readable dump of every authoritative {@code cpeMatch}'s own {@code criteria} string for
     *  the given (part, vendor, product) -- used in {@link LiveOnlyCause#LIVE_ONLY_FALSE_POSITIVE}
     *  report detail so the printed record carries NVD's own ground-truth criteria, not just this
     *  class's verdict. */
    private static String authoritativeCriteriaSummary(JsonNode configurations, String part, String vendor,
            String product) {
        List<String> criteriaStrings = new ArrayList<>();
        for (JsonNode cpeMatch : matchingCriteriaNodes(configurations, part, vendor, product)) {
            criteriaStrings.add(cpeMatch.path("criteria").asText());
        }
        return criteriaStrings.isEmpty()
                ? "(no cpeMatch entries at all for this part/vendor/product)"
                : criteriaStrings.toString();
    }

    /** Why a live-only CVE (returned by the live NVD query, not by {@link #mirrorLookup}) diverges
     *  -- see the gate's own pass/fail wording in {@link
     *  #compareLiveAndMirrorForEveryIdentifiedCpeGoldenRow} for how each cause is (or isn't) treated
     *  as "explained". */
    private enum LiveOnlyCause {
        /** NVD's own authoritative {@code ?cveId=} record (see {@link #fetchAuthoritativeCveData})
         *  has no {@code cpeMatch} covering this (part, vendor, product, version) at all -- live's
         *  {@code ?cpeName=} search endpoint returned this CVE anyway, meaning that search index
         *  hasn't caught up with the CVE's own reanalysis yet (confirmed live for CVE-2026-18301/
         *  GIMP, round 4 -> round 5). This is a live-side artifact, not a mirror defect: {@link
         *  #mirrorLookup} was right not to return it. Explained, does NOT gate. */
        LIVE_ONLY_FALSE_POSITIVE,
        /** Authoritative data confirms this CVE genuinely covers the queried version, but {@code
         *  nvd_cve_records} has no row for this CVE at all -- never synced, or created/modified after
         *  this DB's backfill snapshot. A proven freshness gap. Explained, does NOT gate. */
        FRESHNESS_MISSING,
        /** Authoritative data confirms this CVE genuinely covers the queried version, and {@code
         *  nvd_cve_records} has a row for it, but that row's own {@code last_modified_at} is older
         *  than the authoritative {@code lastModified} -- the mirror is holding a stale revision. A
         *  proven (not assumed, unlike round 4's {@code FRESHNESS_STALE}) freshness gap. Explained,
         *  does NOT gate. */
        FRESHNESS_LAG,
        /** Authoritative data confirms this CVE genuinely covers the queried version, the mirror's
         *  {@code nvd_cve_records} row is at least as fresh as authoritative's own {@code
         *  lastModified} (so this is NOT a freshness gap), and this class found a {@code cpe_match}
         *  row for this CVE/part/vendor/product whose {@code criteria} carries a bare {@code -}
         *  version segment -- {@link #versionApplies}'s deliberate fail-closed treatment (see its own
         *  javadoc) is exactly why {@link #mirrorLookup} didn't match it. This is the known,
         *  schema-limited AND-node gap ({@code nvd_cve_cpe_match} has no node/operator columns to
         *  represent a real NVD applicability condition spanning two paired CPEs) -- NOT fixable
         *  within this task's scope, and still gates (not counted as "explained"). */
        DASH_FAIL_CLOSED,
        /** Authoritative data confirms this CVE genuinely covers the queried version, the mirror's
         *  {@code nvd_cve_records} row is at least as fresh as authoritative's own {@code
         *  lastModified}, and none of its {@code nvd_cve_cpe_match} rows for this CVE/part/vendor/
         *  product carry a {@code -} either -- neither freshness nor the known dash schema gap
         *  explains this. A genuine ingest-correctness bug (this specific CVE's cpe_match rows for
         *  this part/vendor/product simply didn't land, or landed wrong, despite the record itself
         *  being fresh) or applicability-logic bug in {@link #mirrorLookup}/{@link #versionApplies}
         *  worth root-causing on its own. Gates. */
        INGEST_GAP_OR_LOGIC_BUG,
        /** The authoritative {@code ?cveId=} fetch itself failed (network/parse error, zero {@code
         *  vulnerabilities} entries, or an unparseable {@code lastModified}) -- see {@link
         *  #fetchAuthoritativeCveData}. Cannot classify this liveOnly CVE without ground truth, so it
         *  is never silently treated as explained. Gates. */
        UNEXPLAINED
    }

    private record LiveOnlyExplanation(LiveOnlyCause cause, String detail) {
    }

    /** Classifies one live-only CVE id per {@link LiveOnlyCause}, using NVD's own authoritative
     *  {@code ?cveId=} response (see {@link #fetchAuthoritativeCveData}) as ground truth rather than
     *  assuming every liveOnly CVE is a mirror freshness gap.
     *
     *  <p>REVISE (senior-reviewer round 4 -> round 5, 2026-09-03): round 4's {@code FRESHNESS_STALE}
     *  bucket (absorbing every liveOnly CVE with zero matching {@code nvd_cve_cpe_match} rows)
     *  repeated round 3's structural-tautology mistake in a new shape -- "no mirror match row" was
     *  *assumed* to mean "not synced yet" without ever checking whether NVD's own live data actually
     *  covers this CVE at all. Live's {@code ?cpeName=} search was re-verified against
     *  CVE-2026-18301/GIMP: its own {@code ?cveId=} authoritative record (lastModified=2026-09-02)
     *  has exactly one {@code gimp:gimp} {@code cpeMatch} -- version {@code 3.2.2}, a fixed value
     *  with no range -- which does not cover golden-300's queried {@code 2.10.38}. Live's search
     *  index (not yet caught up to that record's own reanalysis) returned this CVE anyway: a
     *  live-side false positive, not a mirror defect. This version checks authoritative coverage
     *  first (step (a): {@link #authoritativeConfigurationsCover}) before ever consulting freshness,
     *  and only falls through to the freshness/dash/ingest-gap buckets (step (b)) once authoritative
     *  data has confirmed there's a real gap for the mirror to explain. Freshness (missing record,
     *  then a stale {@code last_modified_at}) is checked before the '-' fail-closed bucket, which in
     *  turn is checked before the {@link LiveOnlyCause#INGEST_GAP_OR_LOGIC_BUG} catch-all -- a CVE
     *  that's simply not fresh yet doesn't need the schema-gap explanation to be accounted for. */
    private LiveOnlyExplanation classifyLiveOnly(String cveId, String cpeName) {
        AuthoritativeCveData authoritative = fetchAuthoritativeCveData(cveId);
        if (!authoritative.fetchSucceeded()) {
            return new LiveOnlyExplanation(LiveOnlyCause.UNEXPLAINED,
                    "authoritative NVD ?cveId=" + cveId + " lookup failed or returned no usable record "
                            + "(see AUTHORITATIVE FETCH log above) -- cannot classify without ground "
                            + "truth, counted as unexplained rather than silently skipped");
        }

        List<String> segments = splitCpeSegments(cpeName);
        String part = segments.get(2);
        String vendor = segments.get(3);
        String product = segments.get(4);
        String itemVersion = segments.get(5);

        if (!authoritativeConfigurationsCover(authoritative.configurations(), part, vendor, product,
                itemVersion)) {
            return new LiveOnlyExplanation(LiveOnlyCause.LIVE_ONLY_FALSE_POSITIVE,
                    "CVE " + cveId + ": live NVD's ?cpeName= search returned this CVE, but its own "
                            + "authoritative ?cveId= record (lastModified=" + authoritative.lastModified()
                            + ") has no cpeMatch covering " + part + ":" + vendor + ":" + product + ":"
                            + itemVersion + " -- a live search-index lag/over-broad-match false "
                            + "positive, not a mirror defect. Authoritative cpeMatch criteria for this "
                            + "part/vendor/product: "
                            + authoritativeCriteriaSummary(authoritative.configurations(), part, vendor, product));
        }

        OffsetDateTime authoritativeLastModified = parseNvdTimestamp(authoritative.lastModified());
        if (authoritativeLastModified == null) {
            return new LiveOnlyExplanation(LiveOnlyCause.UNEXPLAINED,
                    "authoritative NVD ?cveId=" + cveId + " lastModified=\"" + authoritative.lastModified()
                            + "\" could not be parsed -- cannot determine freshness without it, counted "
                            + "as unexplained rather than silently assumed fresh");
        }

        List<Map<String, Object>> recordRows = jdbcTemplate.queryForList(
                "SELECT (last_modified_at >= ?) AS mirror_is_fresh FROM nvd_cve_records WHERE cve_id = ?",
                authoritativeLastModified, cveId);
        if (recordRows.isEmpty()) {
            return new LiveOnlyExplanation(LiveOnlyCause.FRESHNESS_MISSING,
                    "authoritative data confirms this CVE genuinely covers " + itemVersion + " (part="
                            + part + " vendor=" + vendor + " product=" + product + "), but it's not "
                            + "present in nvd_cve_records at all -- mirror data gap (never synced, or "
                            + "CVE created/modified after this DB's backfill snapshot)");
        }
        boolean mirrorIsFresh = Boolean.TRUE.equals(recordRows.get(0).get("mirror_is_fresh"));
        if (!mirrorIsFresh) {
            return new LiveOnlyExplanation(LiveOnlyCause.FRESHNESS_LAG,
                    "authoritative data confirms this CVE genuinely covers " + itemVersion + ", and this "
                            + "DB's nvd_cve_records row for it exists but its own last_modified_at is "
                            + "older than live's authoritative lastModified=" + authoritative.lastModified()
                            + " -- the mirror is holding a stale revision of this CVE, a proven (not "
                            + "assumed) freshness gap");
        }

        List<Map<String, Object>> matchRows = jdbcTemplate.queryForList(
                "SELECT criteria, vulnerable, version_start_including, version_start_excluding, "
                        + "version_end_including, version_end_excluding FROM nvd_cve_cpe_match "
                        + "WHERE cve_id = ? AND part = ? AND vendor = ? AND product = ?",
                cveId, part, vendor, product);
        boolean mirrorHasDashRow = matchRows.stream().anyMatch(row -> {
            List<String> criteriaSegments = splitCpeSegments((String) row.get("criteria"));
            String criteriaVersion = criteriaSegments.size() > 5 ? criteriaSegments.get(5) : "*";
            return "-".equals(criteriaVersion);
        });
        if (mirrorHasDashRow) {
            return new LiveOnlyExplanation(LiveOnlyCause.DASH_FAIL_CLOSED,
                    "authoritative data confirms this CVE genuinely covers " + itemVersion + ", the "
                            + "mirror's nvd_cve_records row is at least as fresh as live's authoritative "
                            + "lastModified, but its own nvd_cve_cpe_match row(s) for this CVE/part/"
                            + "vendor/product carry a bare '-' version segment that versionApplies "
                            + "fail-closes on -- the known, schema-limited AND-node gap (see "
                            + "versionApplies javadoc), not fixable within this task's scope. mirror "
                            + "cpe_match rows: " + matchRows);
        }
        return new LiveOnlyExplanation(LiveOnlyCause.INGEST_GAP_OR_LOGIC_BUG,
                "authoritative data confirms this CVE genuinely covers " + itemVersion + ", the mirror's "
                        + "nvd_cve_records row is at least as fresh as live's authoritative lastModified, "
                        + "and none of its nvd_cve_cpe_match rows for this CVE/part/vendor/product carry "
                        + "a '-' version segment either -- NOT a freshness gap and NOT the known dash "
                        + "schema limitation, a genuine ingest-correctness or applicability-logic bug "
                        + "worth root-causing on its own. mirror cpe_match rows: " + matchRows);
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
