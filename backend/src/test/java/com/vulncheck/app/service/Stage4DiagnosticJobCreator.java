package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import java.io.InputStream;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

/**
 * Note: the CSV filename below dates from its original 5-row version; it now has 5 diagnostic
 * rows + 43 budget-padding rows (48 total) — see the class list below. Not renamed because
 * renaming would require updating this class's file-path reference along with it, which wasn't
 * worth doing for a throwaway diagnostic fixture.
 *
 * <p>Creates a real-cost diagnostic job (stage4-diagnostic-5.csv) whose sole purpose is to force 3-5
 * real Stage4 (web_search_research) calls against the real, running pipeline so the 2026-08-29
 * {@code _count_web_searches} fix (billing-authoritative
 * {@code response.usage.server_tool_use.web_search_requests} instead of counting
 * {@code web_search_tool_result} content blocks, see {@code llm-service/main.py}) can be verified
 * against real Claude API responses — see docs/spec/nfr-status-2026-08.md cost section, item 3.
 *
 * <p>The CSV has 2 kinds of rows:
 * <ul>
 *   <li><b>5 diagnostic rows</b> (is-number/kind-of/cowsay/colorize/same-file): real, existing
 *   packages (npm/PyPI/RubyGems/crates.io, confirmed via each registry's live API to exist at the
 *   exact version) chosen because a live OSV.dev query ({@code POST
 *   https://api.osv.dev/v1/query}) returned zero advisories for each at diagnostic time
 *   (2026-08-29) — this is expected to make Stage1 identify them via registry match (no CPE) and
 *   Stage2 return 0 vulnerabilities, which is Stage4's trigger condition
 *   ({@code Stage4WebSearchResearchService}, see docs/spec/pipeline.md).
 *   <li><b>43 budget-padding rows</b> (log4j-core/jackson-databind at old, confirmed-vulnerable
 *   Maven coordinate versions — {@code groupId:artifactId} is structurally unique to Maven Central,
 *   so {@code RegistryRoutingPolicy} only ever queries Maven for these, avoiding the
 *   cross-registry-candidate Tier2 disambiguation seen on the first run (job 186) — and each
 *   version was confirmed via a live OSV.dev query to have vulnerabilities, so Stage2 finds a hit
 *   and Stage4 correctly does NOT fire for them). These exist purely to raise
 *   {@code JobCostBudgetService}'s per-job cap ({@code COST_CAP_PER_ITEM_USD * itemCount}) high
 *   enough to actually afford 5 Stage4 reservations — job 186 (5 items only, no padding) hit "job
 *   cost budget exhausted" on every single item because a 5-item job's total cap ($0.025) is below
 *   even a single $0.035 Stage4 reservation, a hard floor independent of how much Tier2 spent (it
 *   would have been exhausted even at zero Tier2 spend). Padding rows were expected to add
 *   $0 in real spend (free Tier1 registry match + free Stage2 structured-DB lookup, no Claude call
 *   at all) while still counting toward the item-count multiplier — <b>this expectation was
 *   falsified by the actual job 187 run (2026-08-29): the 43 padding rows did NOT skip Tier2, they
 *   were charged Tier2 43 times ($0.051619, 31% of job 187's $0.164977 total)</b>. A Maven
 *   {@code groupId:artifactId} coordinate keeps {@code RegistryRoutingPolicy} from querying other
 *   registries, but that alone does not guarantee Tier1's static registry match resolves to a
 *   single candidate without needing Tier2 disambiguation — those are two different things, and
 *   this class conflated them. See docs/spec/nfr-status-2026-08.md's cost section (item 3) for the
 *   corrected accounting and the resulting net budget headroom per padding row (~$0.0038, not
 *   $0.005).
 * </ul>
 *
 * Neither expectation is a hard guarantee (OSV/registry state can change), but no plaintext API
 * key handling is required here — same real-dev-DB / real-key-already-in-user_secrets flow as
 * {@link RealAiValidationJobCreator} (job 185).
 *
 * <p>Same pattern as {@link RealAiValidationJobCreator}: only persists the job (PENDING) via the
 * real {@link ResearchJobService} against the real {@code vulncheck} dev DB; starting it is done
 * separately by spoofing {@code research_jobs.status} to {@code PROCESSING} and restarting the
 * backend so {@link StuckJobResumer} picks it up. Throwaway; not part of the permanent suite.
 * Disabled immediately after use for the same reason as {@code RealAiValidationJobCreator} — a live
 * job-creating {@code @SpringBootTest} left enabled would re-fire (and re-bill) on every subsequent
 * {@code mvn test} run.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:postgresql://postgres:5432/vulncheck",
        "spring.datasource.username=vulncheck",
        "spring.datasource.password=vulncheck"
})
@Disabled("Already run twice (Stage4 web-search diagnostic, 2026-08-29: job 186 with 5 items only "
        + "hit budget exhaustion on every item and fired Stage4 zero times; job 187 added 43 "
        + "budget-padding rows and is the one actually used for the diagnostic) to create the "
        + "diagnostic job against the real dev DB. Left disabled so it can never re-fire (and "
        + "re-bill) on a routine mvn test run — see class javadoc.")
class Stage4DiagnosticJobCreator {

    private static final Long REAL_USER_ID = 5L;

    @Autowired
    private ResearchJobService researchJobService;

    @Test
    void createStage4DiagnosticJob() throws Exception {
        try (InputStream csv = getClass().getClassLoader().getResourceAsStream("stage4-diagnostic-5.csv")) {
            ResearchJob job = researchJobService.createJob(
                    REAL_USER_ID, "stage4-diagnostic-5.csv", csv, ColumnMapping.identity(), false);
            System.out.println("\n=== CREATED STAGE4 DIAGNOSTIC JOB ID: " + job.getId() + " ===\n");
        }
    }
}
