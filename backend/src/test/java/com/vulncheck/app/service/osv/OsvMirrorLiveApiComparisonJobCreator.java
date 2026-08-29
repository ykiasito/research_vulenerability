package com.vulncheck.app.service.osv;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.service.vuln.GhsaVulnerabilitySource;
import com.vulncheck.app.service.vuln.OsvEcosystems;
import com.vulncheck.app.service.vuln.OsvLiveQueryClient;
import com.vulncheck.app.service.vuln.OsvVulnerabilitySource;
import com.vulncheck.app.service.vuln.SourceResult;
import com.vulncheck.app.service.vuln.VulnFinding;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

/**
 * A/B validation gate required by {@code docs/spec/osv-mirror-plan.md} §9-2 as an implementation
 * completion condition, before {@link OsvVulnerabilitySource#find} is trusted as the mirror's
 * replacement for the old live-API implementation. Runs a REAL baseline sync (all 10 ecosystem
 * zips) against {@code vulncheck_test}, then for a hand-picked set of (ecosystem, package, version)
 * tuples spanning every non-GHSA-heavy source population (PyPI/Go/crates.io, the largest of the
 * ~13,600 in-scope records — plan §2-1) plus a few GHSA-heavy ecosystems (npm/Maven/RubyGems, to
 * exercise the expected "live-only, explained by GHSA exclusion" case from plan §9-2 item 3), runs
 * both:
 * <ul>
 *   <li>the OLD live-API path, reconstructed here via {@link OsvLiveQueryClient#queryPackage}
 *       (identical logic to what {@code OsvVulnerabilitySource#find} used to do before this
 *       implementation pass — see that class's git history / the design plan §7-1);
 *   <li>the NEW mirror-backed {@link OsvVulnerabilitySource#find}.
 * </ul>
 * and prints the id-set diff for each case, plus an aggregate summary. Throwaway; not part of the
 * permanent suite (same convention as {@code GhsaBaselineSyncTriggerJobCreator} — not named {@code
 * *Test} so Surefire's default discovery skips it).
 *
 * <p><b>Per plan §9-2 item 5 / the task's own gating instruction: this test does NOT flip any
 * wiring by itself.</b> It only prints findings for a human (or the orchestrator/senior-reviewer) to
 * read; whether {@link OsvVulnerabilitySource#find}'s mirror-backed body stays as the production
 * implementation is decided by whoever reads this run's output, not by this test's own pass/fail
 * status (it always "passes" as long as neither call throws).
 */
@SpringBootTest
class OsvMirrorLiveApiComparisonJobCreator {

    @Autowired
    private OsvSyncService osvSyncService;
    // OsvVulnerabilitySource is now a real @Component bean (the A/B gate below is what cleared it
    // for the switch) — autowired directly, same as ghsaVulnerabilitySource below.
    @Autowired
    private OsvVulnerabilitySource osvVulnerabilitySource;
    @Autowired
    private OsvLiveQueryClient osvLiveQueryClient;
    // Only used for the Stage2-aggregate fallback check below (task step 4): even an unexplained
    // OSV-mirror-only loss may not be a real end-to-end loss if GhsaVulnerabilitySource's own,
    // independently-run lookup already surfaces the same CVE for the same (ecosystem, package,
    // version) — Stage2 combines every source's findings, so only a gap in the union matters.
    @Autowired
    private GhsaVulnerabilitySource ghsaVulnerabilitySource;

    private record Case(String ecosystem, String packageName, String version) {
    }

    /** Spans PyPI/Go/crates.io (the three largest non-GHSA-reviewed source populations, ~93% of the
     *  ~13,600 in-scope records combined — plan §2-1) plus npm/Maven/RubyGems/NuGet (heavily
     *  GHSA-covered ecosystems, included specifically to produce the "live-only, explained by GHSA
     *  exclusion" case plan §9-2 item 3 expects). Real, historically-vulnerable (package, version)
     *  pairs, not synthetic.
     *
     *  <p>Expanded from the original 10-case set to 31 cases, weighted toward crates.io and go (8
     *  each), after the senior-reviewer's real-data deep dive found the original 10-case run too
     *  small to surface the {@code introduced:"0.0.0-0"} sentinel bug (crates.io's advisory-unit
     *  reach was only 19% before that fix) — see the P0 item in the task that expanded this list. */
    private static final List<Case> CASES = List.of(
            // crates.io (8) — heaviest weight per this revision, RustSec's "0.0.0-0" sentinel is
            // crates.io-specific so this ecosystem is where the P0 fix matters most.
            new Case("crates.io", "time", "0.1.40"),
            new Case("crates.io", "openssl", "0.10.20"),
            new Case("crates.io", "smallvec", "1.6.0"),
            new Case("crates.io", "regex", "1.5.0"),
            new Case("crates.io", "tokio", "0.1.0"),
            new Case("crates.io", "hyper", "0.14.3"),
            new Case("crates.io", "rustls", "0.19.0"),
            new Case("crates.io", "chrono", "0.4.19"),
            // go (8) — second-heaviest weight, also affected by version-format quirks (pseudo-
            // versions, +incompatible — out of scope, see known-limitations.md).
            new Case("go", "golang.org/x/text", "0.3.0"),
            new Case("go", "github.com/gin-gonic/gin", "1.6.0"),
            new Case("go", "github.com/dgrijalva/jwt-go", "3.2.0"),
            new Case("go", "github.com/gorilla/websocket", "1.4.0"),
            new Case("go", "github.com/miekg/dns", "1.1.25"),
            new Case("go", "github.com/prometheus/client_golang", "1.0.0"),
            new Case("go", "google.golang.org/grpc", "1.29.0"),
            new Case("go", "github.com/hashicorp/consul", "1.7.0"),
            // pypi (6)
            new Case("pypi", "django", "3.2.0"),
            new Case("pypi", "requests", "2.6.0"),
            new Case("pypi", "pyyaml", "5.1"),
            new Case("pypi", "flask", "0.12"),
            new Case("pypi", "jinja2", "2.10"),
            new Case("pypi", "pillow", "8.1.0"),
            // GHSA-heavy ecosystems (9) — kept light, exercise the "live-only, explained by GHSA
            // exclusion" case.
            new Case("npm", "lodash", "4.17.15"),
            new Case("npm", "minimist", "1.2.0"),
            new Case("npm", "axios", "0.18.0"),
            new Case("maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
            new Case("maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
            new Case("rubygems", "rails", "5.0.0"),
            new Case("rubygems", "nokogiri", "1.10.0"),
            new Case("nuget", "Newtonsoft.Json", "9.0.1"),
            new Case("nuget", "System.Text.Encodings.Web", "4.5.0"));

    @Test
    void compareLiveApiAndMirrorFindings() {
        OsvSyncService.SyncResult baseline = osvSyncService.syncBaseline();
        System.out.println("\n=== OSV BASELINE SYNC RESULT (for A/B comparison): upserted=" + baseline.upserted()
                + " failed=" + baseline.failed() + " alreadyRunning=" + baseline.alreadyRunning() + " ===\n");

        Set<String> allLiveOnly = new TreeSet<>();
        Set<String> allMirrorOnly = new TreeSet<>();
        Set<String> unexplainedLiveOnly = new TreeSet<>();
        // Case + its full live-only id set (GHSA-* included), kept structured (not just the printed
        // string form above) so the Stage2 fallback check below can re-run GhsaVulnerabilitySource's
        // own find() per case and check the COMBINED (OSV-mirror + GHSA-mirror) union, not just the
        // OSV mirror alone — this is what Stage2 actually reports to the user.
        Map<Case, Set<String>> liveOnlyByCase = new LinkedHashMap<>();

        for (Case c : CASES) {
            String osvEcosystem = OsvEcosystems.INTERNAL_TO_OSV.get(c.ecosystem());
            SourceResult liveResult = osvLiveQueryClient.queryPackage(osvEcosystem, c.packageName(), c.version());
            SourceResult mirrorResult = osvVulnerabilitySource.find(item(c.version()), identified(c.ecosystem(), c.packageName()), 1L);

            Set<String> liveIds = idsOf(liveResult);
            Set<String> mirrorIds = idsOf(mirrorResult);

            Set<String> liveOnly = new TreeSet<>(liveIds);
            liveOnly.removeAll(mirrorIds);
            Set<String> mirrorOnly = new TreeSet<>(mirrorIds);
            mirrorOnly.removeAll(liveIds);

            allLiveOnly.addAll(liveOnly);
            allMirrorOnly.addAll(mirrorOnly);
            if (!liveOnly.isEmpty()) {
                liveOnlyByCase.put(c, liveOnly);
            }
            for (String id : liveOnly) {
                if (!id.startsWith("GHSA-")) {
                    unexplainedLiveOnly.add(c.ecosystem() + "/" + c.packageName() + "@" + c.version() + " -> " + id);
                }
            }

            System.out.println("=== " + c.ecosystem() + "/" + c.packageName() + "@" + c.version()
                    + " (live succeeded=" + liveResult.succeeded() + ", mirror succeeded=" + mirrorResult.succeeded() + ") ===");
            System.out.println("  live ids:   " + liveIds);
            System.out.println("  mirror ids: " + mirrorIds);
            System.out.println("  live-only:   " + liveOnly);
            System.out.println("  mirror-only: " + mirrorOnly);
        }

        System.out.println("\n=== A/B SUMMARY ===");
        System.out.println("all live-only ids across every case:   " + allLiveOnly);
        System.out.println("all mirror-only ids across every case: " + allMirrorOnly);
        System.out.println("live-only ids NOT explained by GHSA-* exclusion (plan §9-2 item 3/4): " + unexplainedLiveOnly);
        if (unexplainedLiveOnly.isEmpty()) {
            System.out.println("RESULT: every live-only finding is explained by the deliberate GHSA-* exclusion "
                    + "(plan §0(d)) — no unexplained loss found.");
        } else {
            System.out.println("RESULT: unexplained live-only losses found in the OSV mirror alone — see "
                    + "docs/spec/osv-mirror-plan.md §9-2 item 4. Checking Stage2's actual combined union (OSV mirror "
                    + "+ GhsaVulnerabilitySource's own independent lookup) below before concluding this is a real "
                    + "end-to-end gap.");
        }
        // Run for every case with ANY live-only id (GHSA-* included), not just the "unexplained"
        // ones — this both checks the fallback for genuine gaps AND verifies the GHSA-* exclusion
        // assumption above is actually backed by GhsaVulnerabilitySource surfacing those ids too,
        // rather than just asserting it by prefix.
        if (!liveOnlyByCase.isEmpty()) {
            System.out.println("\n=== STAGE2 FALLBACK CHECK (task step 4): does GhsaVulnerabilitySource's own, "
                    + "independent lookup for the same (ecosystem, package, version) already surface each OSV-mirror "
                    + "live-only id (directly, or the same underlying CVE under a different id), so Stage2's actual "
                    + "combined result set has no real gap? ===");
            Set<String> stillMissingOverall = new TreeSet<>();
            for (Map.Entry<Case, Set<String>> entry : liveOnlyByCase.entrySet()) {
                Case c = entry.getKey();
                SourceResult ghsaResult = ghsaVulnerabilitySource.find(item(c.version()), identified(c.ecosystem(), c.packageName()), 1L);
                Set<String> ghsaIds = idsOf(ghsaResult);
                Set<String> stillMissing = new TreeSet<>(entry.getValue());
                stillMissing.removeAll(ghsaIds);
                stillMissingOverall.addAll(stillMissing);
                System.out.println("  " + c.ecosystem() + "/" + c.packageName() + "@" + c.version()
                        + " — OSV-mirror-only ids: " + entry.getValue() + ", GhsaVulnerabilitySource ids: " + ghsaIds
                        + ", still missing from Stage2's combined union: " + stillMissing);
            }
            System.out.println("\nSTAGE2 RESULT: ids missing from the combined (OSV mirror + GHSA mirror) union "
                    + "across every case: " + stillMissingOverall);
            if (stillMissingOverall.isEmpty()) {
                System.out.println("Every OSV-mirror live-only id is covered by GhsaVulnerabilitySource's own "
                        + "independent lookup (directly, by an alias id, or — for the RUSTSEC-*/GO-*/PYSEC-* "
                        + "id-representation cases — by the OSV mirror itself under the CVE-ID-priority COALESCE "
                        + "id, plan §9-2 item 10) — no real end-to-end Stage2 gap found.");
            } else {
                System.out.println("Real Stage2 gap: the ids above are missing from BOTH the OSV mirror and "
                        + "GhsaVulnerabilitySource for the same (ecosystem, package, version) — must be recorded in "
                        + "known-limitations.md.");
            }
        }
    }

    private Set<String> idsOf(SourceResult result) {
        Set<String> ids = new LinkedHashSet<>();
        for (VulnFinding finding : result.findings()) {
            ids.add(finding.cveOrGhsaId());
        }
        return ids;
    }

    private ResearchJobItem item(String version) {
        ResearchJobItem item = new ResearchJobItem();
        item.setProductName("test");
        item.setVersion(version);
        item.setUsageText("test");
        return item;
    }

    private IdentifiedProduct identified(String ecosystem, String packageName) {
        IdentifiedProduct product = new IdentifiedProduct();
        product.setEcosystem(ecosystem);
        product.setPackageName(packageName);
        return product;
    }
}
