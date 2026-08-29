package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.VulnerabilityRepository;
import com.vulncheck.app.service.llm.LlmServiceClient;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledChangelogResponse;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledComponentDto;
import com.vulncheck.app.service.llm.LlmServiceModels.BundledExtractResponse;
import com.vulncheck.app.service.vuln.NvdVulnerabilitySource;
import com.vulncheck.app.service.vuln.OsvLiveQueryClient;
import com.vulncheck.app.service.vuln.SourceResult;
import com.vulncheck.app.service.vuln.VulnFinding;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BundledComponentResearchServiceTest {

    private static final Long USER_ID = 7L;

    @Mock
    private UserApiKeyService userApiKeyService;
    @Mock
    private LlmServiceClient llmServiceClient;
    @Mock
    private JobCostBudgetService jobCostBudgetService;
    @Mock
    private CpeDictionaryRepository cpeDictionaryRepository;
    @Mock
    private NvdVulnerabilitySource nvdVulnerabilitySource;
    @Mock
    private OsvLiveQueryClient osvLiveQueryClient;
    @Mock
    private VulnerabilityRepository vulnerabilityRepository;
    @Mock
    private JobItemVulnerabilityRepository jobItemVulnerabilityRepository;

    @BeforeEach
    void allowClaudeKeyAndBudgetByDefault() {
        lenient().when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.of("sk-ant-test"));
        lenient().when(jobCostBudgetService.tryReserveBundledComponent(any(), any())).thenReturn(true);
    }

    private BundledComponentResearchService service() {
        return new BundledComponentResearchService(userApiKeyService, llmServiceClient, jobCostBudgetService,
                cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository,
                jobItemVulnerabilityRepository);
    }

    private ResearchJobItem item() {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(9L);
        item.setJobId(1L);
        item.setProductName("Chocolatey CLI");
        item.setVersion("4.6.0");
        item.setUsageText("used to install packages");
        return item;
    }

    private void stubChangelogFound(String text) {
        when(llmServiceClient.discoverBundledComponentChangelog(eq("sk-ant-test"), any(), any()))
                .thenReturn(Optional.of(new BundledChangelogResponse(true, text, List.of("https://example.com"), null)));
    }

    private void stubExtraction(BundledComponentDto... components) {
        when(llmServiceClient.extractBundledComponents(eq("sk-ant-test"), any(), anyString(), any()))
                .thenReturn(Optional.of(new BundledExtractResponse(List.of(components), null)));
    }

    /** Builds a CPE dictionary candidate with the given {@code target_sw} set — mirrors what {@code
     *  CpeDictionaryRepositoryImpl#findFuzzyMatches} actually populates (see {@link
     *  CpeDictionaryEntry#getTargetSwValues}'s own javadoc). Pass no values for "no target_sw signal
     *  at all" (a candidate the real query never actually produces, but exercised by some tests
     *  below purely to isolate the exact-slug matching from the target_sw gate). */
    private CpeDictionaryEntry cpeEntry(String vendor, String product, String... targetSw) {
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setVendor(vendor);
        entry.setProduct(product);
        entry.setCpeString("cpe:2.3:a:" + vendor + ":" + product + ":1.0:*:*:*:*:*:*:*");
        entry.setTargetSwValues(Set.of(targetSw));
        return entry;
    }

    @Test
    void skipsEntirelyWithoutAClaudeApiKey() {
        when(userApiKeyService.getClaudeApiKey(USER_ID)).thenReturn(Optional.empty());

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(llmServiceClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void skipsWhenBudgetIsExhaustedBeforeChangelogDiscovery() {
        when(jobCostBudgetService.tryReserveBundledComponent(any(), any())).thenReturn(false);

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(llmServiceClient);
    }

    @Test
    void skipsWhenNoChangelogTextIsFound() {
        when(llmServiceClient.discoverBundledComponentChangelog(eq("sk-ant-test"), any(), any()))
                .thenReturn(Optional.of(new BundledChangelogResponse(false, null, List.of(), null)));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verify(llmServiceClient, never()).extractBundledComponents(any(), any(), any(), any());
    }

    @Test
    void skipsExtractionWhenBudgetIsExhaustedAfterChangelogDiscovery() {
        stubChangelogFound("Updated bundled 7-Zip to 26.02.");
        // First reservation (changelog) succeeds, second (extraction) is exhausted.
        when(jobCostBudgetService.tryReserveBundledComponent(any(), any())).thenReturn(true, false);

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verify(llmServiceClient, never()).extractBundledComponents(any(), any(), any(), any());
    }

    @Test
    void emptyExtractionResultPersistsNothing() {
        stubChangelogFound("Updated bundled 7-Zip to 26.02.");
        stubExtraction();

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(vulnerabilityRepository, jobItemVulnerabilityRepository, cpeDictionaryRepository,
                nvdVulnerabilitySource, osvLiveQueryClient);
    }

    @Test
    void rejectsBlankComponentName() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("  ", "26.02", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void rejectsOversizedComponentName() {
        stubChangelogFound("changelog text");
        String tooLong = "x".repeat(101);
        stubExtraction(new BundledComponentDto(tooLong, "1.0.0", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void rejectsAVersionThatExactlyMatchesTheItemsOwnVersion() {
        // Guards against the LLM re-extracting the product's own version as if it were a bundled
        // component's version (plan's §3-3) — item()'s own version is "4.6.0".
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("Chocolatey CLI", "4.6.0", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void rejectsABlankVersion() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("7-Zip", "  ", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    // --- REVISE item 5: server-side version-format validation ----------------------------------

    @Test
    void rejectsANonVersionStringLikeLatest() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("7-Zip", "latest", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void rejectsANonVersionStringLikeStable() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("7-Zip", "stable", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void rejectsAVersionContainingAColonRatherThanBuildingAMalformedCpe() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("7-Zip", "1:2.3", "high"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    // --- REVISE item 8: self-flagged low-confidence extractions are discarded ------------------

    @Test
    void rejectsALowConfidenceCandidate() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("7-Zip", "26.02", "low"));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(cpeDictionaryRepository, nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository);
    }

    @Test
    void cpeTrigramHitQueriesNvdAndPersistsTheFindingWithBundledComponentAttribution() {
        stubChangelogFound("Updated bundled 7-Zip to 26.02.");
        stubExtraction(new BundledComponentDto("7-Zip", "26.02", "high"));

        when(cpeDictionaryRepository.findFuzzyMatches(eq("7-Zip"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("7-zip", "7-zip", "*")));

        VulnFinding finding = new VulnFinding(
                "CVE-2026-11111", "nvd", "HIGH", "7-Zip vuln", "https://nvd.nist.gov/vuln/detail/CVE-2026-11111", null);
        when(nvdVulnerabilitySource.fetchFromNvdCached(eq("cpe:2.3:a:7-zip:7-zip:26.02:*:*:*:*:*:*:*"), eq(USER_ID)))
                .thenReturn(SourceResult.success(List.of(finding)));
        // REVISE item 6: vulnerabilities.source is the finding's real provenance ("nvd"), not the
        // bundled_component discovery-tier constant, and the write goes through upsertAndGetId
        // (authoritative source) rather than insertIfAbsentAndGetId.
        when(vulnerabilityRepository.upsertAndGetId(
                eq("CVE-2026-11111"), eq("nvd"), eq("HIGH"), eq("7-Zip vuln"),
                eq("https://nvd.nist.gov/vuln/detail/CVE-2026-11111"), any()))
                .thenReturn(777L);

        int count = service().research(item(), USER_ID);

        assertThat(count).isEqualTo(1);
        // discovered_via_tier still carries the bundled_component constant — that attribution
        // belongs on the join table, distinct from vulnerabilities.source above.
        verify(jobItemVulnerabilityRepository).linkIfAbsentWithBundledComponent(
                eq(9L), eq(777L), eq("bundled_component"), eq("https://nvd.nist.gov/vuln/detail/CVE-2026-11111"),
                eq("7-Zip"), eq("26.02"));
        verifyNoInteractions(osvLiveQueryClient);
    }

    @Test
    void noCpeMatchAndNoOsvEcosystemGuessIsInconclusiveAndPersistsNothing() {
        stubChangelogFound("changelog text");
        // A plain, unscoped/non-coordinate name — matches neither the npm @scope/name nor the
        // Maven group:artifact convention, and the CPE dictionary has nothing for it either.
        stubExtraction(new BundledComponentDto("SomeInternalTool", "3.0.0", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("SomeInternalTool"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(nvdVulnerabilitySource, osvLiveQueryClient, vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    @Test
    void npmScopedPackageNameTriggersAnOsvQuery() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("@babel/core", "7.24.0", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("@babel/core"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());

        VulnFinding finding = new VulnFinding(
                "GHSA-aaaa-bbbb-cccc", "osv", "MEDIUM", "desc", "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc", null);
        when(osvLiveQueryClient.queryPackage(eq("npm"), eq("@babel/core"), eq("7.24.0")))
                .thenReturn(SourceResult.success(List.of(finding)));
        when(vulnerabilityRepository.upsertAndGetId(
                eq("GHSA-aaaa-bbbb-cccc"), eq("osv"), any(), any(), any(), any()))
                .thenReturn(888L);

        int count = service().research(item(), USER_ID);

        assertThat(count).isEqualTo(1);
        verify(osvLiveQueryClient).queryPackage("npm", "@babel/core", "7.24.0");
        verify(jobItemVulnerabilityRepository).linkIfAbsentWithBundledComponent(
                eq(9L), eq(888L), eq("bundled_component"), any(), eq("@babel/core"), eq("7.24.0"));
    }

    @Test
    void mavenCoordinateTriggersAnOsvQueryWithTheMavenEcosystem() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("com.google.guava:guava", "32.1.0", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("com.google.guava:guava"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        when(osvLiveQueryClient.queryPackage(eq("Maven"), eq("com.google.guava:guava"), eq("32.1.0")))
                .thenReturn(SourceResult.success(List.of()));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verify(osvLiveQueryClient).queryPackage("Maven", "com.google.guava:guava", "32.1.0");
    }

    @Test
    void aFailedAdjudicationSourceContributesNoFindingsWithoutError() {
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("@scope/pkg", "1.2.3", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("@scope/pkg"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        when(osvLiveQueryClient.queryPackage(eq("npm"), eq("@scope/pkg"), eq("1.2.3")))
                .thenReturn(SourceResult.failure());

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(vulnerabilityRepository, jobItemVulnerabilityRepository);
    }

    // --- REVISE item 1: wide-pool + target_sw vendor disambiguation, measured against real data --

    @Test
    void wideCandidatePoolLetsTheCorrectVendorSurviveInsteadOfBeingTruncatedOutBeforeGating() {
        // Real measured shape (senior review, 2026-08-26): "openssl" collides with a Rust binding
        // (sfackler:openssl, target_sw=rust) sharing the same exact product slug. Only one candidate
        // (openssl:openssl) is target_sw=* — the gate leaves exactly one distinct vendor, so
        // adjudication proceeds normally rather than falling through to "inconclusive".
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("openssl", "3.2.1", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("openssl"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("openssl", "openssl", "*"),
                        cpeEntry("sfackler", "openssl", "rust")));

        VulnFinding finding = new VulnFinding(
                "CVE-2026-22222", "nvd", "CRITICAL", "openssl vuln", "https://nvd.nist.gov/vuln/detail/CVE-2026-22222", null);
        when(nvdVulnerabilitySource.fetchFromNvdCached(eq("cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*"), eq(USER_ID)))
                .thenReturn(SourceResult.success(List.of(finding)));
        when(vulnerabilityRepository.upsertAndGetId(eq("CVE-2026-22222"), eq("nvd"), any(), any(), any(), any()))
                .thenReturn(999L);

        int count = service().research(item(), USER_ID);

        assertThat(count).isEqualTo(1);
        verify(nvdVulnerabilitySource).fetchFromNvdCached(eq("cpe:2.3:a:openssl:openssl:3.2.1:*:*:*:*:*:*:*"), eq(USER_ID));
    }

    @Test
    void aTargetSwScopedVendorIsGatedOutEntirelyRatherThanMisattributingToItsBinding() {
        // Real measured shape: "curl" resolves in the raw dictionary to curl_project:curl scoped
        // target_sw=ruby (the Ruby binding, not native curl) — the only exact-slug candidate. With
        // no wildcard-scoped survivor at all, this must be gated out entirely (no CPE query issued),
        // not misattributed to the Ruby binding.
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("curl", "8.9.0", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("curl"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("curl_project", "curl", "ruby")));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(nvdVulnerabilitySource);
    }

    @Test
    void multipleSurvivingWildcardScopedVendorsAreTreatedAsInconclusiveRatherThanGuessed() {
        // Real measured shape: "zlib" has (at least) cloudflare/gnu/zlib all catalogued
        // target_sw=* under the exact same product slug — genuinely ambiguous even after the
        // target_sw gate. Per product direction (this is a triage feature, not an authoritative
        // one): no query is issued for any of them rather than guessing one.
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("zlib", "1.3.1", "high"));
        when(cpeDictionaryRepository.findFuzzyMatches(eq("zlib"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cloudflare", "zlib", "*"),
                        cpeEntry("gnu", "zlib", "*"),
                        cpeEntry("ruby-lang", "zlib", "ruby"),
                        cpeEntry("zlib", "zlib", "*")));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(nvdVulnerabilitySource);
    }

    @Test
    void aCandidateWithNoTargetSwValueAtAllIsGatedOutRatherThanTreatedAsAWildcard() {
        // A row with no target_sw signal at all (null set — never actually produced by
        // findFuzzyMatches for a bare-native-binary query in practice, but exercised here to pin
        // down the gate's behavior precisely) does not contain "*", so it does not pass the gate —
        // this is deliberately stricter than Stage1IdentificationService's own null-means-no-
        // signal-so-pass gate (see findCpeMatch's javadoc): the plan calls for keeping only
        // candidates whose target_sw set contains "*", not for treating an absent signal as one.
        stubChangelogFound("changelog text");
        stubExtraction(new BundledComponentDto("widgetlib", "2.0.0", "high"));
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setVendor("acme");
        entry.setProduct("widgetlib");
        entry.setCpeString("cpe:2.3:a:acme:widgetlib:1.0:*:*:*:*:*:*:*");
        // targetSwValues left null — never explicitly set.
        when(cpeDictionaryRepository.findFuzzyMatches(eq("widgetlib"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(entry));

        int count = service().research(item(), USER_ID);

        assertThat(count).isZero();
        verifyNoInteractions(nvdVulnerabilitySource);
    }

    // --- REVISE item 2: hard cap on candidates adjudicated per item ----------------------------

    @Test
    void truncatesToTheMaxComponentsPerItemCapRatherThanAdjudicatingEveryExtractedCandidate() {
        stubChangelogFound("changelog text");
        BundledComponentDto[] tooMany = new BundledComponentDto[BundledComponentResearchService.MAX_COMPONENTS_PER_ITEM + 5];
        for (int i = 0; i < tooMany.length; i++) {
            tooMany[i] = new BundledComponentDto("component" + i, "1.0." + i, "high");
        }
        stubExtraction(tooMany);
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());

        service().research(item(), USER_ID);

        verify(cpeDictionaryRepository, org.mockito.Mockito.times(BundledComponentResearchService.MAX_COMPONENTS_PER_ITEM))
                .findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt());
    }
}
