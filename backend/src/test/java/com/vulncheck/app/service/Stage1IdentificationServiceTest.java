package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.CpeDictionaryEntry;
import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.CpeDictionaryRepository;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.service.nvd.CpeNameVariantCache;
import com.vulncheck.app.service.registry.PackageRegistryLookup;
import com.vulncheck.app.service.registry.RegistryLookupCache;
import com.vulncheck.app.service.registry.RegistryMatch;
import com.vulncheck.app.service.registry.RegistryRoutingPolicy;
import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): every AI-tier scenario this suite used to
 * cover (Tier2 CPE/registry disambiguation, Tier3 web-search identification) was deleted along with
 * {@code LlmServiceClient}/{@code LlmServiceModels} and the AI call sites in {@link
 * Stage1AiArbitration}/{@link Stage1RegistryIdentification} themselves — those now always take the
 * exact fallback this suite already exercised for "no Claude key configured", which is the only
 * condition every real closed-mode job runs under now. Every remaining test here already asserted
 * that fallback outcome, so removing the (now nonexistent) API-key/LLM-response stubs is the only
 * change most of them needed.
 *
 * <p>Closed-mode backlog item 273 (B4): the live NVD CPE keyword-search fallback ({@code
 * liveNvdCpeLookupWithFallback}, {@code UserApiKeyService}/{@code NvdCpeSyncService} collaborators)
 * has since been physically deleted too. The 4 tests whose entire purpose was validating that live
 * path outright ({@code emptyLocalDictionaryFallsBackToLiveNvdCpeLookup}, {@code
 * reQueriesWithTheWordDroppedVariantThatActuallySucceededNotTheOriginalFullQuery}, {@code
 * nonEmptyLocalDictionaryNeverTriggersLiveNvdLookup}, {@code
 * variantSearchDoesNotSuppressLiveNvdFallbackForAKnownRealName}) were removed outright rather than
 * adapted; every other test that merely stubbed {@code nvdCpeSyncService.syncKeywordSinglePage} as
 * boilerplate (never asserting anything about it) had just that now-unneeded stub line dropped,
 * keeping its own actual assertions unchanged.
 */
@ExtendWith(MockitoExtension.class)
class Stage1IdentificationServiceTest {

    private static final Long USER_ID = 42L;

    @Mock
    private CpeDictionaryRepository cpeDictionaryRepository;

    @Mock
    private IdentifiedProductRepository identifiedProductRepository;

    @Mock
    private RegistryRoutingPolicy registryRoutingPolicy;

    @BeforeEach
    void routingPolicyIsAPassThroughByDefault() {
        // Every existing registry-fan-out test here was written before RegistryRoutingPolicy was
        // wired in and assumes every registry lookup it supplies actually gets called — so the
        // default stub is a no-op pass-through (route() returns whatever it was given), same as
        // "no routing at all". The one test that cares about routing itself overrides this.
        lenient().when(registryRoutingPolicy.route(any(), any()))
                .thenAnswer(invocation -> invocation.getArgument(1));
    }

    private ResearchJobItem item(String productName) {
        ResearchJobItem item = new ResearchJobItem();
        item.setId(1L);
        item.setJobId(1L);
        item.setProductName(productName);
        item.setVersion("1.0.0");
        item.setUsageText("internal tool");
        return item;
    }

    private Stage1IdentificationService service(List<PackageRegistryLookup> lookups) {
        // A fresh cache per test/service instance — no cross-test pollution, and every test here
        // only exercises one identify() call per item anyway, so the cache is never the thing
        // under test in this file (see RegistryLookupCacheTest / CpeNameVariantCacheTest for that).
        // Closed-mode B2 (docs/spec/closed-mode-plan.md §9-2): both collaborators below are now
        // gutted to an unconditional AI-unavailable fallback — see their own javadoc.
        HighConfidenceVerificationService highConfidenceVerificationService = new HighConfidenceVerificationService();
        Stage1RegistryIdentification registryIdentification = new Stage1RegistryIdentification(
                lookups, registryRoutingPolicy, new RegistryLookupCache());
        Stage1AiArbitration aiArbitration = new Stage1AiArbitration();
        return new Stage1IdentificationService(
                cpeDictionaryRepository, new CpeNameVariantCache(), identifiedProductRepository,
                highConfidenceVerificationService, registryIdentification, aiArbitration);
    }

    private void stubSaveReturnsArgument() {
        when(identifiedProductRepository.save(any(IdentifiedProduct.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    private CpeDictionaryEntry cpeEntry(String cpeString, String product) {
        CpeDictionaryEntry entry = new CpeDictionaryEntry();
        entry.setCpeString(cpeString);
        entry.setProduct(product);
        entry.setLastSyncedAt(OffsetDateTime.now());
        return entry;
    }

    @Test
    void tier3IsSkippedWithNoCandidatesAndNoApiKey() {
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("totally-unknown-thing"), USER_ID);

        assertThat(result).isEmpty();
    }

    @Test
    void routesRegistryLookupsThroughTheRoutingPolicyBeforeFanningOut() {
        // Fix 4 (senior review, 2026-08-26): RegistryRoutingPolicy was written (with a javadoc
        // describing real rate-limiter-wait savings) but never actually injected/called anywhere —
        // a "wired but never called" gap that's easy to silently reintroduce, so this specifically
        // guards that identify() routes through it before fanning out to every registry.
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.empty();
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());

        service(List.of(npmLookup)).identify(item("lodash"), USER_ID);

        verify(registryRoutingPolicy).route(eq("lodash"), eq(List.of(npmLookup)));
    }

    @Test
    void registryMatchSkipsNameVariantSearchWhenLocalDictionaryIsEmpty() {
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "express", "pkg:npm/express@4.18.2", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(npmLookup)).identify(item("express"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("npm");
        assertThat(result.get().getCpe()).isNull();
    }

    @Test
    void singleRegistryAndSingleCpeMatchAreMergedWithoutCallingLlm() {
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "lodash", "pkg:npm/lodash@4.17.15", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("cpe:2.3:a:lodash:lodash:0.1.0:*:*:*:*:*:*:*", "lodash")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(npmLookup)).identify(item("lodash"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getMethod()).isEqualTo(IdentifiedProduct.METHOD_STATIC);
        assertThat(result.get().getEcosystem()).isEqualTo("npm");
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:lodash:lodash:1.0.0:*:*:*:*:*:*:*");
        // Measurement-only provenance (docs/spec/task-backlog.md item 16): a lone, literal dictionary
        // match — exactly the "single candidate" path resolveCandidates records.
        assertThat(result.get().getCpeCandidateCount()).isEqualTo(1);
        assertThat(result.get().getCpeCandidateVariantDerived()).isFalse();
    }

    @Test
    void unconfirmedVersionRegistryMatchIsDistrustedWhenCpeCorroboratesADifferentProduct() {
        // A generic short product name can collide with an unrelated same-named npm package —
        // observed live for the real Java "gson" (Google) vs an unrelated npm "gson" package.
        // The npm match only confirms the package NAME, not this exact version (weak signal); the
        // CPE match confirms the real, specific product, so it should win outright — ecosystem/
        // packageName should NOT be set to the misleading npm match.
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "gson", "pkg:npm/gson@2.10.1", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("cpe:2.3:a:google:gson:2.10.0:*:*:*:*:*:*:*", "gson")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(npmLookup)).identify(item("gson"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isNull();
        assertThat(result.get().getPackageName()).isNull();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:google:gson:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void fallsBackToAnotherCpeCandidateWhenTheOnlyOneDiscardedByRegistryDistrustNeededItsEcosystemContext() {
        // Backlog item 176 (job 203 root-cause): an unconfirmed crates.io "OpenSSL" match (really the
        // unrelated Rust FFI binding crate sfackler:openssl) sits alongside the correct openssl:openssl
        // CPE candidate in the same pool. Before the registry match's trustworthiness is known,
        // resolveCpeCandidates ranks with crates.io's ecosystem context in play, which lets the
        // target_sw=rust candidate's targetSwMatchesEcosystem tie-break outrank the correct one (both
        // exact-slug-match "openssl"). The registry match is then correctly judged untrustworthy
        // (exactVersionConfirmed=false) and the wrongly-top-ranked CPE is correctly re-gated and
        // dropped for only surviving via that now-distrusted ecosystem context — but the other,
        // actually-correct candidate is still sitting right there in the same pool and independently
        // passes the bare (no-ecosystem) gate, so it must be picked up as a fallback instead of the
        // item going UNIDENTIFIED.
        PackageRegistryLookup cratesLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch(
                        "crates.io", "openssl", "pkg:cargo/openssl@0.10.55", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "crates.io";
            }
        };
        CpeDictionaryEntry correctOpenssl =
                cpeEntry("cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*", "openssl");
        CpeDictionaryEntry unrelatedRustBinding =
                cpeEntry("cpe:2.3:a:sfackler:openssl:0.10.55:*:*:*:*:rust:*:*", "openssl");
        unrelatedRustBinding.setTargetSwValues(java.util.Set.of("rust"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(unrelatedRustBinding, correctOpenssl));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("OpenSSL");
        item.setVersion("3.3.1");
        Optional<IdentifiedProduct> result = service(List.of(cratesLookup)).identify(item, USER_ID);

        assertThat(result).isPresent();
        // The distrusted registry match must not be attached — only the fallback CPE stands on its own.
        assertThat(result.get().getEcosystem()).isNull();
        assertThat(result.get().getPackageName()).isNull();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:openssl:openssl:3.3.1:*:*:*:*:*:*:*");
    }

    @Test
    void unconfirmedVersionRegistryMatchIsStillUsedWhenNoCpeCorroborationExists() {
        // Same weak signal as above, but with no CPE candidate at all — still the only signal
        // available, so it's used as a best-effort fallback (unchanged from prior behavior).
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "cobra", "pkg:npm/cobra@1.7.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(npmLookup)).identify(item("cobra"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("npm");
        assertThat(result.get().getPackageName()).isEqualTo("cobra");
    }

    @Test
    void unconfirmedRegistryMatchWithNonBlankVendorAndNoAiVerdictIsStaticallyRejected() {
        // REVISE item 3 (senior review 2026-08-26, job 38): an unconfirmed-version registry match
        // with a non-blank item vendor and no AI verdict available is statically rejected (measured
        // 14/14 wrong with a non-blank vendor vs 5/5 correct with a blank one).
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "slack", "pkg:npm/slack@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());

        ResearchJobItem item = item("Slack");
        item.setVendor("Slack Technologies");

        Optional<IdentifiedProduct> result = service(List.of(npmLookup)).identify(item, USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void implausibleCpeMatchIsRejectedDespitePassingTheSimilarityThreshold() {
        // Real case observed live: querying "Python Extension Pack for Visual Studio Code" scored
        // 0.59 product-similarity (past the 0.3 pg_trgm threshold) against the unrelated CPE for
        // Microsoft's ESLint VS Code extension, purely from sharing generic words ("visual",
        // "studio", "code", "extension"). Neither string actually contains the other's
        // distinguishing word ("python" / "eslint"), so the containment post-filter must reject it
        // — leaving the item UNIDENTIFIED (no registry match, no API key to try Tier3) rather than
        // silently persisting a wrong CPE.
        CpeDictionaryEntry unrelatedEslintExtension =
                cpeEntry("cpe:2.3:a:microsoft:visual_studio_code_eslint_extension:1.7.0:*:*:*:*:*:*:*",
                        "visual_studio_code_eslint_extension");
        unrelatedEslintExtension.setTitle("Microsoft ESLint 1.7.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(unrelatedEslintExtension));

        Optional<IdentifiedProduct> result =
                service(List.of()).identify(item("Python Extension Pack for Visual Studio Code"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAMatchThatOnlyOverlapsOnTheVendorWordNotTheProductName() {
        // Real bug found live 2026-08-24: a real (if low-quality) NVD CPE entry exists for vendor
        // "mozilla" / product literally "mozilla" (title "Mozilla Mozilla"). Querying e.g. "Mozilla
        // Zoom" or "Mozilla echo" — an unrelated product that merely happens to have "Mozilla" as
        // its vendor — matched this entry purely because the *vendor* word was contained in the
        // candidate; the containment filter never actually checked the product name ("Zoom"/
        // "echo") against anything. 94 items across two live test jobs ended up misidentified as
        // generic "Mozilla Mozilla" this way. The containment check must require the *product
        // name* itself to share text with the candidate, not just the vendor prefix.
        CpeDictionaryEntry genericMozillaEntry = cpeEntry("cpe:2.3:a:mozilla:mozilla:-:*:*:*:*:*:*:*", "mozilla");
        genericMozillaEntry.setTitle("Mozilla Mozilla");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(genericMozillaEntry));

        ResearchJobItem zoomItem = item("Zoom");
        zoomItem.setVendor("Mozilla");
        Optional<IdentifiedProduct> result = service(List.of()).identify(zoomItem, USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsANarrowerCandidateWhoseLeftoverQueryWordsTheCpeVendorDoesNotExplain() {
        // Measured on jobs 30/31/32 (2026-08-25), after the dictionary grew from 1,791 entries to
        // the full 1,815,263: NVD catalogues Docker Desktop as vendor "docker", product "desktop",
        // and the old symmetric substring check therefore matched *every* product whose name ends
        // in "Desktop" — GitHub Desktop, Power BI Desktop and Tableau Desktop all came back as
        // docker:desktop. What separates the one correct case from the three wrong ones is whether
        // the leftover word is the CPE vendor.
        CpeDictionaryEntry dockerDesktop = cpeEntry("cpe:2.3:a:docker:desktop:4.0.0:*:*:*:*:*:*:*", "desktop");
        dockerDesktop.setTitle("Docker Desktop 4.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(dockerDesktop));

        assertThat(service(List.of()).identify(item("GitHub Desktop"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void stillAcceptsANarrowerCandidateWhenTheLeftoverWordIsTheCpeVendor() {
        // The other half of the rule above: "Docker Desktop" must keep resolving to docker:desktop.
        CpeDictionaryEntry dockerDesktop = cpeEntry("cpe:2.3:a:docker:desktop:4.0.0:*:*:*:*:*:*:*", "desktop");
        dockerDesktop.setTitle("Docker Desktop 4.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(dockerDesktop));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("Docker Desktop"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:docker:desktop:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void rejectsACandidateThatOnlyOverlapsMidWordWithNoTokenBoundary() {
        // Also measured live: "failureaccess" (a Guava artifact) matched microsoft:access, "javapoet"
        // matched ibm:java, and "guice" matched sap:gui — the last one at 0.95 confidence, because a
        // confirmed Maven registry hit lent its confidence to a CPE picked by this unrelated
        // substring overlap. Requiring whole-token alignment removes the entire class.
        CpeDictionaryEntry microsoftAccess = cpeEntry("cpe:2.3:a:microsoft:access:2016:*:*:*:*:*:*:*", "access");
        microsoftAccess.setTitle("Microsoft Access 2016");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(microsoftAccess));

        assertThat(service(List.of()).identify(item("failureaccess"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void onlyLeadingLeftoverWordsAreHeldAgainstACandidateNotTrailingOnes() {
        // Counterpart to the two tests above: only words *ahead of* the match have to be explained,
        // because the head of a name is what identifies it. "IntelliJ IDEA Community Edition" starts
        // with the product itself, so the trailing edition words are descriptive and must not veto
        // the match — as opposed to "GitHub Desktop", where the unexplained word comes first.
        // Deliberately no curated stop-word list: it would have to grow forever, and every word it
        // omitted would silently lose a real product.
        CpeDictionaryEntry intellij =
                cpeEntry("cpe:2.3:a:jetbrains:intellij_idea:2023.1:*:*:*:*:*:*:*", "intellij_idea");
        intellij.setTitle("JetBrains IntelliJ IDEA 2023.1");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(intellij));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result =
                service(List.of()).identify(item("IntelliJ IDEA Community Edition"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:jetbrains:intellij_idea:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void searchesTheCpeDictionaryByProductNameAloneNeverVendorPrefixed() {
        // Root cause of a whole class of misses found live 2026-08-24: the dictionary search used
        // to be issued as "<vendor> <productName>". Measured against the real dictionary, for
        // "Amazon Web Services TeamViewer" the vendor words scored amazon_web_services_aws-c-io at
        // 0.51 and amazon_web_services_freertos at 0.50, while the genuinely correct `teamviewer`
        // scored only 0.35 — so the true product was pushed out of the candidate window entirely
        // and the item came back UNIDENTIFIED despite TeamViewer being present in the dictionary.
        // The vendor must never enter the query text; it is only a re-ranking signal.
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());

        ResearchJobItem item = item("TeamViewer");
        item.setVendor("Amazon Web Services");
        service(List.of()).identify(item, USER_ID);

        verify(cpeDictionaryRepository).findFuzzyMatches(eq("TeamViewer"), anyDouble(), anyDouble(), anyInt());
        verify(cpeDictionaryRepository, never())
                .findFuzzyMatches(eq("Amazon Web Services TeamViewer"), anyDouble(), anyDouble(), anyInt());
    }

    @Test
    void collapsesVersionDuplicateRowsSoOneProductDoesNotFillTheCandidateWindow() {
        // The dictionary stores one row per catalogued version — 72.7% of the real NVD dictionary's
        // 1.8M rows are version duplicates, and a single product (TeamViewer) can hold dozens.
        // Three rows of the SAME vendor:product must count as one candidate, not three, otherwise
        // the window meant for "the best distinct products" is wasted on near-identical rows (and
        // Tier2 would be asked to disambiguate a product from itself).
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cpe:2.3:a:teamviewer:teamviewer:11.0:*:*:*:*:*:*:*", "teamviewer"),
                        cpeEntry("cpe:2.3:a:teamviewer:teamviewer:10.0:*:*:*:*:*:*:*", "teamviewer"),
                        cpeEntry("cpe:2.3:a:teamviewer:teamviewer:9.0:*:*:*:*:*:*:*", "teamviewer")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("TeamViewer"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:teamviewer:teamviewer:1.0.0:*:*:*:*:*:*:*");
        // Collapsed to a single candidate, so this is the unambiguous path — no AI spend at all.
    }

    @Test
    void promotesTheCandidateWhoseCpeVendorAgreesWithTheUserSuppliedVendor() {
        // Vendor is a weak ranking signal rather than query text: among otherwise-plausible
        // same-named products, the one whose CPE vendor matches what the user typed should win,
        // without a vendor mismatch ever hard-rejecting a candidate (real vendor columns are often
        // blank, a reseller, or a parent company rather than the CPE vendor slug).
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cpe:2.3:a:someoneelse:widget:1.0:*:*:*:*:*:*:*", "widget"),
                        cpeEntry("cpe:2.3:a:acme:widget:2.0:*:*:*:*:*:*:*", "widget")));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("widget");
        item.setVendor("Acme");
        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:acme:widget:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void ambiguousCpeCandidatesWithNoApiKeyDegradeToFirstCandidate() {
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cpe:2.3:a:apache:apache_http_server:2.4:*:*:*:*:*:*:*", "apache_http_server"),
                        cpeEntry("cpe:2.3:a:apache:apache_tomcat:9.0:*:*:*:*:*:*:*", "apache_tomcat")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("apache"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:apache:apache_http_server:1.0.0:*:*:*:*:*:*:*");
        // Measurement-only provenance (docs/spec/task-backlog.md item 16): no-arbitration path —
        // multiple candidates, but no AI call at all, so the first is picked without judging between them.
        assertThat(result.get().getCpeCandidateCount()).isEqualTo(2);
        assertThat(result.get().getCpeCandidateVariantDerived()).isFalse();
    }

    @Test
    void relaxedContainmentDerivedMultiCandidatesWithNoApiKeyAreDroppedRatherThanTakingTheFirst() {
        // REVISE item 1 (senior review, PR #51): a backlog item 89 P2 relaxed-containment-derived
        // candidate pool is exactly as unverified a mechanical guess as a lone name-variant
        // candidate — with no Claude key configured (today's real operating condition, see the
        // PR's own root-cause note: the API credit is exhausted so apiKey.isPresent() is false for
        // every real job), the pre-existing "no AI verdict -> take cpeCandidates.get(0)" fallback
        // silently trusted whichever candidate happened to sort first among several unrelated
        // vendors. "Android Studio" against google:android/motorola:android/samsung:android is the
        // real control-row false positive this fixes: the strict containment pass rejects all
        // three (their trailing "studio" token isn't vendor-explained by google/motorola/samsung),
        // so the relaxed second pass is what actually produced this pool.
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cpe:2.3:a:google:android:1.0:*:*:*:*:*:*:*", "android"),
                        cpeEntry("cpe:2.3:a:motorola:android:1.0:*:*:*:*:*:*:*", "android"),
                        cpeEntry("cpe:2.3:a:samsung:android:1.0:*:*:*:*:*:*:*", "android")));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("Android Studio"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void strictContainmentDerivedMultiCandidatesStillDegradeToFirstCandidateWithNoApiKey() {
        // Regression companion to the two relaxed-pass tests above (REVISE item 1, PR #51): a
        // strict-containment-derived pool (the common case — plausibleContainmentOnly's first pass
        // already succeeded) must keep the pre-existing "no AI verdict -> take get(0)" behavior
        // exactly as before. "PDF-XChange" against two same-vendor products is a real strict-pass
        // multi-candidate case (neither needed the relaxed second pass to be admitted).
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(
                        cpeEntry("cpe:2.3:a:tracker-software:pdf-xchange_editor:9.0:*:*:*:*:*:*:*", "pdf-xchange_editor"),
                        cpeEntry("cpe:2.3:a:tracker-software:pdf-xchange_viewer:2.5:*:*:*:*:*:*:*", "pdf-xchange_viewer")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("PDF-XChange"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:tracker-software:pdf-xchange_editor:1.0.0:*:*:*:*:*:*:*");
        assertThat(result.get().getCpeCandidateCount()).isEqualTo(2);
    }

    @Test
    void nameVariantDerivedMultiCandidatesStillDegradeToFirstCandidateWithNoApiKey() {
        // Regression companion to the relaxed-pass tests above (REVISE item 1, PR #51): a
        // name-variant-derived pool (backlog item 98, evaluated separately) must be left completely
        // untouched by this fix — relaxedContainmentDerived is false for it, so the pre-existing
        // "no AI verdict -> take get(0)" behavior applies exactly as before, even with more than one
        // variant-search candidate.
        CpeDictionaryEntry vlcMediaPlayer =
                cpeEntry("cpe:2.3:a:videolan:vlc_media_player:3.0.0:*:*:*:*:*:*:*", "vlc_media_player");
        // Also satisfies expandLeadingInitialism's own leadingInitialsMatch check ("player" as the
        // anchor, preceded by tokens whose initials spell "vm") — a second, genuinely-admitted
        // variant-search candidate, not just a second row in the mocked repository response.
        CpeDictionaryEntry otherVariantGuess =
                cpeEntry("cpe:2.3:a:acme:video_manager_player:1.0.0:*:*:*:*:*:*:*", "video_manager_player");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        when(cpeDictionaryRepository.findByLeadingInitialismMatch(anyString(), anyString(), anyInt()))
                .thenReturn(List.of(vlcMediaPlayer, otherVariantGuess));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("VM Player"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:videolan:vlc_media_player:1.0.0:*:*:*:*:*:*:*");
        assertThat(result.get().getCpeCandidateCount()).isEqualTo(2);
        assertThat(result.get().getCpeCandidateVariantDerived()).isTrue();
    }

    @Test
    void ambiguousRegistryCandidatesWithNoApiKeyDegradeToMaxConfidenceMatch() {
        // Same generic-name-collision shape as the CPE Tier2 candidates, but across two different
        // registries — previously this silently took whichever registry client happened to be
        // injected first on a tie, or the max-confidence one otherwise, with no AI arbitration at
        // all (unlike CPE Tier2). No key configured degrades to that same pre-existing behavior.
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "commons-io", "pkg:npm/commons-io@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        PackageRegistryLookup mavenLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("maven", "commons-io:commons-io", "pkg:maven/commons-io/commons-io@1.0.0",
                        new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "maven";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(npmLookup, mavenLookup)).identify(item("commons-io"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("maven");
    }

    @Test
    void usageTextTieBreakDoesNotMisfireOnJavaScriptSubstringMatchingJava() {
        // REVISE item 2 (senior review 2026-08-29, round 1): ECOSYSTEM_USAGE_TEXT_KEYWORDS used plain
        // String::contains, so maven's "java" keyword substring-matched inside "javascript",
        // falsely tagging an npm/Node usage_text as also mentioning maven. That pollutes the
        // usage-text-narrowed set to more than one ecosystem (npm genuinely, maven only via the
        // substring bug), which defeats maxConfidenceMatch's tie-break (it only overrides the
        // default pick when usage_text narrows a tie down to EXACTLY one ecosystem) and falls back
        // to whichever tied registry match happened to be listed/queried first — maven here, since
        // it's registered before npm below. With word-boundary-aware matching, "javascript" no
        // longer falsely matches "java", so only npm's real "node" keyword hit narrows the tie, and
        // npm — the actually correct ecosystem for this usage_text — wins deterministically instead
        // of by accidental list order.
        PackageRegistryLookup mavenLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("maven", "widget:widget", "pkg:maven/widget/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "maven";
            }
        };
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "widget", "pkg:npm/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        ResearchJobItem item = item("widget");
        item.setUsageText("used as a JavaScript library in a Node project");

        Optional<IdentifiedProduct> result = service(List.of(mavenLookup, npmLookup)).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("npm");
    }

    @Test
    void tiedRegistryCandidatesWithNoApiKeyAreTieBrokenByUsageTextEcosystemKeyword() {
        // golden-300 fix (2026-08-29, item 2 "cross-registry same-name collision"): with no AI
        // arbitration available, two equally-confident same-named registry matches used to fall
        // back to a blind max-confidence pick with no other signal — item.usage_text was already
        // stored but never consulted. numpy/jekyll/redis/phoenix/phoenix_live_view/http were all
        // mis-routed this way in golden-300. Both candidates here are unconfirmed at the same 0.5
        // confidence (a genuine tie), and usage_text unambiguously names pypi.
        PackageRegistryLookup pypiLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("pypi", "widget", "pkg:pypi/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "pypi";
            }
        };
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "widget", "pkg:npm/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        ResearchJobItem item = item("widget");
        item.setUsageText("installed via pip install widget for our Python data pipeline");

        Optional<IdentifiedProduct> result = service(List.of(pypiLookup, npmLookup)).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("pypi");
    }

    @Test
    void tiedRegistryCandidatesWithNoUsageTextEcosystemSignalKeepTheOriginalMaxConfidencePick() {
        // Control for the fix above: usage_text mentioning no configured ecosystem keyword (or
        // mentioning more than one) must leave the original, unchanged degrade-to-max-confidence
        // behavior in place — this is a narrow tie-break, not a general re-ranking of registry
        // matches by usage_text.
        PackageRegistryLookup pypiLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("pypi", "widget", "pkg:pypi/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "pypi";
            }
        };
        PackageRegistryLookup npmLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "widget", "pkg:npm/widget@1.0.0", new BigDecimal("0.5"), false));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt())).thenReturn(List.of());
        stubSaveReturnsArgument();

        ResearchJobItem item = item("widget");
        item.setUsageText("a small internal utility, no further detail recorded");

        Optional<IdentifiedProduct> result = service(List.of(pypiLookup, npmLookup)).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("pypi");
    }

    @Test
    void theInitialismExpansionSearchRejectsAnAnchorMatchWhoseLeadingWordsDoNotSpellTheAbbreviation() {
        // Guards the new candidate-generation path against reintroducing the exact false-positive
        // shape prior sessions already fixed for containment matching (see
        // rejectsANarrowerCandidateWhoseLeftoverQueryWordsTheCpeVendorDoesNotExplain): the anchor
        // word alone ("desktop") matching is not enough. NVD catalogues Docker Desktop with
        // product slug literally "desktop" (vendor "docker" lives in a separate CPE field, never
        // inside the product token sequence at all) — so there are zero leading words within the
        // product slug for the query's "vs" to explain, and this must be rejected rather than
        // guessed, exactly like a real query with nothing before the anchor at all. Kept as a
        // Java-level safety net (see item 4 in the senior review) even though the SQL query itself
        // is now far more targeted than a plain anchor-substring scan.
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        CpeDictionaryEntry dockerDesktop = cpeEntry("cpe:2.3:a:docker:desktop:4.0.0:*:*:*:*:*:*:*", "desktop");
        when(cpeDictionaryRepository.findByLeadingInitialismMatch(eq("vs"), eq("desktop"), anyInt()))
                .thenReturn(List.of(dockerDesktop));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("VS Desktop"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void acronymContractionRequiresAnExactProductSlugMatchNotJustContainment() {
        // Item 3 requirement (senior review, 2026-08-25): the contraction direction must not accept
        // a candidate merely because its product slug *contains* the acronym — routing an acronym
        // query through the general containment check produced real false positives (e.g.
        // "animal-sniffer-annotations" -> pix_asa). Only an exact product-slug match is trusted.
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        CpeDictionaryEntry gimpExtension =
                cpeEntry("cpe:2.3:a:someone:gimp_extension_pack:1.0.0:*:*:*:*:*:*:*", "gimp_extension_pack");
        when(cpeDictionaryRepository.findFuzzyMatches(eq("gimp"), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(gimpExtension));

        Optional<IdentifiedProduct> result =
                service(List.of()).identify(item("GNU Image Manipulation Program"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void aLoneNameVariantDerivedCpeCandidateIsDroppedRatherThanAutoAcceptedWithNoApiKey() {
        // Item 1 requirement (senior review, 2026-08-25): a single variant-derived candidate must
        // never be auto-accepted the way a single literal-match candidate is — with no Claude key
        // configured, today's real-world baseline (UNIDENTIFIED) must be preserved. "VM Player"
        // spelling the same leading initials as "VLC Media Player" purely by coincidence is a real
        // false positive the expansion direction's initials check has no way to tell apart on text
        // alone — the fix is that this can no longer be trusted with zero verification.
        CpeDictionaryEntry vlcMediaPlayer =
                cpeEntry("cpe:2.3:a:videolan:vlc_media_player:3.0.0:*:*:*:*:*:*:*", "vlc_media_player");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of());
        when(cpeDictionaryRepository.findByLeadingInitialismMatch(anyString(), anyString(), anyInt()))
                .thenReturn(List.of(vlcMediaPlayer));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("VM Player"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void acronymContractionNeverMatchesAnUnrelatedShortSlugForAnimalSnifferAnnotations() {
        // Measured false positive (senior review, 2026-08-25): the acronym/contraction direction
        // routed through plausibleContainmentOnly's unanchored substring check, which is unsafe for
        // a 3-letter query — "animal-sniffer-annotations" contracted to a 3-letter acronym that
        // matched this unrelated product. Every repository entry point is broadly stubbed here (not
        // just the one call site the mechanism is currently known to use) so this test fails for a
        // real precision regression regardless of internal call shape.
        CpeDictionaryEntry wrongMatch = cpeEntry("cpe:2.3:a:someunrelatedvendor:pix_asa:1.0.0:*:*:*:*:*:*:*", "pix_asa");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(wrongMatch));
        when(cpeDictionaryRepository.findByLeadingInitialismMatch(anyString(), anyString(), anyInt()))
                .thenReturn(List.of(wrongMatch));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("animal-sniffer-annotations"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void contractionDirectionNeverGeneratesACandidateForAThreeMeaningfulWordProductName() {
        // Measured false positive (senior review, 2026-08-25): "org.projectlombok:lombok"
        // contracted to a 3-letter acronym that collided with an unrelated product ("oplynx").
        // Raising the meaningful-token floor from 3 to 4 removes the acronym-contraction attempt
        // entirely for this input; every repository entry point is broadly stubbed to return the
        // wrong candidate regardless of which path is queried, so the rejection is demonstrated to
        // be real rather than just a lucky stub shape.
        CpeDictionaryEntry oplynx = cpeEntry("cpe:2.3:a:someunrelatedvendor:oplynx:1.0.0:*:*:*:*:*:*:*", "oplynx");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(oplynx));
        when(cpeDictionaryRepository.findByLeadingInitialismMatch(anyString(), anyString(), anyInt()))
                .thenReturn(List.of(oplynx));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("org.projectlombok:lombok"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsATitleMatchThatOnlyReachesTheEntrysOwnLeadingVendorWord() {
        // Fix 2 (senior review, 2026-08-26): "slack" matched a completely unrelated WordPress
        // plugin, jenkins:slack/slack:wp_slacksync, purely because the old fast path was a raw,
        // unconstrained substring check against entry.getTitle() ("Slack WP SlackSync for
        // WordPress") — NVD titles are "Vendor Product Version" strings, so the query trivially
        // substring-matched the title's own leading vendor word without saying anything about the
        // actual product. Neither the product slug ("wp_slacksync") nor the title's *product*
        // portion (everything after "Slack") shares a token-boundary-aligned match with "slack".
        CpeDictionaryEntry wpSlackSync = cpeEntry("cpe:2.3:a:slack:wp_slacksync:1.0.0:*:*:*:*:*:*:*", "wp_slacksync");
        wpSlackSync.setTitle("Slack WP SlackSync for WordPress 1.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(wpSlackSync));

        assertThat(service(List.of()).identify(item("slack"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAMidWordSubstringEvenWhenItIsALiteralPrefixOfTheCandidateToken() {
        // "rayon" matched crayon_project:crayon live — "crayon" contains "rayon" as a raw substring
        // (c-RAYON) starting mid-token, not at a token boundary, so the old unconstrained fast path
        // accepted it. The candidate's single token is "crayon", which is not equal to "rayon" and
        // cannot be built by concatenating whole candidate tokens either.
        CpeDictionaryEntry crayon = cpeEntry("cpe:2.3:a:crayon_project:crayon:2.0.0:*:*:*:*:*:*:*", "crayon");
        crayon.setTitle("Crayon Project Crayon 2.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(crayon));

        assertThat(service(List.of()).identify(item("rayon"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAShortQueryThatOnlyMatchesTheSecondWordOfACandidateTitle() {
        // "puma" matched intel:puma live via the title path ("Intel Puma") — the query is not the
        // *leading* word of either the product slug or the title, so it must not be accepted just
        // because it appears somewhere inside a longer string.
        CpeDictionaryEntry intelPuma = cpeEntry("cpe:2.3:a:intel:puma6_chipset_driver:1.0.0:*:*:*:*:*:*:*",
                "puma6_chipset_driver");
        intelPuma.setTitle("Intel Puma 6 Chipset Drivers 1.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(intelPuma));

        assertThat(service(List.of()).identify(item("puma"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAQueryThatOnlyMatchesAfterStrippingALeadingHyphenatedPrefix() {
        // "log" matched siemens:logo! live — "logo!" starts with "log" but the leftover "o" is not
        // a whole extra token, just a mid-token remainder, so this must be rejected the same way as
        // the crayon/rayon case above.
        CpeDictionaryEntry siemensLogo = cpeEntry("cpe:2.3:a:siemens:logo:8.0:*:*:*:*:*:*:*", "logo!");
        siemensLogo.setTitle("Siemens LOGO! Logic Module 8.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(siemensLogo));

        assertThat(service(List.of()).identify(item("log"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAQueryThatOnlyMatchesTheTailTokenOfAHyphenatedCandidate() {
        // "get" matched a candidate literally named "set-or-get" live — the match is at the *tail*
        // of the candidate, not the head, so requiring alignment to start at the candidate's first
        // token rejects it even though "get" is a genuine whole token somewhere inside.
        CpeDictionaryEntry setOrGet = cpeEntry("cpe:2.3:a:acme:set-or-get:2.0.0:*:*:*:*:*:*:*", "set-or-get");
        setOrGet.setTitle("Acme Set-Or-Get Utility 2.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(setOrGet));

        assertThat(service(List.of()).identify(item("get"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsAShortGenericQueryEmbeddedMidWordInAnUnrelatedCandidate() {
        // Same false-positive class as rayon/log/get above, chosen independently: "art" is a
        // literal substring of "smart_hub" (sm-ART-_hub) but not a token-boundary-aligned prefix
        // match, so it must be rejected too.
        CpeDictionaryEntry smartHub = cpeEntry("cpe:2.3:a:acme:smart_hub:1.0.0:*:*:*:*:*:*:*", "smart_hub");
        smartHub.setTitle("Acme Smart Hub 1.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(smartHub));

        assertThat(service(List.of()).identify(item("art"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void acceptsAMultiTokenQueryThatAlignsAtANonLeadingCandidateTokenBoundary() {
        // REVISE item 2 (senior review, job 36): "Process Monitor" is a real, previously-working
        // match against sysinternals_process_monitor that Fix 2's index-0-only alignPrefix
        // anchoring silently broke (a regression, not a new gap) — the query's two tokens line up
        // against the *tail* of the candidate's product slug, not its head. Must be re-accepted, but
        // only because the query itself has two tokens (see the rayon/log/get tests above, all of
        // which must stay rejected precisely because they're single-token queries).
        //
        // REVISE item 4 (senior review, job 37 root-cause): the leftover candidate token
        // ("sysinternals") preceding the aligned run must now be explained by the *item's own*
        // vendor field, not the CPE's own vendor — so this item must set one explicitly.
        CpeDictionaryEntry processMonitor = cpeEntry(
                "cpe:2.3:a:microsoft:sysinternals_process_monitor:3.94:*:*:*:*:*:*:*", "sysinternals_process_monitor");
        processMonitor.setTitle("Microsoft Sysinternals Process Monitor 3.94");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(processMonitor));
        stubSaveReturnsArgument();

        ResearchJobItem processMonitorItem = item("Process Monitor");
        processMonitorItem.setVendor("Microsoft Sysinternals");
        Optional<IdentifiedProduct> result = service(List.of()).identify(processMonitorItem, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe())
                .isEqualTo("cpe:2.3:a:microsoft:sysinternals_process_monitor:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void acceptsTwoQueryTokensThatConcatenateToMatchASingleCandidateToken() {
        // Fix 2 needs concatenation awareness in the *accepting* direction too: "WinRAR" as a query
        // is sometimes split "Win Rar" (two tokens) while the dictionary's own product slug is the
        // single unsplit token "winrar" — the old raw-substring check failed this (there's a space
        // in the query that isn't in the candidate), and a naive whole-token-only check would also
        // fail it, so this must specifically exercise the token-concatenation grouping.
        CpeDictionaryEntry winrar = cpeEntry("cpe:2.3:a:rarlab:winrar:6.11:*:*:*:*:*:*:*", "winrar");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(winrar));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("Win Rar"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:rarlab:winrar:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void acceptsTwoQueryTokensThatConcatenateToMatchASingleCandidateTokenForWampServer() {
        CpeDictionaryEntry wampServer = cpeEntry("cpe:2.3:a:acmeforge:wampserver:3.3.0:*:*:*:*:*:*:*", "wampserver");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(wampServer));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("WAMP Server"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:acmeforge:wampserver:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void goModulePathsNeverResolveToTheGenericVcsHostCpeEvenWhenOneExistsInTheDictionary() {
        // Fix 3 (senior review, 2026-08-26): "github.com/gin-gonic/gin" resolved to the generic,
        // wrong github:github CPE live, because the host component ("github", "com") leaked into
        // containment matching and anchored on a near-universal vendor:vendor entry NVD really does
        // catalog. Every one of these real Go module paths from job 35 must never pick up that same
        // wrong CPE — either a genuinely matching CPE (not present in this dictionary stub) or
        // nothing at all, never github:github.
        CpeDictionaryEntry genericGithub = cpeEntry("cpe:2.3:a:github:github:1.0.0:*:*:*:*:*:*:*", "github");
        genericGithub.setTitle("GitHub GitHub 1.0.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(genericGithub));

        List<String> goModulePaths = List.of(
                "github.com/gin-gonic/gin",
                "github.com/spf13/cobra",
                "github.com/spf13/viper",
                "github.com/google/uuid",
                "github.com/aws/aws-sdk-go",
                "github.com/gorilla/mux",
                "github.com/go-redis/redis/v9");

        for (String modulePath : goModulePaths) {
            Optional<IdentifiedProduct> result = service(List.of()).identify(item(modulePath), USER_ID);
            assertThat(result)
                    .as("module path '%s' must never resolve to the generic github:github CPE", modulePath)
                    .isEmpty();
        }
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void goModulePathHostStrippingStillAllowsAGenuinelyMatchingCandidateThrough() {
        // The other half of Fix 3: stripping the leading host must not become "Go module paths
        // never match anything" — a real CPE for the module's own path segment ("gin") must still
        // resolve once the non-identity-bearing host prefix is out of the way.
        CpeDictionaryEntry gin = cpeEntry("cpe:2.3:a:gin-gonic:gin:1.9.1:*:*:*:*:*:*:*", "gin");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(gin));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result =
                service(List.of()).identify(item("github.com/gin-gonic/gin"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:gin-gonic:gin:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void dropsAMismatchedCpeThatRodeAlongOnATrustedRegistryMatchsConfidence() {
        // Fix 5 (senior review, 2026-08-26): a CPE candidate only ever had to explain the item's
        // *query* text to become chosenCpe, never the specific package a trusted registry match
        // actually resolved to — which can legitimately differ (here: the registry search landed on
        // a different-but-same-queried package than the CPE dictionary hit). Measured live: "rayon"
        // -> crayon_project:crayon rode along on a trusted registry match's 0.95 confidence this
        // way. The CPE must be dropped (cpe=null) without touching the registry match's own
        // ecosystem/package/confidence at all — this is *not* "never attach a CPE when a registry
        // match exists" (see the accompanying positive-case test).
        PackageRegistryLookup registryLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                // The registry's own resolved package name ("rayon") deliberately differs from what
                // the CPE dictionary matched ("crayon") — a real registry match found this crate,
                // exact version confirmed, so it's trusted independently of the CPE below.
                return Optional.of(new RegistryMatch("cargo", "rayon", "pkg:cargo/rayon@1.9.0", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "cargo";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("cpe:2.3:a:crayon_project:crayon:1.0.0:*:*:*:*:*:*:*", "crayon")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(registryLookup)).identify(item("crayon"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isNull();
        assertThat(result.get().getEcosystem()).isEqualTo("cargo");
        assertThat(result.get().getPackageName()).isEqualTo("rayon");
        assertThat(result.get().getConfidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void keepsACpeThatIndependentlyCorroboratesTheTrustedRegistryMatchsOwnPackageName() {
        // The other half of Fix 5: when the CPE genuinely does explain the registry match's own
        // package name, it must still be attached — this must not regress into "never attach a CPE
        // when a registry match exists".
        PackageRegistryLookup registryLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("npm", "gson", "pkg:npm/gson@1.0.0", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "npm";
            }
        };
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(cpeEntry("cpe:2.3:a:google:gson:2.10.1:*:*:*:*:*:*:*", "gson")));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(registryLookup)).identify(item("gson"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:google:gson:1.0.0:*:*:*:*:*:*:*");
        assertThat(result.get().getEcosystem()).isEqualTo("npm");
        assertThat(result.get().getConfidence()).isEqualByComparingTo("0.95");
    }

    @Test
    void rejectsAPlatformScopedCpeWhenTheItemHasNoRegistryMatchAtAll() {
        // REVISE item 1 (senior review, job 36 root-cause): "Slack" (the desktop chat app) matched
        // jenkins:slack live — NVD's real entry for "Jenkins Slack Notification plugin for
        // Jenkins" (target_sw=jenkins), not Slack itself. There is no registry ecosystem here at
        // all (desktop software), so the stricter gate applies: a candidate whose entire target_sw
        // set is platform-scoped (no "*"/"-" present anywhere in it) can never be this standalone
        // item's own identity and must be hard-rejected, falling through to UNIDENTIFIED rather than
        // a lower-ranked candidate.
        CpeDictionaryEntry jenkinsSlack = cpeEntry("cpe:2.3:a:jenkins:slack:1.0:*:*:*:*:jenkins:*:*", "slack");
        jenkinsSlack.setTitle("Jenkins Slack Notification Plugin for Jenkins 1.0");
        jenkinsSlack.setTargetSwValues(java.util.Set.of("jenkins"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(jenkinsSlack));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("Slack"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void prefersACpeWhoseTargetSwMatchesTheItemsOwnEcosystemOverAMismatchedCandidate() {
        // REVISE item 3 (senior review, job 36 root-cause): rubygems "puma" must prefer the real
        // puma:puma gem CPE over an unrelated, differently-vendored "puma" CPE that isn't scoped to
        // ruby at all — vendor agreement alone can't distinguish them (the item's vendor field is
        // blank here, the common real-world case for a bare package name), so the target_sw
        // preference (positioned ahead of vendorAgrees in rankCpeCandidates) has to be what decides
        // it. No Claude key configured so the ambiguous-candidate path deterministically takes the
        // top-ranked candidate without an LLM call, making the ranking outcome directly observable.
        PackageRegistryLookup rubyGemsLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("rubygems", "puma", "pkg:gem/puma@5.6.0", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "rubygems";
            }
        };
        CpeDictionaryEntry rubyPuma = cpeEntry("cpe:2.3:a:puma:puma:5.6.0:*:*:*:*:ruby:*:*", "puma");
        rubyPuma.setTargetSwValues(java.util.Set.of("ruby"));
        CpeDictionaryEntry unrelatedPuma = cpeEntry("cpe:2.3:a:othervendor:puma:1.0.0:*:*:*:*:*:*:*", "puma");
        unrelatedPuma.setTargetSwValues(java.util.Set.of("*"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(unrelatedPuma, rubyPuma));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(rubyGemsLookup)).identify(item("puma"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:puma:puma:1.0.0:*:*:*:*:ruby:*:*");
    }

    @Test
    void exactProductSlugMatchOutranksATargetSwMatchingButDifferentlyNamedCandidate() {
        // REVISE item 1 (senior review, job 37 root-cause): round 2 put targetSwMatchesEcosystem
        // ahead of an exact slug match, which let a merely target_sw-agreeing but wrong sub-package
        // (bigcat88:pillow-heif-shaped) outrank the real, exactly-named canonical package
        // (python:pillow-shaped) purely because target_sw happened to line up too. The exact match
        // must win regardless of which candidate's target_sw happens to agree.
        PackageRegistryLookup pypiLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch("pypi", "pillow", "pkg:pypi/pillow@10.0.0", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "pypi";
            }
        };
        CpeDictionaryEntry exactPillow = cpeEntry("cpe:2.3:a:python:pillow:10.0.0:*:*:*:*:*:*:*", "pillow");
        exactPillow.setTargetSwValues(java.util.Set.of("*"));
        CpeDictionaryEntry pillowHeif = cpeEntry("cpe:2.3:a:bigcat88:pillow-heif:10.0.0:*:*:*:*:python:*:*", "pillow-heif");
        pillowHeif.setTargetSwValues(java.util.Set.of("python"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(pillowHeif, exactPillow));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(pypiLookup)).identify(item("Pillow"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:python:pillow:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void allowsANonScopingOsTargetSwValueThroughTheGateEvenWithNoRegistryMatch() {
        // REVISE item 2 (senior review, job 37 root-cause): target_sw=macos scopes Sophos Home's
        // real NVD entry to "the macOS build", not to being a component of some other platform the
        // way target_sw=jenkins does — treating every non-wildcard value as equally disqualifying
        // wrongly rejected this standalone desktop item (no registry match to gate against at all).
        CpeDictionaryEntry sophosHome = cpeEntry("cpe:2.3:a:sophos:home:1.0:*:*:*:*:macos:*:*", "home");
        sophosHome.setTitle("Sophos Home 1.0");
        sophosHome.setTargetSwValues(java.util.Set.of("macos"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(sophosHome));
        stubSaveReturnsArgument();

        ResearchJobItem sophosItem = item("Sophos Home");
        sophosItem.setVendor("Sophos");
        Optional<IdentifiedProduct> result = service(List.of()).identify(sophosItem, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:sophos:home:1.0.0:*:*:*:*:macos:*:*");
    }

    @Test
    void rejectsAJenkinsScopedCpeUnconditionallyEvenUnderAnUnmappedEcosystemsDefaultAllow() {
        // REVISE item 3 (senior review, job 37 root-cause): maven has no ECOSYSTEM_TO_TARGET_SW
        // mapping, so passesTargetSwGate's own orElse(true) default-allow would otherwise let a
        // Jenkins-plugin-scoped CPE through unchallenged. jenkins:junit (NVD's real "JUnit plugin
        // for Jenkins") must never win over the correct Maven registry match with cpe=null — NVD
        // has no generic junit:junit CPE, only junit:junit4/junit5, so no-CPE is the honest answer.
        PackageRegistryLookup mavenLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch(
                        "maven", "junit:junit", "pkg:maven/junit/junit@4.13.2", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "maven";
            }
        };
        CpeDictionaryEntry jenkinsJunit = cpeEntry("cpe:2.3:a:jenkins:junit:1.0:*:*:*:*:jenkins:*:*", "junit");
        jenkinsJunit.setTitle("Jenkins JUnit Plugin 1.0");
        jenkinsJunit.setTargetSwValues(java.util.Set.of("jenkins"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(jenkinsJunit));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(mavenLookup)).identify(item("JUnit"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("maven");
        assertThat(result.get().getCpe()).isNull();
    }

    @Test
    void hexAndMavenStillDefaultAllowAnArbitraryScopingTargetSwValue() {
        // Non-regression control: hex/maven's own orElse(true)-shaped default-allow (see
        // ECOSYSTEM_TO_TARGET_SW's javadoc) for an arbitrary non-wildcard, non-jenkins target_sw
        // value is unconditional now that no ecosystem hard-rejects via this path.
        PackageRegistryLookup mavenLookup = new PackageRegistryLookup() {
            @Override
            public Optional<RegistryMatch> lookup(String name, String version) {
                return Optional.of(new RegistryMatch(
                        "maven", "somelib", "pkg:maven/some/somelib@1.0.0", new BigDecimal("0.95"), true));
            }

            @Override
            public String ecosystem() {
                return "maven";
            }
        };
        CpeDictionaryEntry scopedSomelib = cpeEntry("cpe:2.3:a:somevendor:somelib:1.0.0:*:*:*:*:python:*:*", "somelib");
        scopedSomelib.setTargetSwValues(java.util.Set.of("python"));
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(scopedSomelib));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of(mavenLookup)).identify(item("somelib"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getEcosystem()).isEqualTo("maven");
        assertThat(result.get().getCpe()).isNotNull();
    }

    @Test
    void versionCoverageTieBreakPrefersACandidateWhoseCatalogedVersionsCoverTheItemsVersion() {
        // Backlog item 15, P2 (senior review 2026-08-30); ratio value updated for backlog item 36
        // (senior review 2026-08-30, ratio-guard rewrite): two same-slug candidates tie on
        // exactProductSlugMatch/targetSwMatchesEcosystem (no registry match, no ecosystem to gate
        // on), and item vendor is blank here so vendorAgrees can't discriminate either — the
        // version-coverage tie-break must be what decides it. Mirrors the real Audacity false
        // positive this was built for: audacity:audacity is catalogued in the real dictionary as a
        // single row at version 1.2.6 (max cataloged major 1), while audacityteam:audacity is
        // genuinely catalogued at the item's own 3.7.x version. Item major 3 vs. cataloged major 1
        // is a ratio of 3.0, safely above VERSION_COVERAGE_IMPLAUSIBILITY_RATIO's threshold of 2, so
        // this candidate is correctly demoted even under the ratio-guard rewrite.
        CpeDictionaryEntry oldAudacity = cpeEntry("cpe:2.3:a:audacity:audacity:1.2.6:*:*:*:*:*:*:*", "audacity");
        oldAudacity.setMaxCatalogedMajor(1);
        CpeDictionaryEntry realAudacity = cpeEntry("cpe:2.3:a:audacityteam:audacity:3.7.0:*:*:*:*:*:*:*", "audacity");
        realAudacity.setMaxCatalogedMajor(3);
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(oldAudacity, realAudacity));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("Audacity");
        item.setVersion("3.7.0");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:audacityteam:audacity:3.7.0:*:*:*:*:*:*:*");
    }

    @Test
    void versionCoverageTieBreakDoesNotDemoteACandidateWhoseCatalogTrailsTheItemByOnlyAFewMajors() {
        // Backlog item 36 (senior review 2026-08-30): the golden-300 regression this ratio guard
        // fixes — a correct candidate whose NVD catalogue simply stops a few majors behind the
        // item's real-world version (because NVD only ever catalogues versions a CVE happened to
        // name) must NOT be demoted, unlike the genuinely-wrong-vendor Audacity case above. Uses the
        // real golden-300 Citrix Workspace App measurement: item major 2405 vs. the correct
        // candidate's cataloged major 2006 is a ratio of ~1.20, comfortably under
        // VERSION_COVERAGE_IMPLAUSIBILITY_RATIO's threshold of 2.
        //
        // REVISE item 2 (senior review, PR #51): restored to the original regression shape — a
        // same-slug competitor with NO cataloged evidence at all (null maxCatalogedMajor), not a
        // fully-covering one. A brief, now-fixed regression (backlog item 89's K2 ranking key,
        // versionCoverageRank) collapsed "trails but plausible" and "no evidence whatsoever" into
        // the same worst rank, which made a fully-covering competitor an unsuitable "everything
        // else ties" opponent here (K2 alone would legitimately prefer it, masking whether this
        // ratio guard itself still works) — see versionCoverageRank's own javadoc. With K2 now
        // correctly ranking both candidates UNKNOWN (tied), the ratio guard (versionPlausible) is
        // also tied (no-evidence defaults to plausible too), so the trailing candidate wins purely
        // by stable sort, exactly as this test originally relied on.
        CpeDictionaryEntry trailingCatalog =
                cpeEntry("cpe:2.3:a:citrix:workspace:2006.0:*:*:*:*:*:*:*", "workspace");
        trailingCatalog.setMaxCatalogedMajor(2006);
        CpeDictionaryEntry noEvidenceCompetitor =
                cpeEntry("cpe:2.3:a:othervendor:workspace:1.0.0:*:*:*:*:*:*:*", "workspace");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(trailingCatalog, noEvidenceCompetitor));
        stubSaveReturnsArgument();

        // Item name is the bare shared slug ("workspace"), not the full "Citrix Workspace App" —
        // with two different-vendor candidates in play, a fuller query name would make
        // plausibleContainmentOnly's leading-leftover-token check depend on which vendor happens to
        // explain "citrix", which isn't what this test is about; the bare-slug name keeps both
        // candidates equally admitted so the tie-break under test is the only thing deciding.
        ResearchJobItem item = item("workspace");
        item.setVersion("2405.0");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        // identify() always rewrites the winning CPE's version segment to the item's own version
        // (see Stage1IdentificationService#withItemVersion), so the presence/vendor:product of this
        // result is what actually proves the candidate was not demoted, not its version segment.
        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:citrix:workspace:2405.0:*:*:*:*:*:*:*");
    }

    @Test
    void versionCoverageTieBreakTreatsAZeroMaxCatalogedMajorAsNoEvidence() {
        // Backlog item 36 (senior review 2026-08-30): maxCatalogedMajor <= 0 (e.g. a partition whose
        // only numeric leading run ever parsed to zero) must default to plausible exactly like a
        // null maxCatalogedMajor does — it is not concrete evidence of anything, so it must never be
        // punished as if it were concrete evidence the item's version is out of reach.
        //
        // REVISE item 2 (senior review, PR #51): restored to the original regression shape — a
        // same-slug competitor with NO cataloged evidence at all (null maxCatalogedMajor), not a
        // fully-covering one (see the sibling test above for why a fully-covering competitor no
        // longer isolates anything once K2, versionCoverageRank, exists). With the {@code <= 0}
        // case correctly treated as "no evidence", both candidates tie all the way down the key
        // chain (K2, the ratio guard, vendor agreement, cataloged row count), so the zero-evidence
        // candidate wins purely by stable sort, exactly as this test originally relied on.
        CpeDictionaryEntry zeroEvidence =
                cpeEntry("cpe:2.3:a:vendor:widget-tool:1.0.0:*:*:*:*:*:*:*", "widget-tool");
        zeroEvidence.setMaxCatalogedMajor(0);
        CpeDictionaryEntry noEvidenceCompetitor =
                cpeEntry("cpe:2.3:a:othervendor:widget-tool:1.0.0:*:*:*:*:*:*:*", "widget-tool");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(zeroEvidence, noEvidenceCompetitor));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("widget-tool");
        item.setVersion("9.0.0");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        // Same version-rewriting caveat as above: only presence/vendor:product proves the
        // zero-max-cataloged-major candidate was treated as no-evidence (UNKNOWN) rather than as bad
        // as concrete NOT_COVERS evidence.
        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:vendor:widget-tool:9.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void versionCoverageTieBreakDoesNotHardRejectWhenNoCatalogedVersionsExist() {
        // Non-regression control: absence of evidence (null maxCatalogedMajor, the common
        // case for a candidate not sourced from findFuzzyMatches) must never turn into a rejection —
        // this candidate would otherwise have no other tie-break signal to fall back on.
        CpeDictionaryEntry candidate = cpeEntry("cpe:2.3:a:vendor:widget-tool:1.0.0:*:*:*:*:*:*:*", "widget-tool");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(candidate));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("widget-tool"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isNotNull();
    }

    @Test
    void rejectsAHardwarePartCpeEvenWhenTextMatchingWouldOtherwiseAccept() {
        // REVISE item 6 (senior review, job 37 root-cause): cpe:2.3:h:corsair:commander_pro is a
        // real NVD hardware CPE that npm "commander" would otherwise text-match via plain prefix
        // containment — no part other than "a" (application) can ever be a software item's identity.
        CpeDictionaryEntry commanderPro = cpeEntry("cpe:2.3:h:corsair:commander_pro:-:*:*:*:*:*:*:*", "commander_pro");
        commanderPro.setTitle("Corsair Commander Pro");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(commanderPro));

        assertThat(service(List.of()).identify(item("commander"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void fallsBackToAnOperatingSystemPartCpeWhenNoApplicationPartCandidateExistsAtAll() {
        // golden-300 fix (2026-08-29, item 3): PAN-OS / MikroTik RouterOS are catalogued by NVD only
        // as part=o (operating system), with no part=a entry at all (measured 2026-08-30: 779 PAN-OS
        // rows and 744 MikroTik RouterOS rows, zero part=a among either — senior review caught an
        // earlier version of this comment wrongly including Cisco IOS XE, which the dictionary
        // actually catalogues with 26 part=a rows alongside its 1,089 part=o rows) — the pre-fix
        // part=a-only gate silently discarded the only candidate that could ever have identified
        // them. Safe because the fallback only ever engages when the pool has zero part=a rows (see
        // the control test below for the case where one does exist).
        CpeDictionaryEntry panOs = cpeEntry("cpe:2.3:o:paloaltonetworks:pan-os:10.2:*:*:*:*:*:*:*", "pan-os");
        panOs.setTitle("Palo Alto Networks PAN-OS 10.2");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(panOs));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("PAN-OS"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:o:paloaltonetworks:pan-os:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void neverFallsBackToAnOperatingSystemPartCpeWhenAnApplicationPartCandidateIsAlreadyPresent() {
        // Control for the fix above: the part=o fallback must never engage merely because an OS CPE
        // scores well — only because the pool has NO part=a candidate at all. Here a genuine part=a
        // candidate for the same query is present alongside a part=o one; the part=a candidate must
        // win and the part=o one must not surface at all (this is exactly the shape of the job 37
        // hardware incident the original gate was built to prevent, just with an OS part instead of
        // a hardware one).
        CpeDictionaryEntry commanderApp = cpeEntry("cpe:2.3:a:commander:commander_one:3.0:*:*:*:*:*:*:*", "commander_one");
        commanderApp.setTitle("Commander One 3.0");
        CpeDictionaryEntry commanderOs = cpeEntry("cpe:2.3:o:somevendor:commander_os:1.0:*:*:*:*:*:*:*", "commander_os");
        commanderOs.setTitle("Commander OS 1.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(commanderApp, commanderOs));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("commander"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:commander:commander_one:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void neverAdmitsAnyCpeWhenCandidatePoolIsHardwarePartOnlyAndNoApplicationPartExistsAtAll() {
        // REVISE item 4 (senior review 2026-08-29): explicit regression guard for the job 37
        // hardware-CPE incident, written specifically alongside the part=o fallback added right
        // above (golden-300 fix, item 3). That fallback only ever kicks in when bestPerProduct
        // (part=a) is empty AND bestOsPerProductFallback (part=o) is non-empty — this test locks in
        // that a part=h (hardware)-only pool leaves BOTH of those empty, so the fallback must never
        // fire for hardware and the item must end up completely unidentified, not just "not
        // preferred". Distinct from rejectsAHardwarePartCpeEvenWhenTextMatchingWouldOtherwiseAccept
        // above (which predates the part=o fallback and only asserts the part=a gate itself);
        // this test instead guards the fallback's own boundary now that a second, adjacent
        // "no part=a candidates" fallback path exists that could accidentally be widened to include
        // part=h too.
        CpeDictionaryEntry commanderPro = cpeEntry("cpe:2.3:h:corsair:commander_pro:-:*:*:*:*:*:*:*", "commander_pro");
        commanderPro.setTitle("Corsair Commander Pro");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(commanderPro));

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("commander"), USER_ID);

        assertThat(result).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsANonLeadingBoundaryMatchWhenTheLeftoverIsExplainedOnlyByTheCpesOwnVendorNotTheItems() {
        // REVISE item 4 (senior review, job 37 root-cause): vendorExplains("goanother", "another")
        // trivially passes because the CPE's own vendor slug happens to contain the leftover word —
        // that's not evidence about *this* item's identity. The item's own vendor ("RDM Dev Team")
        // does not explain "another", and there is no correct CPE for this product in the real
        // dictionary at all (confirmed live) — must fall through to UNIDENTIFIED.
        CpeDictionaryEntry anotherRedisDesktopManager = cpeEntry(
                "cpe:2.3:a:goanother:another_redis_desktop_manager:1.6.6:*:*:*:*:*:*:*",
                "another_redis_desktop_manager");
        anotherRedisDesktopManager.setTitle("goanother Another Redis Desktop Manager 1.6.6");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(anotherRedisDesktopManager));

        ResearchJobItem rdmItem = item("Redis Desktop Manager");
        rdmItem.setVendor("RDM Dev Team");
        assertThat(service(List.of()).identify(rdmItem, USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void rejectsASingleTokenCandidateMatchingAtTheHeadOfTheQueryWithUnexplainedTrailingTokens() {
        // REVISE item 5 (senior review, job 37 root-cause): direction 2 only ever policed leading
        // leftovers, never trailing ones — fine when a leading anchor already proves the vendor tie,
        // but "Chrome Remote Desktop" matched 360:chrome with nothing at all preceding the match to
        // vouch for it and the entire "remote desktop" tail silently unaccounted for.
        CpeDictionaryEntry threeSixtyChrome = cpeEntry("cpe:2.3:a:360:chrome:13.0.2170.0:*:*:*:*:*:*:*", "chrome");
        threeSixtyChrome.setTitle("360 Chrome 13.0.2170.0");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(threeSixtyChrome));

        assertThat(service(List.of()).identify(item("Chrome Remote Desktop"), USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void keepsASingleTokenCandidateWhoseLeadingTokenIsVendorExplainedRegardlessOfUnexplainedTrailingTokens() {
        // The other half of REVISE item 5: a leading anchor that's already vendor-explained is
        // enough on its own — the trailing "Free" edition qualifier must not additionally have to be.
        CpeDictionaryEntry avgAntivirus = cpeEntry("cpe:2.3:a:avg:antivirus:22.10:*:*:*:*:*:*:*", "antivirus");
        avgAntivirus.setTitle("Avg Antivirus 22.10");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(avgAntivirus));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("AVG AntiVirus Free"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:avg:antivirus:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void unexplainedQueryTokenCountTieBreakPrefersTheCandidateThatExplainsEveryQueryToken() {
        // Backlog item 89, K1 (senior review 2026-08-30, real job195/196 data): "Adobe Acrobat
        // Reader DC" ties on exactSlug (neither candidate's bare product slug equals the full,
        // vendor-prefixed query) and targetSw (no ecosystem here at all) between the correct
        // acrobat_reader_dc and the wrong, shorter acrobat_reader — only K1 (how many query tokens
        // neither the candidate's own text nor its CPE vendor explain) can tell them apart: "dc" is
        // explained by acrobat_reader_dc's own title but by neither acrobat_reader's product/title
        // nor Adobe's own short CPE vendor slug.
        CpeDictionaryEntry acrobatReaderDc =
                cpeEntry("cpe:2.3:a:adobe:acrobat_reader_dc:24.002.21005:*:*:*:*:*:*:*", "acrobat_reader_dc");
        acrobatReaderDc.setTitle("Adobe Acrobat Reader DC 24.002.21005");
        CpeDictionaryEntry acrobatReader =
                cpeEntry("cpe:2.3:a:adobe:acrobat_reader:2020.006.20042:*:*:*:*:*:*:*", "acrobat_reader");
        acrobatReader.setTitle("Adobe Acrobat Reader 2020.006.20042");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(acrobatReader, acrobatReaderDc));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("Adobe Acrobat Reader DC");
        item.setVendor("Adobe");
        item.setVersion("24.002.21005");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:adobe:acrobat_reader_dc:24.002.21005:*:*:*:*:*:*:*");
    }

    @Test
    void versionCoverageRankTieBreakPrefersTheCandidateWhoseCatalogueActuallyCoversTheItemsMajorVersion() {
        // Backlog item 89, K2 (senior review 2026-08-30): Node.js 20.16.0 — both nodejs:node.js and
        // joyent:node.js are exact-slug matches with no ecosystem/target_sw signal, so only K2 (a
        // real cataloged major covering the item vs. no cataloged evidence at all) can distinguish
        // them. Positioned ahead of versionPlausible/vendorAgrees in rankCpeCandidates's own key
        // chain — see this test's PDF-XChange sibling below for why that ordering itself matters.
        CpeDictionaryEntry nodejsNodeJs = cpeEntry("cpe:2.3:a:nodejs:node.js:20.16.0:*:*:*:*:*:*:*", "node.js");
        nodejsNodeJs.setMaxCatalogedMajor(26);
        CpeDictionaryEntry joyentNodeJs = cpeEntry("cpe:2.3:a:joyent:node.js:0.6.0:*:*:*:*:*:*:*", "node.js");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(joyentNodeJs, nodejsNodeJs));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("Node.js");
        item.setVersion("20.16.0");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:nodejs:node.js:20.16.0:*:*:*:*:*:*:*");
    }

    @Test
    void versionCoverageRankTieBreakOutranksVendorAgreesEvenWhenTheItemsOwnVendorMatchesTheWrongCandidate() {
        // Backlog item 89, K2 (senior review 2026-08-30): PDF-XChange Editor 10.2.1's item vendor
        // field is literally "Tracker Software Products", which would make vendorAgrees favor the
        // wrong, version-stale tracker-software:pdf-xchange_editor (cataloged only up to major 9)
        // over the correct pdf-xchange:pdf-xchange_editor (cataloged up to major 10, actually covers
        // the item) — this is exactly why K2 must sit ahead of vendorAgrees in rankCpeCandidates's
        // own key chain, not merely somewhere in it.
        CpeDictionaryEntry pdfXchangeVendor =
                cpeEntry("cpe:2.3:a:pdf-xchange:pdf-xchange_editor:10.3.0.386:*:*:*:*:*:*:*", "pdf-xchange_editor");
        pdfXchangeVendor.setMaxCatalogedMajor(10);
        CpeDictionaryEntry trackerSoftwareVendor =
                cpeEntry("cpe:2.3:a:tracker-software:pdf-xchange_editor:6.0.320.0:*:*:*:*:*:*:*", "pdf-xchange_editor");
        trackerSoftwareVendor.setMaxCatalogedMajor(9);
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(trackerSoftwareVendor, pdfXchangeVendor));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("PDF-XChange Editor");
        item.setVendor("Tracker Software Products");
        item.setVersion("10.2.1");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:pdf-xchange:pdf-xchange_editor:10.2.1:*:*:*:*:*:*:*");
    }

    @Test
    void catalogedRowCountTieBreakPrefersTheVendorProductPairWithMoreCatalogedRows() {
        // Backlog item 89, K3 (senior review 2026-08-30): Greenshot 1.3.290 ties getgreenshot:greenshot
        // and greenshot:greenshot on every earlier key (both exact-slug, both no ecosystem/target_sw
        // signal, both no version-coverage evidence, and both vendor-agree — "getgreenshot" and
        // "greenshot" both containment-match the item's own "Greenshot" vendor field either way) —
        // only K3, the final tie-break, can separate them: NVD actually catalogues 80 rows for
        // getgreenshot:greenshot versus 1 for greenshot:greenshot.
        CpeDictionaryEntry getgreenshotGreenshot =
                cpeEntry("cpe:2.3:a:getgreenshot:greenshot:1.3.290:*:*:*:*:*:*:*", "greenshot");
        getgreenshotGreenshot.setCatalogedRowCount(80);
        CpeDictionaryEntry greenshotGreenshot =
                cpeEntry("cpe:2.3:a:greenshot:greenshot:1.0:*:*:*:*:*:*:*", "greenshot");
        greenshotGreenshot.setCatalogedRowCount(1);
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(greenshotGreenshot, getgreenshotGreenshot));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("Greenshot");
        item.setVendor("Greenshot");
        item.setVersion("1.3.290");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:getgreenshot:greenshot:1.3.290:*:*:*:*:*:*:*");
    }

    @Test
    void relaxedContainmentPass2NeverFiresWhenTheStrictPassAlreadyFoundACandidate() {
        // Control for the test above: when the strict pass already admits at least one candidate,
        // the relaxed second pass must never run at all — proven by the ordinary no-Claude-key
        // direct-trust path still succeeding without any AI call (a relaxed-pass admission would
        // have forced AI verification and, with no key configured, dropped the candidate instead).
        CpeDictionaryEntry exactSlug = cpeEntry("cpe:2.3:a:vendor:widget-tool:1.0.0:*:*:*:*:*:*:*", "widget-tool");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(exactSlug));
        stubSaveReturnsArgument();

        Optional<IdentifiedProduct> result = service(List.of()).identify(item("widget-tool"), USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpeCandidateVariantDerived()).isFalse();
    }

    @Test
    void rejectsASingleTokenQueryMatchingOnlyALeadingPortionOfAMultiTokenCandidateWhenItemVendorDoesNotExplainTheLeftover() {
        // Backlog item 89 P3 (senior review 2026-08-30): "Slack" (item vendor "Slack Technologies")
        // against slack_archivebot_project:slack_archivebot — Direction 1 previously accepted this
        // purely because "slack" aligns against the candidate's leading token, leaving "archivebot"
        // completely unpoliced. The item's own vendor field doesn't explain "archivebot" either, so
        // this must now be rejected, leaving the item UNIDENTIFIED (golden-300's own intended
        // outcome for this control row) rather than misidentified as an unrelated Slack add-on.
        CpeDictionaryEntry slackArchivebot =
                cpeEntry("cpe:2.3:a:slack_archivebot_project:slack_archivebot:1.0:*:*:*:*:*:*:*", "slack_archivebot");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(slackArchivebot));

        ResearchJobItem item = item("Slack");
        item.setVendor("Slack Technologies");

        assertThat(service(List.of()).identify(item, USER_ID)).isEmpty();
        verify(identifiedProductRepository, never()).save(any());
    }

    @Test
    void keepsASingleTokenQueryMatchingALeadingPortionOfAMultiTokenCandidateWhenItemVendorExplainsTheLeftover() {
        // Contrast with the Slack rejection above (backlog item 89 P3): when the item's own vendor
        // field DOES explain the candidate's leftover trailing token, the match is still accepted —
        // this is not a blanket ban on every single-token-query-vs-multi-token-candidate match, only
        // on ones whose leftover the item's own vendor field can't account for.
        CpeDictionaryEntry fooBar = cpeEntry("cpe:2.3:a:acme:foo_bar:2.0:*:*:*:*:*:*:*", "foo_bar");
        when(cpeDictionaryRepository.findFuzzyMatches(anyString(), anyDouble(), anyDouble(), anyInt()))
                .thenReturn(List.of(fooBar));
        stubSaveReturnsArgument();

        ResearchJobItem item = item("Foo");
        item.setVendor("Foo Bar Inc");

        Optional<IdentifiedProduct> result = service(List.of()).identify(item, USER_ID);

        assertThat(result).isPresent();
        assertThat(result.get().getCpe()).isEqualTo("cpe:2.3:a:acme:foo_bar:1.0.0:*:*:*:*:*:*:*");
    }

    @Test
    void normalizeForContainmentStripsCpeBackslashEscapesSoAnEscapedDictionaryEntryStillMatchesTheUnescapedQuery() {
        // CPE 2.3 strings backslash-escape reserved characters (e.g. "notepad\+\+" for the product
        // segment of Notepad++'s own dictionary entry) — normalizeForContainment must strip those so
        // the escaped dictionary form still containment-matches the plain query text a user would
        // actually type ("Notepad++", unescaped).
        String normalizedEscaped = service(List.of()).normalizeForContainment("notepad\\+\\+");
        String normalizedQuery = service(List.of()).normalizeForContainment("Notepad++");

        assertThat(normalizedEscaped).isEqualTo(normalizedQuery);
    }
}
