package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.CsafSyncState;
import com.vulncheck.app.entity.CveOrgSyncState;
import com.vulncheck.app.entity.GhsaSyncState;
import com.vulncheck.app.entity.NvdCveSyncState;
import com.vulncheck.app.entity.OsvSyncState;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.CveOrgSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.RegistryPackageMirrorRepository;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Closed-mode backlog item 382 (promoted to master by item 396). Each mirror is exercised with its
 * own healthy baseline plus every distinct way it can go stale, since {@link
 * MirrorFreshnessService#staleMirrorWarnings()} is the sole gate deciding whether {@code
 * jobs/detail.html} shows a freshness banner at all. CVE.org/GHSA/OSV are always checked (mirror-only
 * sources on this branch too); NVD CVE and the registry mirror are gated by {@code
 * app.mirror-freshness.nvd-cve-check-enabled}/{@code app.mirror-freshness.registry-check-enabled}
 * (item 396) — those two gates are exercised separately in the "gating" section below, with every
 * other test in this class leaving both at their code-level default ({@code true}) so the
 * pre-existing per-mirror behavior stays covered exactly as it was on closed-mode.
 */
@ExtendWith(MockitoExtension.class)
class MirrorFreshnessServiceTest {

    @Mock
    private CveOrgSyncStateRepository cveOrgSyncStateRepository;
    @Mock
    private GhsaSyncStateRepository ghsaSyncStateRepository;
    @Mock
    private OsvSyncStateRepository osvSyncStateRepository;
    @Mock
    private NvdCveSyncStateRepository nvdCveSyncStateRepository;
    @Mock
    private CsafSyncStateRepository csafSyncStateRepository;
    @Mock
    private RegistryPackageMirrorRepository registryPackageMirrorRepository;

    private MirrorFreshnessService service;

    @BeforeEach
    void setUp() {
        service = new MirrorFreshnessService(cveOrgSyncStateRepository, ghsaSyncStateRepository,
                osvSyncStateRepository, nvdCveSyncStateRepository, csafSyncStateRepository,
                registryPackageMirrorRepository);
        // @Value fields have no Spring context here to inject them -- default both gates to their
        // code-level default (true) so every pre-existing test below observes the same behavior as
        // closed-mode's version of this class, which had no gates at all.
        ReflectionTestUtils.setField(service, "nvdCveCheckEnabled", true);
        ReflectionTestUtils.setField(service, "registryCheckEnabled", true);
    }

    /** Every mirror healthy (recently synced, baseline loaded, no error) -- no warnings at all. */
    @Test
    void noWarningsWhenEveryMirrorIsHealthy() {
        OffsetDateTime recent = OffsetDateTime.now(ZoneOffset.UTC).minusHours(1);
        stubHealthyCveOrg(recent);
        stubHealthyGhsa(recent);
        stubHealthyOsv(recent);
        stubHealthyNvdCve(recent);
        stubHealthyCsaf(recent);
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(recent.toInstant()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).isEmpty();
    }

    // ------------------------------------------------------------------------------ CVE.org -----

    @Test
    void cveOrgNeverSyncedRowIsStale() {
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("CVE.org") && w.contains("baseline"));
    }

    @Test
    void cveOrgWithAnOldSyncIsStale() {
        CveOrgSyncState state = new CveOrgSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(OffsetDateTime.now(ZoneOffset.UTC).minusDays(5));
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("CVE.org") && w.contains("経過"));
    }

    @Test
    void cveOrgWithARecentButFailedSyncIsStaleAndDoesNotLeakTheRawErrorText() {
        String secretDetail = "java.net.UnknownHostException: internal-cve-org-mirror.example";
        CveOrgSyncState state = new CveOrgSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        state.setLastSyncError(secretDetail);
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("CVE.org") && w.contains("/admin/cve-org"));
        assertThat(warnings).noneMatch(w -> w.contains(secretDetail));
    }

    // -------------------------------------------------------------------------------- GHSA -------

    @Test
    void ghsaBaselineNotLoadedIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        when(ghsaSyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("GHSA") && w.contains("baseline"));
    }

    @Test
    void ghsaWithARecentButFailedSyncIsStaleAndDoesNotLeakTheRawErrorText() {
        String secretDetail = "connection to internal-mirror-host.example failed: password authentication failed for user \"ghsa_sync\"";
        GhsaSyncState state = new GhsaSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        state.setLastSyncError(secretDetail);
        when(ghsaSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("GHSA") && w.contains("/admin/ghsa"));
        assertThat(warnings).noneMatch(w -> w.contains(secretDetail));
    }

    @Test
    void osvBaselineNotLoadedIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        when(osvSyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("OSV") && w.contains("baseline"));
    }

    @Test
    void osvWithARecentButFailedSyncIsStaleAndDoesNotLeakTheRawErrorText() {
        String secretDetail = "java.net.UnknownHostException: internal-osv-mirror.example";
        OsvSyncState state = new OsvSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        state.setLastSyncError(secretDetail);
        when(osvSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("OSV") && w.contains("/admin/osv"));
        assertThat(warnings).noneMatch(w -> w.contains(secretDetail));
    }

    @Test
    void aMirrorWithNoRecordedLastSyncedAtIsStale() {
        GhsaSyncState state = new GhsaSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(null);
        when(ghsaSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("GHSA") && w.contains("同期日時が記録されていません"));
    }

    // --------------------------------------------------------------------------- NVD CVE ---------

    @Test
    void nvdCveBaselineNotCompletedIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        when(nvdCveSyncStateRepository.findById((short) 1)).thenReturn(Optional.empty());
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("NVD CVE") && w.contains("baseline"));
    }

    @Test
    void nvdCveOlderThanTwoDaysIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC).minusDays(3));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("NVD CVE") && w.contains("経過"));
    }

    // ------------------------------------------------------------------------------- CSAF ---------

    @Test
    void csafVendorNeverSyncedIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        when(csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR)).thenReturn(Optional.empty());
        when(csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR))
                .thenReturn(Optional.of(healthyCsafState(RedHatCsafSyncService.VENDOR, OffsetDateTime.now(ZoneOffset.UTC))));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("Siemens"));
        assertThat(warnings).noneMatch(w -> w.contains("Red Hat"));
    }

    @Test
    void csafVendorOlderThanTwoDaysIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        OffsetDateTime stale = OffsetDateTime.now(ZoneOffset.UTC).minusDays(3);
        when(csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR))
                .thenReturn(Optional.of(healthyCsafState(SiemensCsafSyncService.VENDOR, stale)));
        when(csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR))
                .thenReturn(Optional.of(healthyCsafState(RedHatCsafSyncService.VENDOR, OffsetDateTime.now(ZoneOffset.UTC))));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("Siemens") && w.contains("経過"));
        assertThat(warnings).noneMatch(w -> w.contains("Red Hat"));
    }

    // ---------------------------------------------------------------------------- registry -------

    @Test
    void registryMirrorNeverSyncedIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt()).thenReturn(Optional.empty());

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("レジストリ"));
    }

    @Test
    void registryMirrorOlderThanNineDaysIsStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now().minus(java.time.Duration.ofDays(10))));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("レジストリ") && w.contains("経過"));
    }

    @Test
    void registryMirrorWithinNineDaysIsNotStale() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now().minus(java.time.Duration.ofDays(3))));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).noneMatch(w -> w.contains("レジストリ"));
    }

    // ------------------------------------------------------------------------------- gating -------

    /** Item 396: with the NVD-CVE gate off, checkNvdCve must never run -- not even to report
     *  "stale" -- and the repository backing it must never be touched at all. */
    @Test
    void nvdCveCheckIsSkippedEntirelyWhenItsGateIsDisabled() {
        ReflectionTestUtils.setField(service, "nvdCveCheckEnabled", false);
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));
        // Deliberately no nvdCveSyncStateRepository stub at all -- if checkNvdCve ran despite the
        // gate, findById would return Mockito's default null-Optional stub and this test would still
        // pass by accident; verifyNoInteractions below is the real assertion.

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).noneMatch(w -> w.contains("NVD CVE"));
        verifyNoInteractions(nvdCveSyncStateRepository);
    }

    /** Item 396: with the NVD-CVE gate on (the code-level default), a stale NVD CVE mirror is still
     *  reported -- pins down that the gate is additive (skip when off), not a silent always-skip. */
    @Test
    void nvdCveCheckStillFiresWhenItsGateIsEnabled() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC).minusDays(3));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("NVD CVE") && w.contains("経過"));
        verify(nvdCveSyncStateRepository, times(1)).findById((short) 1);
    }

    /** Item 396: with the registry gate off, checkRegistry must never run, and {@link
     *  RegistryPackageMirrorRepository#maxLastSyncedAt} must never be called. */
    @Test
    void registryCheckIsSkippedEntirelyWhenItsGateIsDisabled() {
        ReflectionTestUtils.setField(service, "registryCheckEnabled", false);
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        // Deliberately no registryPackageMirrorRepository stub -- verifyNoInteractions below is the
        // real assertion, same rationale as nvdCveCheckIsSkippedEntirelyWhenItsGateIsDisabled.

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).noneMatch(w -> w.contains("レジストリ"));
        verify(registryPackageMirrorRepository, never()).maxLastSyncedAt();
    }

    /** Item 396: with the registry gate on (the code-level default), a never-synced registry
     *  mirror is still reported. */
    @Test
    void registryCheckStillFiresWhenItsGateIsEnabled() {
        stubHealthyCveOrg(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt()).thenReturn(Optional.empty());

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("レジストリ"));
    }

    // ------------------------------------------------------------------------------- caching ------

    @Test
    void staleMirrorWarningsOnlyHitsTheRepositoriesOnceWithinTheCacheTtl() {
        OffsetDateTime recent = OffsetDateTime.now(ZoneOffset.UTC).minusHours(1);
        stubHealthyCveOrg(recent);
        stubHealthyGhsa(recent);
        stubHealthyOsv(recent);
        stubHealthyNvdCve(recent);
        stubHealthyCsaf(recent);
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(recent.toInstant()));

        List<String> first = service.staleMirrorWarnings();
        List<String> second = service.staleMirrorWarnings();

        assertThat(first).isEmpty();
        assertThat(second).isEmpty();
        verify(cveOrgSyncStateRepository, times(1)).findById((short) 1);
        verify(ghsaSyncStateRepository, times(1)).findById((short) 1);
        verify(osvSyncStateRepository, times(1)).findById((short) 1);
        verify(nvdCveSyncStateRepository, times(1)).findById((short) 1);
        verify(registryPackageMirrorRepository, times(1)).maxLastSyncedAt();
    }

    /** Closed-mode backlog item 397: {@link MirrorFreshnessService#staleMirrorWarnings()} must
     *  return a defensive copy, not the cached {@code ArrayList} instance itself -- otherwise a
     *  caller mutating its result would silently corrupt the cache for every subsequent call within
     *  the TTL. */
    @Test
    void staleMirrorWarningsReturnsAnImmutableList() {
        OffsetDateTime recent = OffsetDateTime.now(ZoneOffset.UTC).minusHours(1);
        stubHealthyCveOrg(recent);
        stubHealthyGhsa(recent);
        stubHealthyOsv(recent);
        stubHealthyNvdCve(recent);
        stubHealthyCsaf(recent);
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(recent.toInstant()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThatThrownBy(() -> warnings.add("should not be allowed"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    // ------------------------------------------------------------------------------ helpers -------

    private void stubHealthyCveOrg(OffsetDateTime lastSyncedAt) {
        CveOrgSyncState state = new CveOrgSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(lastSyncedAt);
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
    }

    private void stubHealthyGhsa(OffsetDateTime lastSyncedAt) {
        GhsaSyncState state = new GhsaSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(lastSyncedAt);
        when(ghsaSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
    }

    private void stubHealthyOsv(OffsetDateTime lastSyncedAt) {
        OsvSyncState state = new OsvSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(lastSyncedAt);
        when(osvSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
    }

    private void stubHealthyNvdCve(OffsetDateTime lastDeltaSyncedAt) {
        NvdCveSyncState state = new NvdCveSyncState();
        state.setBaselineCompleted(true);
        state.setLastDeltaSyncedAt(lastDeltaSyncedAt);
        when(nvdCveSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
    }

    private void stubHealthyCsaf(OffsetDateTime lastSyncedAt) {
        when(csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR))
                .thenReturn(Optional.of(healthyCsafState(SiemensCsafSyncService.VENDOR, lastSyncedAt)));
        when(csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR))
                .thenReturn(Optional.of(healthyCsafState(RedHatCsafSyncService.VENDOR, lastSyncedAt)));
    }

    private CsafSyncState healthyCsafState(String vendor, OffsetDateTime lastSyncedAt) {
        CsafSyncState state = new CsafSyncState(vendor);
        state.setLastSyncedAt(lastSyncedAt);
        return state;
    }
}
