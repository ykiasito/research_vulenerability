package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
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

/**
 * Closed-mode backlog item 382. Each mirror is exercised with its own healthy baseline plus every
 * distinct way it can go stale, since {@link MirrorFreshnessService#staleMirrorWarnings()} is the
 * sole gate deciding whether {@code jobs/detail.html} shows a freshness banner at all. CVE.org's
 * {@code checkCveOrg} path is deliberately age-only (no {@code last_sync_error} check) — see
 * {@link MirrorFreshnessService}'s own class javadoc for why (closed-mode backlog item 379 hasn't
 * landed on this branch yet).
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

    /** Closed-mode backlog item 379 has not landed on this branch yet (see this class's own
     *  javadoc) — {@code CveOrgSyncState} has no {@code last_sync_error} field here, so a recent
     *  {@code last_synced_at} is never treated as stale regardless of any prior failure; only the
     *  age check below applies to CVE.org for now. */
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

    /** Senior review, PR #274 round 2 (a real security finding, not a hardening suggestion): the
     *  raw {@code last_sync_error} text (which can carry internal detail -- host names, JDBC error
     *  text, file paths -- see {@code GhsaSyncService}/{@code OsvSyncService}'s own {@code
     *  failSync}) must never reach this class's output, since it's rendered on {@code
     *  jobs/detail.html} for every authenticated user, not just {@code ROLE_ADMIN}. */
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

    /** Same rationale as {@link #ghsaWithARecentButFailedSyncIsStaleAndDoesNotLeakTheRawErrorText}
     *  — OSV has its own independent {@code checkOsv} branch to regress. */
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

    /** {@link MirrorFreshnessService#addIfStale}'s own null-{@code lastSyncedAt} branch -- a
     *  baseline-loaded, error-free mirror that has, for whatever reason, never actually recorded a
     *  sync timestamp. Exercised via GHSA (any of the per-mirror checks reaches the same shared
     *  {@code addIfStale} helper). */
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

    // ------------------------------------------------------------------------------- caching ------

    /** Senior review, PR #274 round 2: {@code jobs/detail.html} auto-refreshes every 5 seconds
     *  while a job is running, and {@link RegistryPackageMirrorRepository#maxLastSyncedAt} is an
     *  unindexed full-table {@code MAX(...)} scan that closed-mode's architecture gate forbids
     *  adding an index for. {@link MirrorFreshnessService#staleMirrorWarnings()} must therefore
     *  reuse its previous result within the cache TTL instead of hitting every repository again on
     *  each call -- asserted here via any one of the underlying repositories (they all share the
     *  same cache, so one is representative of the whole method). */
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
