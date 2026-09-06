package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
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
 * Closed-mode backlog item 382 (and item 379, which this class's {@code checkCveOrg} path also
 * covers — see {@link MirrorFreshnessService}'s own class javadoc). Each mirror is exercised with
 * its own healthy baseline plus every distinct way it can go stale, since {@link
 * MirrorFreshnessService#staleMirrorWarnings()} is the sole gate deciding whether {@code
 * jobs/detail.html} shows a freshness banner at all.
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

    /** Closed-mode backlog item 379: a continuously-failing sync must be flagged even though {@code
     *  CveOrgSyncService} now advances {@code last_synced_at} on every attempt (so an age-only check
     *  alone would miss it). */
    @Test
    void cveOrgWithARecentButFailedSyncIsStale() {
        CveOrgSyncState state = new CveOrgSyncState();
        state.setBaselineLoaded(true);
        state.setLastSyncedAt(OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(5));
        state.setLastSyncError("delta sync failed after upserting 0 records (IOException)");
        when(cveOrgSyncStateRepository.findById((short) 1)).thenReturn(Optional.of(state));
        stubHealthyGhsa(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyOsv(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyNvdCve(OffsetDateTime.now(ZoneOffset.UTC));
        stubHealthyCsaf(OffsetDateTime.now(ZoneOffset.UTC));
        when(registryPackageMirrorRepository.maxLastSyncedAt())
                .thenReturn(Optional.of(Instant.now()));

        List<String> warnings = service.staleMirrorWarnings();

        assertThat(warnings).anyMatch(w -> w.contains("CVE.org") && w.contains("失敗"));
    }

    @Test
    void cveOrgWithAnOldButErrorFreeSyncIsStale() {
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
