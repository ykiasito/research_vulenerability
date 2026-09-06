package com.vulncheck.app.service;

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
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Closed-mode backlog item 382: in closed mode, every one of these six mirrors (NVD CVE, CVE.org,
 * GHSA, OSV, CSAF, the package registry mirror — see {@code docs/spec/closed-mode-plan.md}) is the
 * <em>only</em> data source the pipeline's per-source lookups read; there is no live-API fallback
 * left to silently paper over a mirror that never finished its baseline, has gone stale, or has
 * been failing every scheduled run. Before this class, that state was visible only per-mirror on
 * its own {@code /admin/*} page (useful only to an operator who already suspects a problem and
 * knows which page to check) and nowhere at all on the page every user — not just an admin — looks
 * at: a job's own {@code jobs/detail.html}. {@link #staleMirrorWarnings()} is the one check both
 * that page (see {@code JobController}) and this class's own tests exercise, so "stale" means the
 * same thing everywhere instead of being redefined ad hoc per page.
 *
 * <p><b>What counts as stale, per mirror</b> — deliberately three independent conditions, not just
 * "hasn't synced in a while":
 *
 * <ol>
 *   <li>baseline never completed at all (nothing to serve yet);
 *   <li>the mirror's own sync state records a {@code last_sync_error} from its most recent
 *       attempt — this is what lets this same check also surface closed-mode backlog item 379 (a
 *       {@code CveOrgSyncService} baseline/delta sync that keeps failing every scheduled run):
 *       {@link com.vulncheck.app.service.cveorg.CveOrgSyncService} now advances {@code
 *       last_synced_at} on every attempt, success or failure (matching {@code GhsaSyncService}/
 *       {@code OsvSyncService}'s existing convention), so a mirror that fails every day forever
 *       would otherwise always look "recently synced" under condition 3 alone, silently hiding the
 *       exact failure item 379 was filed about — {@code last_sync_error} being non-null is what
 *       actually distinguishes "ran and failed" from "ran and succeeded";
 *   <li>the last successful sync is older than this mirror's own freshness threshold.
 * </ol>
 *
 * <p>Age thresholds are derived from each mirror's own scheduled cadence (see the {@code
 * @Scheduled} cron on {@code CveOrgScheduledSync}/{@code GhsaScheduledSync}/{@code
 * OsvScheduledSync}/{@code RedHatCsafScheduledSync}/{@code SiemensCsafScheduledSync}/{@code
 * NvdCveDeltaScheduledRunner} — all daily — and {@code RegistryMirrorScheduledSync}, weekly): {@link
 * #DAILY_MIRROR_STALE_AFTER} gives a one-run buffer past a daily schedule (a single missed run
 * doesn't flag anything; a second consecutive miss does), and {@link #WEEKLY_MIRROR_STALE_AFTER}
 * gives the same one-run buffer past the registry mirror's 7-day schedule.
 */
@Service
@RequiredArgsConstructor
public class MirrorFreshnessService {

    private static final Duration DAILY_MIRROR_STALE_AFTER = Duration.ofDays(2);
    private static final Duration WEEKLY_MIRROR_STALE_AFTER = Duration.ofDays(9);

    private final CveOrgSyncStateRepository cveOrgSyncStateRepository;
    private final GhsaSyncStateRepository ghsaSyncStateRepository;
    private final OsvSyncStateRepository osvSyncStateRepository;
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository;
    private final CsafSyncStateRepository csafSyncStateRepository;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * @return one human-readable (Japanese) warning per mirror currently judged stale —
     *     deliberately not a single boolean, so a caller (currently only {@code JobController}) can
     *     show which specific mirror(s) are the problem rather than just "something, somewhere is
     *     stale". Empty when every mirror looks healthy.
     */
    public List<String> staleMirrorWarnings() {
        List<String> warnings = new ArrayList<>();
        checkCveOrg(warnings);
        checkGhsa(warnings);
        checkOsv(warnings);
        checkNvdCve(warnings);
        checkCsaf(warnings, SiemensCsafSyncService.VENDOR, "CSAF（Siemens）");
        checkCsaf(warnings, RedHatCsafSyncService.VENDOR, "CSAF（Red Hat）");
        checkRegistry(warnings);
        return warnings;
    }

    private void checkCveOrg(List<String> warnings) {
        CveOrgSyncState state = cveOrgSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineLoaded()) {
            warnings.add("CVE.org: baselineが未読み込みです。");
            return;
        }
        if (state.getLastSyncError() != null) {
            warnings.add("CVE.org: 直近の同期が失敗しています（" + state.getLastSyncError() + "）。");
            return;
        }
        addIfStale(warnings, "CVE.org", toInstant(state.getLastSyncedAt()), DAILY_MIRROR_STALE_AFTER);
    }

    private void checkGhsa(List<String> warnings) {
        GhsaSyncState state = ghsaSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineLoaded()) {
            warnings.add("GHSA: baselineが未読み込みです。");
            return;
        }
        if (state.getLastSyncError() != null) {
            warnings.add("GHSA: 直近の同期が失敗しています（" + state.getLastSyncError() + "）。");
            return;
        }
        addIfStale(warnings, "GHSA", toInstant(state.getLastSyncedAt()), DAILY_MIRROR_STALE_AFTER);
    }

    private void checkOsv(List<String> warnings) {
        OsvSyncState state = osvSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineLoaded()) {
            warnings.add("OSV: baselineが未読み込みです。");
            return;
        }
        if (state.getLastSyncError() != null) {
            warnings.add("OSV: 直近の同期が失敗しています（" + state.getLastSyncError() + "）。");
            return;
        }
        addIfStale(warnings, "OSV", toInstant(state.getLastSyncedAt()), DAILY_MIRROR_STALE_AFTER);
    }

    private void checkNvdCve(List<String> warnings) {
        NvdCveSyncState state = nvdCveSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineCompleted()) {
            warnings.add("NVD CVE: baselineが未完了です。");
            return;
        }
        addIfStale(warnings, "NVD CVE", toInstant(state.getLastDeltaSyncedAt()), DAILY_MIRROR_STALE_AFTER);
    }

    private void checkCsaf(List<String> warnings, String vendor, String label) {
        CsafSyncState state = csafSyncStateRepository.findById(vendor).orElse(null);
        if (state == null || state.getLastSyncedAt() == null) {
            warnings.add(label + ": 一度も同期されていません。");
            return;
        }
        addIfStale(warnings, label, toInstant(state.getLastSyncedAt()), DAILY_MIRROR_STALE_AFTER);
    }

    private void checkRegistry(List<String> warnings) {
        Optional<Instant> lastSyncedAt = registryPackageMirrorRepository.maxLastSyncedAt();
        if (lastSyncedAt.isEmpty()) {
            warnings.add("パッケージレジストリミラー: 一度も同期されていません。");
            return;
        }
        addIfStale(warnings, "パッケージレジストリミラー", lastSyncedAt.get(), WEEKLY_MIRROR_STALE_AFTER);
    }

    private void addIfStale(List<String> warnings, String label, Instant lastSyncedAt, Duration staleAfter) {
        if (lastSyncedAt == null) {
            warnings.add(label + ": 同期日時が記録されていません。");
            return;
        }
        Duration age = Duration.between(lastSyncedAt, Instant.now());
        if (age.compareTo(staleAfter) > 0) {
            warnings.add(label + ": 最終同期から" + age.toDays() + "日経過しています。");
        }
    }

    private static Instant toInstant(OffsetDateTime value) {
        return value == null ? null : value.toInstant();
    }
}
