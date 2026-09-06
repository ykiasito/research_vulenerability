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
 * <p><b>What counts as stale, per mirror</b> — deliberately more than just "hasn't synced in a
 * while":
 *
 * <ol>
 *   <li>baseline never completed at all (nothing to serve yet);
 *   <li>for GHSA/OSV (which already carry a {@code last_sync_error} column in closed mode), the
 *       mirror's own sync state records an error from its most recent attempt — non-null there
 *       distinguishes "ran and failed" from "ran and succeeded", since both {@code GhsaSyncService}
 *       and {@code OsvSyncService} advance {@code last_synced_at} on every attempt, success or
 *       failure, so an age-only check alone would otherwise treat a mirror that fails every
 *       scheduled run as "recently synced" forever;
 *   <li>the last successful sync is older than this mirror's own freshness threshold.
 * </ol>
 *
 * <p><b>The raw {@code last_sync_error} text is never shown here</b> (senior review on PR #274,
 * round 2 — a real finding, not a hardening suggestion): {@link #staleMirrorWarnings()} is rendered
 * on {@code jobs/detail.html}, which any authenticated user can reach ({@code
 * .anyRequest().authenticated()} — see {@code SecurityConfig}), whereas {@code last_sync_error}
 * itself was previously visible only behind {@code /admin/**}'s {@code ROLE_ADMIN} gate. Both
 * {@code GhsaSyncService} and {@code OsvSyncService} store the raw {@code
 * Exception#getMessage()}/transport-error text in that column, which can carry internal detail
 * (host names, JDBC error text, file paths) never meant for a non-admin audience. {@link
 * #checkGhsa}/{@link #checkOsv} therefore show only a fixed, non-leaking sentence pointing the
 * reader at the relevant {@code /admin/*} page for the real detail — the {@code admin/ghsa.html}/
 * {@code admin/osv.html} pages themselves are unaffected and keep showing the raw text, since that
 * surface was already admin-only.
 *
 * <p><b>{@link #staleMirrorWarnings()}'s result is cached for {@link #CACHE_TTL_MILLIS}</b> (senior
 * review on PR #274, round 2): {@code jobs/detail.html} auto-refreshes every 5 seconds
 * while a job is running (see its {@code http-equiv="refresh"}), and {@link
 * RegistryPackageMirrorRepository#maxLastSyncedAt} runs an unindexed {@code MAX(last_synced_at)}
 * over the whole {@code registry_package_mirror} table on every call — adding an index is exactly
 * the kind of schema change the closed-mode architecture gate forbids on this branch (see this
 * class's own CVE.org note above), so a cache is the only closed-mode-legal fix. 5 minutes is far
 * shorter than every mirror's own staleness threshold (2 or 9 days below), so it can never change
 * which side of "stale" a mirror falls on — it only bounds how long a just-fixed sync can take to
 * stop showing the banner.
 *
 * <p><b>CVE.org (closed-mode backlog item 379) is deliberately age-only for now</b> — {@code
 * CveOrgSyncService} does not yet advance {@code cve_org_sync_state} on a failed attempt at all
 * (unlike GHSA/OSV above), so a continuously-failing CVE.org sync simply leaves {@code
 * last_synced_at} frozen at whatever its last real success was, which the age check below already
 * catches on its own without needing a {@code last_sync_error} column. Item 379's actual fix (a
 * schema change plus the corresponding {@code CveOrgSyncService} logic) is being implemented
 * against {@code master}/{@code test} rather than this closed-mode branch directly — the
 * closed-mode architecture gate (see {@code docs/spec/closed-mode-plan.md} §3-2) only allows this
 * branch's diff from {@code master} to be deletions, and {@code CveOrgSyncService}/{@code
 * CveOrgSyncState} are shared, unmodified-here files. Once that fix reaches this branch through the
 * normal master→closed-mode sync (§9-3), {@link #checkCveOrg} should be extended to match {@link
 * #checkGhsa}/{@link #checkOsv}'s error check.
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

    /** See this class's own javadoc ("{@code staleMirrorWarnings()}'s result is cached...") for
     *  why this exists and why 5 minutes is safe. */
    private static final long CACHE_TTL_MILLIS = 5 * 60 * 1000L;

    private final CveOrgSyncStateRepository cveOrgSyncStateRepository;
    private final GhsaSyncStateRepository ghsaSyncStateRepository;
    private final OsvSyncStateRepository osvSyncStateRepository;
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository;
    private final CsafSyncStateRepository csafSyncStateRepository;
    private final RegistryPackageMirrorRepository registryPackageMirrorRepository;

    /**
     * Plain {@code volatile} snapshot + expiry timestamp (same shape as {@code
     * RegistryLookupCache}/{@code CpeNameVariantCache}'s entry records, simplified since this
     * method takes no parameters — there is nothing to key on) rather than a full {@code
     * ConcurrentHashMap}-based cache or Spring's {@code @EnableCaching} (unused anywhere in this
     * codebase). Two threads racing past a stale/absent cache both recomputing and redundantly
     * overwriting each other's result is harmless (the same tolerance {@code RegistryLookupCache}
     * documents for its own equivalent race) — this is a read-only, side-effect-free query, so a
     * lost update here is at most one extra set of DB round trips, never a correctness issue.
     */
    private volatile List<String> cachedWarnings;
    private volatile long cacheExpiresAtMillis;

    /**
     * @return one human-readable (Japanese) warning per mirror currently judged stale —
     *     deliberately not a single boolean, so a caller (currently only {@code JobController}) can
     *     show which specific mirror(s) are the problem rather than just "something, somewhere is
     *     stale". Empty when every mirror looks healthy. Cached for {@link #CACHE_TTL_MILLIS} — see
     *     this class's own javadoc.
     */
    public List<String> staleMirrorWarnings() {
        long now = System.currentTimeMillis();
        List<String> cached = cachedWarnings;
        if (cached != null && now < cacheExpiresAtMillis) {
            return cached;
        }

        List<String> warnings = new ArrayList<>();
        checkCveOrg(warnings);
        checkGhsa(warnings);
        checkOsv(warnings);
        checkNvdCve(warnings);
        checkCsaf(warnings, SiemensCsafSyncService.VENDOR, "CSAF（Siemens）");
        checkCsaf(warnings, RedHatCsafSyncService.VENDOR, "CSAF（Red Hat）");
        checkRegistry(warnings);

        cachedWarnings = warnings;
        cacheExpiresAtMillis = now + CACHE_TTL_MILLIS;
        return warnings;
    }

    /** Age-only for now — see this class's own javadoc for why (closed-mode backlog item 379 has
     *  not landed on this branch yet). */
    private void checkCveOrg(List<String> warnings) {
        CveOrgSyncState state = cveOrgSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineLoaded()) {
            warnings.add("CVE.org: baselineが未読み込みです。");
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
            // Deliberately not state.getLastSyncError() itself — see this class's own javadoc
            // ("The raw last_sync_error text is never shown here").
            warnings.add("GHSA: 直近の同期が失敗しています。管理者に/admin/ghsaで詳細を確認してください。");
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
            // Deliberately not state.getLastSyncError() itself — see this class's own javadoc
            // ("The raw last_sync_error text is never shown here").
            warnings.add("OSV: 直近の同期が失敗しています。管理者に/admin/osvで詳細を確認してください。");
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
