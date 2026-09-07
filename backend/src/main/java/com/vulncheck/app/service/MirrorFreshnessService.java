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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Closed-mode backlog item 382 (promoted to master by item 396): CVE.org, GHSA, OSV and CSAF are
 * mirror-only data sources on both branches -- the {@code *VulnerabilitySource}/sync-service pair
 * for each of these four reads exclusively from its own local mirror table, with no {@code
 * RestClient}-backed live-API fallback to paper over a mirror that never finished its baseline, has
 * gone stale, or has been failing every scheduled run. Before this class, that state was visible
 * only per-mirror on its own {@code /admin/*} page (useful only to an operator who already suspects
 * a problem and knows which page to check) and nowhere at all on the page every user -- not just an
 * admin -- looks at: a job's own {@code jobs/detail.html}. {@link #staleMirrorWarnings()} is the one
 * check both that page (see {@code JobController}) and this class's own tests exercise, so "stale"
 * means the same thing everywhere instead of being redefined ad hoc per page.
 *
 * <p><b>NVD CVE and the package registry mirror are different</b>: on this branch, both still have a
 * live-API fallback path available ({@code NvdVulnerabilitySource}/the 9 {@code *RegistryClient}
 * implementations each still support a live call when their mirror flag is off or the mirror has no
 * entry for a given lookup), so a stale mirror there degrades gracefully rather than silently
 * serving wrong/missing data. {@link #checkNvdCve}/{@link #checkRegistry} are therefore gated behind
 * {@link #nvdCveCheckEnabled}/{@link #registryCheckEnabled} (both default {@code true} in code --
 * see each field's own javadoc for why the shipped {@code application.yml} still overrides both to
 * {@code false} by default) rather than running unconditionally like the four mirror-only checks
 * above.
 *
 * <p><b>What counts as stale, per mirror</b> — deliberately more than just "hasn't synced in a
 * while":
 *
 * <ol>
 *   <li>baseline never completed at all (nothing to serve yet);
 *   <li>for GHSA/OSV/CVE.org (which all carry a {@code last_sync_error} column), the mirror's own
 *       sync state records an error from its most recent attempt — non-null there distinguishes "ran
 *       and failed" from "ran and succeeded", since {@code GhsaSyncService}/{@code OsvSyncService}/
 *       {@code CveOrgSyncService} all advance {@code last_synced_at} on every attempt, success or
 *       failure, so an age-only check alone would otherwise treat a mirror that fails every
 *       scheduled run as "recently synced" forever;
 *   <li>the last successful sync is older than this mirror's own freshness threshold.
 * </ol>
 *
 * <p><b>The raw {@code last_sync_error} text is never shown here</b>: {@link
 * #staleMirrorWarnings()} is rendered on {@code jobs/detail.html}, which any authenticated user can
 * reach ({@code .anyRequest().authenticated()} — see {@code SecurityConfig}), whereas {@code
 * last_sync_error} itself is visible only behind {@code /admin/**}'s {@code ROLE_ADMIN} gate. {@code
 * GhsaSyncService}/{@code OsvSyncService}/{@code CveOrgSyncService} store the raw {@code
 * Exception#getMessage()}/transport-error text in that column, which can carry internal detail
 * (host names, JDBC error text, file paths) never meant for a non-admin audience. {@link
 * #checkCveOrg}/{@link #checkGhsa}/{@link #checkOsv} therefore show only a fixed, non-leaking
 * sentence pointing the reader at the relevant {@code /admin/*} page for the real detail — the
 * {@code admin/cve-org.html}/{@code admin/ghsa.html}/{@code admin/osv.html} pages themselves are
 * unaffected and keep showing the raw text, since that surface was already admin-only.
 *
 * <p><b>{@link #staleMirrorWarnings()}'s result is cached for {@link #CACHE_TTL_MILLIS}</b>: {@code
 * jobs/detail.html} auto-refreshes every 5 seconds while a job is running (see its {@code
 * http-equiv="refresh"}), and each refresh's {@code staleMirrorWarnings()} call fans out to up to
 * six {@code findById} round trips (one per mirror's own sync-state repository) plus {@link
 * RegistryPackageMirrorRepository#maxLastSyncedAt}'s {@code MAX(last_synced_at)} query — without
 * this cache, that whole fan-out would re-run on every single 5-second refresh for as long as a job
 * keeps running, not just once. The cache bounds that to once per {@link #CACHE_TTL_MILLIS} per
 * process instead. 5 minutes is far shorter than every mirror's own staleness threshold (2 or 9 days
 * below), so it can never change which side of "stale" a mirror falls on — it only bounds how long a
 * just-fixed sync can take to stop showing the banner.
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
     * Gates {@link #checkNvdCve} (closed-mode backlog item 396). Defaults to {@code true} in code
     * -- unlike the flags under {@code app.closed-mode.*}, this class must never read one of those
     * keys directly: closed mode deletes {@code app.closed-mode.*} from its own {@code
     * application.yml} entirely, and reading a key that's absent from the active profile silently
     * falls back to whatever default is coded here -- {@code true} would then wrongly force this
     * check on in closed mode even though it has its own dedicated NVD-mirror flag already covering
     * the same case. The shipped {@code application.yml} bundles this to the exact same environment
     * variable as {@code app.closed-mode.nvd-mirror-enabled} ({@code
     * CLOSED_MODE_NVD_MIRROR_ENABLED}) precisely so the two can never drift apart operationally.
     */
    @Value("${app.mirror-freshness.nvd-cve-check-enabled:true}")
    private boolean nvdCveCheckEnabled;

    /**
     * Gates {@link #checkRegistry} (closed-mode backlog item 396). Defaults to {@code true} in
     * code, same rationale as {@link #nvdCveCheckEnabled}. There is no single {@code
     * app.closed-mode.*-mirror-enabled} flag this can bundle onto (there are 9, one per ecosystem,
     * and this check is ecosystem-agnostic — see {@link RegistryPackageMirrorRepository#maxLastSyncedAt}),
     * so this has its own dedicated env var instead ({@code MIRROR_FRESHNESS_REGISTRY_CHECK_ENABLED}
     * — see {@code application.yml}'s comment on when to flip it).
     */
    @Value("${app.mirror-freshness.registry-check-enabled:true}")
    private boolean registryCheckEnabled;

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
        if (nvdCveCheckEnabled) {
            checkNvdCve(warnings);
        }
        checkCsaf(warnings, SiemensCsafSyncService.VENDOR, "CSAF（Siemens）");
        checkCsaf(warnings, RedHatCsafSyncService.VENDOR, "CSAF（Red Hat）");
        if (registryCheckEnabled) {
            checkRegistry(warnings);
        }

        List<String> immutableWarnings = List.copyOf(warnings);
        cachedWarnings = immutableWarnings;
        cacheExpiresAtMillis = now + CACHE_TTL_MILLIS;
        return immutableWarnings;
    }

    private void checkCveOrg(List<String> warnings) {
        CveOrgSyncState state = cveOrgSyncStateRepository.findById((short) 1).orElse(null);
        if (state == null || !state.isBaselineLoaded()) {
            warnings.add("CVE.org: baselineが未読み込みです。");
            return;
        }
        if (state.getLastSyncError() != null) {
            // Deliberately not state.getLastSyncError() itself — see this class's own javadoc
            // ("The raw last_sync_error text is never shown here").
            warnings.add("CVE.org: 直近の同期が失敗しています。管理者に/admin/cve-orgで詳細を確認してください。");
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
