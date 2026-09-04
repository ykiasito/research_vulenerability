package com.vulncheck.app.controller;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.NvdCveSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.NvdCveSyncService;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService.SyncResult;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
import com.vulncheck.app.service.osv.OsvSyncService;
import com.vulncheck.app.service.registry.RegistryMirrorSyncService;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Minimal operational screen for populating the local CPE Dictionary, CVE.org, CSAF vendor
 * advisory, GHSA, registry, and NVD CVE mirrors (see {@link NvdCpeSyncService}, {@link
 * CveOrgSyncService}, {@link SiemensCsafSyncService}, {@link RedHatCsafSyncService}, {@link
 * GhsaSyncService}, {@link RegistryMirrorSyncService}, {@link NvdCveSyncService}). Restricted to
 * {@code ROLE_ADMIN} — see {@code
 * SecurityConfig} (route-level) and {@code AppUserDetailsService} (grants the role to the single
 * account named by the {@code ADMIN_EMAIL} env var, nobody by default).
 */
@Controller
@RequiredArgsConstructor
@Slf4j
public class AdminController {

    private final NvdCpeSyncService nvdCpeSyncService;
    private final UserApiKeyService userApiKeyService;
    private final UserRepository userRepository;
    private final CveOrgSyncService cveOrgSyncService;
    private final SiemensCsafSyncService siemensCsafSyncService;
    private final RedHatCsafSyncService redHatCsafSyncService;
    private final CsafSyncStateRepository csafSyncStateRepository;
    private final GhsaSyncService ghsaSyncService;
    private final GhsaSyncStateRepository ghsaSyncStateRepository;
    private final GhsaSyncFailureRepository ghsaSyncFailureRepository;
    private final OsvSyncService osvSyncService;
    private final OsvSyncStateRepository osvSyncStateRepository;
    private final OsvSyncFailureRepository osvSyncFailureRepository;
    private final RegistryMirrorSyncService registryMirrorSyncService;
    private final NvdCveSyncService nvdCveSyncService;
    private final NvdCveSyncStateRepository nvdCveSyncStateRepository;

    @Value("${app.nvd-cve-backfill.max-requests-per-run:60}")
    private int nvdCveBackfillMaxRequestsPerRun;

    @Value("${app.nvd-cve-backfill.max-duration-minutes:60}")
    private int nvdCveBackfillMaxDurationMinutes;

    @GetMapping("/admin/cpe-dictionary")
    public String form() {
        return "admin/cpe-dictionary";
    }

    @PostMapping("/admin/cpe-dictionary/sync")
    public String sync(@RequestParam("keyword") String keyword, @AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalStateException("認証済みユーザーが見つかりません。"));
        int count = nvdCpeSyncService.syncByKeyword(keyword, userApiKeyService.getNvdApiKey(user.getId()));
        model.addAttribute("result", count + " 件のCPEエントリを同期しました（キーワード: " + keyword + "）。");
        return "admin/cpe-dictionary";
    }

    /**
     * Starts a full (no keyword filter) NVD CPE Dictionary mirror on its own daemon thread and
     * returns immediately — the sync itself takes hours (see {@link
     * NvdCpeSyncService#syncAllAndRelease}). Mirrors {@link
     * com.vulncheck.app.service.CpeDictionaryBootstrapSync}'s startup-triggered sync (same
     * unauthenticated {@code Optional.empty()} call, same daemon-thread-and-forget shape) so this
     * and the {@code CPE_FULL_SYNC_ON_STARTUP} env var remain two independent ways to trigger the
     * same underlying operation. Both go through {@link NvdCpeSyncService#tryBeginFullSync}, which
     * holds the single "already running" guard shared by both trigger paths, so a second click (or
     * a click racing the startup sync) while one is already running doesn't start a concurrent
     * mirror competing for the same NVD rate limit and the same {@code cpe_dictionary} upserts.
     */
    @PostMapping("/admin/cpe-dictionary/sync-all")
    public String cpeFullSync(Model model) {
        if (!nvdCpeSyncService.tryBeginFullSync()) {
            model.addAttribute("result", "フル同期を開始できませんでした: 別のフル同期が既に実行中です。");
            return "admin/cpe-dictionary";
        }

        try {
            startFullSyncWorker();
        } catch (Throwable t) {
            // tryBeginFullSync() above already won the slot, but the worker thread itself never
            // got to run, so syncAllAndRelease()'s own finally-release never fires either —
            // without this, the slot would stay held until the process restarts (task-backlog
            // items 81/136/141).
            nvdCpeSyncService.releaseFullSyncGuard();
            log.error("Full NVD CPE dictionary sync (admin-triggered) failed to start — sync slot released", t);
            model.addAttribute("result", "フル同期の開始に失敗しました。バックエンドのログを確認してください。");
            return "admin/cpe-dictionary";
        }

        model.addAttribute("result",
                "フル同期を開始しました。完了まで数時間かかります。バックエンドのログで進捗を確認してください。");
        return "admin/cpe-dictionary";
    }

    /**
     * Spawns and starts the worker thread that runs the actual sync. Package-private (rather than
     * inlined in {@link #cpeFullSync}) so a unit test can force this step to fail (e.g. via a
     * Mockito spy) without needing a real thread-creation failure (native-thread exhaustion, a
     * SecurityManager denial) to exercise {@link #cpeFullSync}'s guard-release catch block.
     */
    void startFullSyncWorker() {
        Thread worker = new Thread(() -> {
            log.warn("Full NVD CPE dictionary sync starting (admin-triggered) — this takes hours");
            long startedAt = System.currentTimeMillis();
            try {
                SyncOutcome outcome = nvdCpeSyncService.syncAllAndRelease(Optional.empty());
                long minutes = (System.currentTimeMillis() - startedAt) / 60000;
                if (outcome.completed()) {
                    log.warn("Full NVD CPE dictionary sync (admin-triggered) finished: {} entries upserted in {} minutes",
                            outcome.upserted(), minutes);
                } else {
                    log.error("Full NVD CPE dictionary sync (admin-triggered) aborted early after {} entries in {} "
                            + "minutes — dictionary is only partially synced", outcome.upserted(), minutes);
                }
            } catch (Exception e) {
                log.error("Full NVD CPE dictionary sync (admin-triggered) aborted", e);
            }
        }, "cpe-full-sync-admin");
        worker.setDaemon(true);
        worker.start();
    }

    @GetMapping("/admin/cve-org")
    public String cveOrgForm() {
        return "admin/cve-org";
    }

    @PostMapping("/admin/cve-org/sync-delta")
    public String cveOrgSyncDelta(Model model) {
        int count = cveOrgSyncService.syncDelta();
        model.addAttribute("result", count + " 件のCVEレコードを差分同期しました。");
        return "admin/cve-org";
    }

    @PostMapping("/admin/cve-org/sync-baseline")
    public String cveOrgSyncBaseline(Model model) {
        int count = cveOrgSyncService.syncBaseline();
        model.addAttribute("result", count + " 件のCVEレコードを全件投入しました。");
        return "admin/cve-org";
    }

    @GetMapping("/admin/csaf-siemens")
    public String csafSiemensForm(Model model) {
        model.addAttribute("syncState", csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-siemens";
    }

    @PostMapping("/admin/csaf-siemens/sync-delta")
    public String csafSiemensSyncDelta(Model model) {
        SyncResult result = siemensCsafSyncService.syncDelta();
        model.addAttribute("result", describeResult(result, "差分同期"));
        model.addAttribute("syncState", csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-siemens";
    }

    @PostMapping("/admin/csaf-siemens/sync-baseline")
    public String csafSiemensSyncBaseline(Model model) {
        SyncResult result = siemensCsafSyncService.syncBaseline();
        model.addAttribute("result", describeResult(result, "全件同期"));
        model.addAttribute("syncState", csafSyncStateRepository.findById(SiemensCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-siemens";
    }

    private String describeResult(SyncResult result, String label) {
        if (result.alreadyRunning()) {
            return label + "をスキップしました: 別の同期処理が既に実行中です。";
        }
        return label + "が完了しました: " + result.upserted() + " 件のアドバイザリーを同期、" + result.failed() + " 件が失敗しました。";
    }

    @GetMapping("/admin/csaf-redhat")
    public String csafRedHatForm(Model model) {
        model.addAttribute("syncState", csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-redhat";
    }

    @PostMapping("/admin/csaf-redhat/sync-delta")
    public String csafRedHatSyncDelta(Model model) {
        RedHatCsafSyncService.SyncResult result = redHatCsafSyncService.syncDelta();
        model.addAttribute("result", describeRedHatResult(result, "差分同期"));
        model.addAttribute("syncState", csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-redhat";
    }

    @PostMapping("/admin/csaf-redhat/sync-baseline")
    public String csafRedHatSyncBaseline(Model model) {
        RedHatCsafSyncService.SyncResult result = redHatCsafSyncService.syncBaseline();
        model.addAttribute("result", describeRedHatResult(result, "全件同期"));
        model.addAttribute("syncState", csafSyncStateRepository.findById(RedHatCsafSyncService.VENDOR).orElse(null));
        return "admin/csaf-redhat";
    }

    private String describeRedHatResult(RedHatCsafSyncService.SyncResult result, String label) {
        if (result.alreadyRunning()) {
            return label + "をスキップしました: 別の同期処理が既に実行中です。";
        }
        return label + "が完了しました: " + result.upserted() + " 件のアドバイザリーを同期、" + result.failed() + " 件が失敗しました。";
    }

    @GetMapping("/admin/ghsa")
    public String ghsaForm(Model model) {
        model.addAttribute("syncState", ghsaSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", ghsaSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/ghsa";
    }

    @PostMapping("/admin/ghsa/sync-delta")
    public String ghsaSyncDelta(Model model) {
        GhsaSyncService.SyncResult result = ghsaSyncService.syncDelta();
        model.addAttribute("result", describeGhsaResult(result, "差分同期"));
        model.addAttribute("syncState", ghsaSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", ghsaSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/ghsa";
    }

    @PostMapping("/admin/ghsa/sync-baseline")
    public String ghsaSyncBaseline(Model model) {
        GhsaSyncService.SyncResult result = ghsaSyncService.syncBaseline();
        model.addAttribute("result", describeGhsaResult(result, "全件同期"));
        model.addAttribute("syncState", ghsaSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", ghsaSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/ghsa";
    }

    private String describeGhsaResult(GhsaSyncService.SyncResult result, String label) {
        if (result.alreadyRunning()) {
            return label + "をスキップしました: 別の同期処理が既に実行中です。";
        }
        return label + "が完了しました: " + result.upserted() + " 件のアドバイザリーを同期、" + result.failed() + " 件が失敗しました。";
    }

    @GetMapping("/admin/osv")
    public String osvForm(Model model) {
        model.addAttribute("syncState", osvSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", osvSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/osv";
    }

    @PostMapping("/admin/osv/sync-delta")
    public String osvSyncDelta(Model model) {
        OsvSyncService.SyncResult result = osvSyncService.syncDelta();
        model.addAttribute("result", describeOsvResult(result, "差分同期"));
        model.addAttribute("syncState", osvSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", osvSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/osv";
    }

    @PostMapping("/admin/osv/sync-baseline")
    public String osvSyncBaseline(Model model) {
        OsvSyncService.SyncResult result = osvSyncService.syncBaseline();
        model.addAttribute("result", describeOsvResult(result, "全件同期"));
        model.addAttribute("syncState", osvSyncStateRepository.findById((short) 1).orElse(null));
        model.addAttribute("deadLetterCount", osvSyncFailureRepository.countByDeadLetteredAtIsNotNull());
        return "admin/osv";
    }

    private String describeOsvResult(OsvSyncService.SyncResult result, String label) {
        if (result.alreadyRunning()) {
            return label + "をスキップしました: 別の同期処理が既に実行中です。";
        }
        return label + "が完了しました: " + result.upserted() + " 件のレコードを同期、" + result.failed() + " 件が失敗しました。";
    }

    @GetMapping("/admin/registry-mirror")
    public String registryMirrorForm() {
        return "admin/registry-mirror";
    }

    /**
     * Starts a full registry-mirror sync (all 9 ecosystems, see {@link RegistryMirrorSyncService})
     * on its own daemon thread and returns immediately — same shape as {@link #cpeFullSync}. Shares
     * {@link RegistryMirrorSyncService#tryBeginFullSync}'s guard with {@code
     * RegistryMirrorScheduledSync}, so a second click (or a click racing the scheduled resync)
     * while one is already running doesn't start a competing sync against the same 9 ecosystems'
     * rate limits and the same {@code registry_package_mirror} upserts.
     */
    @PostMapping("/admin/registry-mirror/sync-all")
    public String registryMirrorFullSync(Model model) {
        if (!registryMirrorSyncService.tryBeginFullSync()) {
            model.addAttribute("result", "同期を開始できませんでした: 別の同期が既に実行中です。");
            return "admin/registry-mirror";
        }

        try {
            startRegistryMirrorSyncWorker();
        } catch (Throwable t) {
            // Same rationale as cpeFullSync's equivalent catch block (task-backlog items
            // 81/136/141 lineage) — see that method's javadoc.
            registryMirrorSyncService.releaseFullSyncGuard();
            log.error("Registry mirror sync (admin-triggered) failed to start — sync slot released", t);
            model.addAttribute("result", "同期の開始に失敗しました。バックエンドのログを確認してください。");
            return "admin/registry-mirror";
        }

        model.addAttribute("result", "同期を開始しました。完了までしばらくかかります。バックエンドのログで進捗を確認してください。");
        return "admin/registry-mirror";
    }

    /**
     * Spawns and starts the worker thread that runs the actual sync. Package-private (rather than
     * inlined in {@link #registryMirrorFullSync}) so a unit test can force this step to fail (e.g.
     * via a Mockito spy) without needing a real thread-creation failure to exercise {@link
     * #registryMirrorFullSync}'s guard-release catch block.
     */
    void startRegistryMirrorSyncWorker() {
        Thread worker = new Thread(() -> {
            log.warn("Registry mirror sync starting (admin-triggered)");
            long startedAt = System.currentTimeMillis();
            try {
                RegistryMirrorSyncService.SyncOutcome outcome = registryMirrorSyncService.syncAllAndRelease();
                long minutes = (System.currentTimeMillis() - startedAt) / 60000;
                log.warn("Registry mirror sync (admin-triggered) finished in {} minutes: {} synced, {} unresolved, "
                        + "candidate name counts (after freshness filter): {}", minutes, outcome.totalSynced(), outcome.totalUnresolved(),
                        outcome.observedNameCountByEcosystem());
            } catch (Exception e) {
                log.error("Registry mirror sync (admin-triggered) aborted", e);
            }
        }, "registry-mirror-sync-admin");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * Closed-mode backlog item 185: lets an admin add package names to a given ecosystem's mirror
     * seed set directly, alongside {@code identified_products} — see {@link
     * RegistryMirrorSyncService}'s class javadoc for why this exists. Synchronous (unlike {@link
     * #registryMirrorFullSync}): this only writes {@code registry_mirror_seed_name} rows, it doesn't
     * itself call any registry, so there's no long-running work to background here. The names take
     * effect the next time a sync (admin-triggered or scheduled) runs.
     *
     * <p>Reports both the accepted and rejected counts (senior review, PR #126 REVISE) — {@link
     * RegistryMirrorSyncService#addOperatorSuppliedNames} skips (rather than throws for) any name
     * that fails its per-name validation, so without surfacing both counts here an operator would
     * have no way to tell a silently-skipped name apart from one that was never in their submission.
     */
    @PostMapping("/admin/registry-mirror/seed-names")
    public String registryMirrorAddSeedNames(@RequestParam("ecosystem") String ecosystem,
            @RequestParam("names") String namesText, Model model) {
        List<String> names = Arrays.stream(namesText.split("[\\r\\n,]+")).toList();
        try {
            RegistryMirrorSyncService.SeedNameSubmissionOutcome outcome =
                    registryMirrorSyncService.addOperatorSuppliedNames(ecosystem, names);
            model.addAttribute("result", outcome.accepted() + "件の名前をシード一覧に追加しました（" + ecosystem
                    + "）。却下（不正な形式）: " + outcome.rejected() + "件。既に登録済みの名前は無視されます。"
                    + "反映するには「同期を開始」を実行してください。");
        } catch (RegistryMirrorSyncService.SeedNameBatchTooLargeException e) {
            model.addAttribute("result", e.getMessage());
        } catch (IllegalArgumentException e) {
            model.addAttribute("result", "エコシステムの指定が不正です: " + ecosystem);
        }
        return "admin/registry-mirror";
    }

    @GetMapping("/admin/nvd-cve")
    public String nvdCveForm(Model model) {
        model.addAttribute("syncState", nvdCveSyncStateRepository.findById((short) 1).orElse(null));
        return "admin/nvd-cve";
    }

    /**
     * Starts one budgeted backfill tick (see {@link NvdCveSyncService}) on its own daemon thread and
     * returns immediately — same shape as {@link #cpeFullSync}/{@link #registryMirrorFullSync}.
     * Shares {@link NvdCveSyncService#tryBeginRun}'s guard with {@code
     * NvdCveBackfillScheduledRunner}, so a second click (or a click racing the scheduled tick)
     * while one is already running doesn't start a competing run against the same NVD rate limit
     * and the same chunk table. Once the baseline finishes (may take several clicks/ticks — see
     * {@link NvdCveSyncService}'s class javadoc), this becomes a fast no-op.
     */
    @PostMapping("/admin/nvd-cve/sync-now")
    public String nvdCveSyncNow(Model model) {
        if (!nvdCveSyncService.tryBeginRun()) {
            model.addAttribute("result", "同期を開始できませんでした: 別の同期が既に実行中です。");
            return "admin/nvd-cve";
        }

        try {
            startNvdCveBackfillWorker();
        } catch (Throwable t) {
            // Same rationale as cpeFullSync's equivalent catch block (task-backlog items
            // 81/136/141 lineage) — see that method's javadoc.
            nvdCveSyncService.releaseRunGuard();
            log.error("NVD CVE backfill tick (admin-triggered) failed to start — run guard released", t);
            model.addAttribute("result", "同期の開始に失敗しました。バックエンドのログを確認してください。");
            return "admin/nvd-cve";
        }

        model.addAttribute("result", "同期を開始しました。バックエンドのログで進捗を確認してください。");
        return "admin/nvd-cve";
    }

    /**
     * Spawns and starts the worker thread that runs one budgeted backfill tick. Package-private
     * (rather than inlined in {@link #nvdCveSyncNow}) so a unit test can force this step to fail —
     * same rationale as {@link #startFullSyncWorker}.
     */
    void startNvdCveBackfillWorker() {
        Thread worker = new Thread(() -> {
            log.warn("NVD CVE backfill tick starting (admin-triggered)");
            long startedAt = System.currentTimeMillis();
            NvdCveSyncService.RunBudget budget = new NvdCveSyncService.RunBudget(
                    nvdCveBackfillMaxRequestsPerRun, Duration.ofMinutes(nvdCveBackfillMaxDurationMinutes));
            try {
                NvdCveSyncService.SyncOutcome outcome = nvdCveSyncService.runBackfillTickAndRelease(
                        Optional.empty(), budget);
                long seconds = (System.currentTimeMillis() - startedAt) / 1000;
                if (outcome.completed()) {
                    log.warn("NVD CVE backfill tick (admin-triggered) finished the baseline: {} records upserted "
                            + "this tick, {} seconds", outcome.upserted(), seconds);
                } else {
                    log.info("NVD CVE backfill tick (admin-triggered) finished this tick's budget (baseline not "
                            + "yet complete): {} records upserted, {} seconds", outcome.upserted(), seconds);
                }
            } catch (Exception e) {
                log.error("NVD CVE backfill tick (admin-triggered) aborted", e);
            }
        }, "nvd-cve-backfill-admin");
        worker.setDaemon(true);
        worker.start();
    }
}
