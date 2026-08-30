package com.vulncheck.app.controller;

import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.repository.GhsaSyncFailureRepository;
import com.vulncheck.app.repository.GhsaSyncStateRepository;
import com.vulncheck.app.repository.OsvSyncFailureRepository;
import com.vulncheck.app.repository.OsvSyncStateRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.NvdCpeSyncService;
import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import com.vulncheck.app.service.UserApiKeyService;
import com.vulncheck.app.service.csaf.RedHatCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService;
import com.vulncheck.app.service.csaf.SiemensCsafSyncService.SyncResult;
import com.vulncheck.app.service.cveorg.CveOrgSyncService;
import com.vulncheck.app.service.ghsa.GhsaSyncService;
import com.vulncheck.app.service.osv.OsvSyncService;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Minimal operational screen for populating the local CPE Dictionary, CVE.org, CSAF vendor
 * advisory, and GHSA mirrors (see {@link NvdCpeSyncService}, {@link CveOrgSyncService}, {@link
 * SiemensCsafSyncService}, {@link RedHatCsafSyncService}, {@link GhsaSyncService}). Restricted to
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

        model.addAttribute("result",
                "フル同期を開始しました。完了まで数時間かかります。バックエンドのログで進捗を確認してください。");
        return "admin/cpe-dictionary";
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
}
