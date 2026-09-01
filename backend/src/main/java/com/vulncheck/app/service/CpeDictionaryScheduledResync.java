package com.vulncheck.app.service;

import com.vulncheck.app.service.NvdCpeSyncService.SyncOutcome;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Weekly automatic full re-sync of the NVD CPE Dictionary — closes the continuous-freshness gap
 * described in {@code docs/spec/task-backlog.md} item 135 and designed in {@code
 * docs/spec/cpe-dictionary-mirror-plan.md}: without this, the local {@code cpe_dictionary} mirror
 * only ever refreshes via the one-shot startup sync ({@link CpeDictionaryBootstrapSync}, gated
 * behind {@code CPE_FULL_SYNC_ON_STARTUP}) or a manually-triggered admin sync ({@code
 * AdminController#cpeFullSync}) — both require a human to remember to act, so the mirror silently
 * ages the longer nobody does.
 *
 * <p>Off by default (env var {@code CPE_SCHEDULED_RESYNC_ENABLED}), matching {@code
 * CPE_FULL_SYNC_ON_STARTUP}'s safety-first default: a full sync is ~692MB / ~103 minutes against
 * NVD (measured, see the mirror plan), and running that unattended every week is an operational
 * decision an operator should opt into deliberately, not something that starts firing the moment
 * this code ships to every environment (including throwaway/dev ones).
 *
 * <p>Shares {@link NvdCpeSyncService}'s single {@code fullSyncRunning} guard (via {@link
 * NvdCpeSyncService#tryBeginFullSync}) with the startup- and admin-triggered full syncs — all
 * three trigger the exact same underlying operation against the same NVD rate limit and the same
 * {@code cpe_dictionary} upserts, so only one may run at a time no matter which of the three
 * started it (e.g. a weekly cron tick landing while a just-restarted instance's {@code
 * CPE_FULL_SYNC_ON_STARTUP} sync is still in flight).
 *
 * <p>The sync itself runs on its own daemon thread (same shape as {@code
 * CpeDictionaryBootstrapSync}/{@code AdminController#cpeFullSync}), not on the calling {@code
 * @Scheduled} invocation — Spring's default task scheduler is single-threaded, so a multi-hour
 * sync running directly on it would starve every other {@code @Scheduled} job (the daily
 * CVE.org/GHSA/Red&nbsp;Hat&nbsp;CSAF/Siemens&nbsp;CSAF/OSV delta syncs, job retention cleanup)
 * of their own slots for as long as the sync takes.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class CpeDictionaryScheduledResync {

    private final NvdCpeSyncService nvdCpeSyncService;

    @Value("${app.cpe-scheduled-resync-enabled:false}")
    private boolean enabled;

    /**
     * Sunday 01:30 UTC by default (overridable via {@code CPE_SCHEDULED_RESYNC_CRON}) — ahead of
     * every existing daily delta sync's window (CVE.org 03:30, Siemens CSAF 03:45, GHSA 04:00,
     * Red&nbsp;Hat CSAF 04:15, job retention cleanup 04:00, OSV 05:30; see each {@code
     * *ScheduledSync}/{@code JobRetentionScheduledCleanup}), leaving roughly 2 hours of buffer
     * ahead of the 103-minute measured baseline duration before those jobs would otherwise start.
     * Weekly, not daily, because a full sync is a multi-hour, ~692MB operation — see the mirror
     * plan doc for why weekly was chosen over daily/monthly.
     *
     * <p>senior-reviewer REVISE (PR #75): shifted from 01:00 to 01:30 UTC (=10:30 JST) and made
     * configurable. {@code docs/spec/ec2-deployment-guide.md} has not yet decided between
     * always-on and scheduled (e.g. 10:00-15:00 JST) instance uptime; the old 01:00 UTC (=10:00
     * JST) fixed cron coincided exactly with a 10:00 JST instance start under that second option,
     * and Spring's cron scheduler never fires a trigger that already elapsed before the process
     * was up to register it — so this job could have silently never run, every week, under that
     * deployment shape. If a scheduled-uptime deployment is adopted, whoever configures the
     * instance's start time must set {@code CPE_SCHEDULED_RESYNC_CRON} to a time strictly after
     * that start time (not just close to it), or this failure mode recurs.
     */
    @Scheduled(cron = "${app.cpe-scheduled-resync-cron:0 30 1 * * SUN}", zone = "UTC")
    public void resyncWeekly() {
        if (!enabled) {
            return;
        }
        if (!nvdCpeSyncService.tryBeginFullSync()) {
            log.warn("Scheduled weekly NVD CPE dictionary resync skipped: another full sync is already running");
            return;
        }
        Thread worker = new Thread(this::runFullSync, "cpe-scheduled-resync");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * The actual sync + outcome logging. Callers must have already won {@link
     * NvdCpeSyncService#tryBeginFullSync} before invoking this, exactly like {@link
     * NvdCpeSyncService#syncAllAndRelease} itself requires — this method's only job beyond calling
     * that is turning its {@link SyncOutcome} into the same completed-vs-aborted-early log
     * distinction {@code CpeDictionaryBootstrapSync}/{@code AdminController#cpeFullSync} use.
     *
     * <p>Package-private rather than private so a unit test can invoke it directly on the test
     * thread and assert on its logging/call behavior without having to synchronize with a real
     * background thread.
     */
    void runFullSync() {
        log.warn("Scheduled weekly NVD CPE dictionary resync starting — this takes hours");
        long startedAt = System.currentTimeMillis();
        try {
            SyncOutcome outcome = nvdCpeSyncService.syncAllAndRelease(Optional.empty());
            long minutes = (System.currentTimeMillis() - startedAt) / 60000;
            if (outcome.completed()) {
                log.warn("Scheduled weekly NVD CPE dictionary resync finished: {} entries upserted in {} minutes",
                        outcome.upserted(), minutes);
            } else {
                log.error("Scheduled weekly NVD CPE dictionary resync aborted early after {} entries in {} minutes "
                        + "— dictionary is only partially synced", outcome.upserted(), minutes);
            }
        } catch (Exception e) {
            log.error("Scheduled weekly NVD CPE dictionary resync aborted", e);
        }
    }
}
