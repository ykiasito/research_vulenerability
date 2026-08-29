package com.vulncheck.app.repository;

import static org.assertj.core.api.Assertions.assertThat;

import com.vulncheck.app.entity.JobCostLedgerEntry;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.entity.User;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.math.BigDecimal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

/**
 * Exercises {@link JobCostLedgerRepository} against a real Postgres instance (V23's new table)
 * and, in {@link #jobDollarPerItemAverageCanBeExtractedViaSql}, demonstrates the exact query shape
 * that satisfies docs/spec/infra-rollout-plan.md item 5's completion definition: "for a completed
 * job, its $/item average can be extracted via SQL after the fact". {@code @DataJpaTest} wraps
 * each test in a transaction rolled back afterward, so nothing written here is persisted past the
 * test run.
 */
@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class JobCostLedgerRepositoryTest {

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ResearchJobRepository researchJobRepository;
    @Autowired
    private ResearchJobItemRepository researchJobItemRepository;
    @Autowired
    private JobCostLedgerRepository jobCostLedgerRepository;

    @PersistenceContext
    private EntityManager entityManager;

    private Long newJobWithItems(int itemCount) {
        User user = new User();
        user.setEmail("job-cost-ledger-repo-test-" + System.nanoTime() + "@example.com");
        user.setPasswordHash("hash");
        user = userRepository.save(user);

        ResearchJob job = new ResearchJob();
        job.setUserId(user.getId());
        job.setCsvFilename("test.csv");
        job.setStatus(ResearchJob.STATUS_COMPLETED);
        job = researchJobRepository.save(job);

        for (int i = 0; i < itemCount; i++) {
            ResearchJobItem item = new ResearchJobItem();
            item.setJobId(job.getId());
            item.setProductName("widget-" + i);
            item.setVersion("1.0.0");
            item.setUsageText("test");
            item.setStatus(ResearchJobItem.STATUS_IDENTIFIED);
            researchJobItemRepository.save(item);
        }
        return job.getId();
    }

    private JobCostLedgerEntry ledgerEntry(
            Long jobId, Long jobItemId, String ledger, String reservedCostUsd, String actualCostUsd) {
        JobCostLedgerEntry entry = new JobCostLedgerEntry();
        entry.setJobId(jobId);
        entry.setJobItemId(jobItemId);
        entry.setLedger(ledger);
        entry.setReservedCostUsd(new BigDecimal(reservedCostUsd));
        entry.setActualCostUsd(new BigDecimal(actualCostUsd));
        return entry;
    }

    @Test
    void findByJobIdOrderByRecordedAtReturnsOnlyThatJobsRows() {
        Long jobId = newJobWithItems(1);
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(jobId);
        Long itemId = items.get(0).getId();
        Long otherJobId = newJobWithItems(1);

        jobCostLedgerRepository.save(ledgerEntry(jobId, itemId, JobCostLedgerEntry.LEDGER_MAIN, "0.003", "0.002"));
        jobCostLedgerRepository.save(ledgerEntry(otherJobId, null, JobCostLedgerEntry.LEDGER_MAIN, "0.003", "0.001"));

        List<JobCostLedgerEntry> rows = jobCostLedgerRepository.findByJobIdOrderByRecordedAt(jobId);

        assertThat(rows).hasSize(1);
        assertThat(rows.get(0).getJobId()).isEqualTo(jobId);
        assertThat(rows.get(0).getJobItemId()).isEqualTo(itemId);
        assertThat(rows.get(0).getActualCostUsd()).isEqualByComparingTo("0.002");
    }

    @Test
    void sumActualCostUsdByJobIdAddsUpBothLedgersAndIsZeroNotNullWithNoRows() {
        Long jobId = newJobWithItems(1);
        Long itemId = researchJobItemRepository.findByJobIdOrderById(jobId).get(0).getId();

        assertThat(jobCostLedgerRepository.sumActualCostUsdByJobId(jobId)).isEqualByComparingTo("0");

        jobCostLedgerRepository.save(ledgerEntry(jobId, itemId, JobCostLedgerEntry.LEDGER_MAIN, "0.003", "0.0021"));
        jobCostLedgerRepository.save(
                ledgerEntry(jobId, itemId, JobCostLedgerEntry.LEDGER_BUNDLED_COMPONENT, "0.015", "0.0090"));

        assertThat(jobCostLedgerRepository.sumActualCostUsdByJobId(jobId)).isEqualByComparingTo("0.0111");
    }

    /**
     * Runs the actual post-hoc "$/item average for this job" SQL query — the completion definition
     * for docs/spec/infra-rollout-plan.md item 5 — against real data inserted through the
     * repository, using a native query with two independent scalar subqueries (total realized spend
     * for the job; total item count for the job) rather than a single JOIN. A JOIN of
     * research_job_items to job_cost_ledger on job_id alone would fan out N items x M ledger rows
     * and multiply, not average, the sum — this shape avoids that.
     */
    @Test
    void jobDollarPerItemAverageCanBeExtractedViaSql() {
        Long jobId = newJobWithItems(4); // a $5/1,000-item-scale job, in miniature: 4 items
        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(jobId);

        // Only 2 of the 4 items happened to trigger an AI call — the average must still be computed
        // over all 4 items in the job, not just the 2 that have ledger rows, since the $5/1,000
        // target is defined per item in the job, not per item that used AI.
        jobCostLedgerRepository.save(
                ledgerEntry(jobId, items.get(0).getId(), JobCostLedgerEntry.LEDGER_MAIN, "0.003", "0.0020"));
        jobCostLedgerRepository.save(
                ledgerEntry(jobId, items.get(1).getId(), JobCostLedgerEntry.LEDGER_MAIN, "0.030", "0.0260"));

        BigDecimal avgCostPerItem = (BigDecimal) entityManager.createNativeQuery(
                        """
                        SELECT (SELECT COALESCE(SUM(actual_cost_usd), 0) FROM job_cost_ledger WHERE job_id = :jobId)
                             / (SELECT COUNT(*) FROM research_job_items WHERE job_id = :jobId)
                        """)
                .setParameter("jobId", jobId)
                .getSingleResult();

        // (0.0020 + 0.0260) / 4 items = 0.0070
        assertThat(avgCostPerItem).isEqualByComparingTo("0.0070000000");
    }
}
