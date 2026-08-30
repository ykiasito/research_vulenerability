package com.vulncheck.app.service;

import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import java.io.InputStream;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Parses an uploaded CSV and persists the resulting job + items. Kicking off the async Stage1
 * processing is deliberately left to the caller (see {@link ResearchJobProcessingService}) so
 * that it only starts after this transaction has committed — calling an {@code @Async} method
 * from within this same (proxied) service would skip the proxy via self-invocation, and calling
 * it before commit would race the worker thread against uncommitted data.
 */
@Service
@RequiredArgsConstructor
public class ResearchJobService {

    private final CsvParsingService csvParsingService;
    private final ResearchJobRepository researchJobRepository;
    private final ResearchJobItemRepository researchJobItemRepository;

    @Transactional
    public ResearchJob createJob(
            Long userId, String csvFilename, InputStream csvInputStream, ColumnMapping mapping,
            boolean bundledComponentCheckEnabled) {
        List<ParsedCsvRow> rows = csvParsingService.parse(csvInputStream, mapping);

        ResearchJob job = new ResearchJob();
        job.setUserId(userId);
        job.setCsvFilename(csvFilename);
        job.setStatus(ResearchJob.STATUS_PENDING);
        job.setBundledComponentCheckEnabled(bundledComponentCheckEnabled);
        job = researchJobRepository.save(job);

        for (ParsedCsvRow row : rows) {
            ResearchJobItem item = new ResearchJobItem();
            item.setJobId(job.getId());
            item.setRawProductName(row.productName());
            item.setProductName(ProductNameAnnotationStripper.strip(row.productName()));
            item.setVersion(row.version());
            item.setVendor(row.vendor());
            item.setUsageText(row.usageText());
            item.setInstallUrl(row.installUrl());
            item.setStatus(ResearchJobItem.STATUS_PENDING);
            researchJobItemRepository.save(item);
        }

        return job;
    }
}
