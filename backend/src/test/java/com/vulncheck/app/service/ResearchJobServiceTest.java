package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class ResearchJobServiceTest {

    private final CsvParsingService csvParsingService = new CsvParsingService();

    @Test
    void createJobUsesTheSuppliedColumnMappingToBuildJobItems() {
        ResearchJobRepository researchJobRepository = mock(ResearchJobRepository.class);
        ResearchJobItemRepository researchJobItemRepository = mock(ResearchJobItemRepository.class);
        ResearchJobService service = new ResearchJobService(csvParsingService, researchJobRepository, researchJobItemRepository);

        when(researchJobRepository.save(any(ResearchJob.class))).thenAnswer(inv -> {
            ResearchJob job = inv.getArgument(0);
            job.setId(42L);
            return job;
        });

        InputStream csv = toStream("""
                備考,製品名,Ver
                internal batch job,lodash,4.17.15
                """);
        ColumnMapping mapping = new ColumnMapping("製品名", "Ver", null, "備考", null);

        ResearchJob job = service.createJob(7L, "products.csv", csv, mapping, false);

        assertThat(job.getId()).isEqualTo(42L);
        assertThat(job.getUserId()).isEqualTo(7L);
        assertThat(job.getCsvFilename()).isEqualTo("products.csv");

        ArgumentCaptor<ResearchJobItem> itemCaptor = ArgumentCaptor.forClass(ResearchJobItem.class);
        verify(researchJobItemRepository).save(itemCaptor.capture());
        ResearchJobItem savedItem = itemCaptor.getValue();
        assertThat(savedItem.getJobId()).isEqualTo(42L);
        assertThat(savedItem.getProductName()).isEqualTo("lodash");
        assertThat(savedItem.getVersion()).isEqualTo("4.17.15");
        assertThat(savedItem.getUsageText()).isEqualTo("internal batch job");
        assertThat(savedItem.getVendor()).isNull();
    }

    @Test
    void createJobStripsAnnotationNoiseFromProductNameButKeepsTheRawOriginalForDisplay() {
        ResearchJobRepository researchJobRepository = mock(ResearchJobRepository.class);
        ResearchJobItemRepository researchJobItemRepository = mock(ResearchJobItemRepository.class);
        ResearchJobService service = new ResearchJobService(csvParsingService, researchJobRepository, researchJobItemRepository);

        when(researchJobRepository.save(any(ResearchJob.class))).thenAnswer(inv -> {
            ResearchJob job = inv.getArgument(0);
            job.setId(42L);
            return job;
        });

        InputStream csv = toStream("""
                備考,製品名,Ver
                internal batch job,swA(ホニャホニャ)※備考,4.17.15
                """);
        ColumnMapping mapping = new ColumnMapping("製品名", "Ver", null, "備考", null);

        service.createJob(7L, "products.csv", csv, mapping, false);

        ArgumentCaptor<ResearchJobItem> itemCaptor = ArgumentCaptor.forClass(ResearchJobItem.class);
        verify(researchJobItemRepository).save(itemCaptor.capture());
        ResearchJobItem savedItem = itemCaptor.getValue();
        assertThat(savedItem.getProductName()).isEqualTo("swA");
        assertThat(savedItem.getRawProductName()).isEqualTo("swA(ホニャホニャ)※備考");
        assertThat(savedItem.getDisplayProductName()).isEqualTo("swA(ホニャホニャ)※備考");
    }

    private InputStream toStream(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }
}
