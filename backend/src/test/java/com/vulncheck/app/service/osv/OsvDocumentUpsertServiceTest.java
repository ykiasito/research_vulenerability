package com.vulncheck.app.service.osv;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.repository.OsvAdvisoryRepository;
import com.vulncheck.app.repository.OsvAffectedPackageRepository;
import com.vulncheck.app.repository.OsvAffectedRangeRepository;
import com.vulncheck.app.repository.OsvAffectedVersionRepository;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Mockito-based unit test (repositories mocked, no DB) — mirrors the shape of {@code
 *  GhsaDocumentUpsertServiceTest} but exercises the OSV-specific differences: no {@code raw_json}
 *  argument, a second {@code ghsa_id} alias column alongside {@code cve_id}, and unsupported-
 *  ecosystem {@code affected[]} entries being silently skipped. */
class OsvDocumentUpsertServiceTest {

    private OsvAdvisoryRepository osvAdvisoryRepository;
    private OsvAffectedPackageRepository osvAffectedPackageRepository;
    private OsvAffectedRangeRepository osvAffectedRangeRepository;
    private OsvAffectedVersionRepository osvAffectedVersionRepository;
    private OsvDocumentUpsertService service;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        osvAdvisoryRepository = mock(OsvAdvisoryRepository.class);
        osvAffectedPackageRepository = mock(OsvAffectedPackageRepository.class);
        osvAffectedRangeRepository = mock(OsvAffectedRangeRepository.class);
        osvAffectedVersionRepository = mock(OsvAffectedVersionRepository.class);
        service = new OsvDocumentUpsertService(
                osvAdvisoryRepository, osvAffectedPackageRepository, osvAffectedRangeRepository, osvAffectedVersionRepository);
        when(osvAffectedPackageRepository.insertAndGetId(anyString(), anyString(), anyString(), anyString())).thenReturn(1L);
    }

    private static final String PYSEC_WITH_BOTH_ALIASES = """
            {
              "id": "PYSEC-2023-1", "modified": "2026-08-26T20:48:48Z", "published": "2026-02-25T19:13:32Z",
              "aliases": ["CVE-2023-00001", "GHSA-aaaa-bbbb-cccc"],
              "summary": "Example PyPI advisory", "details": "...",
              "affected": [
                {"package": {"ecosystem": "PyPI", "name": "Example-Pkg"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}
              ],
              "database_specific": {"severity": "high"}
            }
            """;

    @Test
    void upsertsAdvisoryWithBothCveAndGhsaAliases() throws Exception {
        String osvId = service.upsertOsvJson(objectMapper.readTree(PYSEC_WITH_BOTH_ALIASES));

        assertThat(osvId).isEqualTo("PYSEC-2023-1");
        verify(osvAdvisoryRepository).upsert(
                eq("PYSEC-2023-1"), eq("CVE-2023-00001"), eq("GHSA-aaaa-bbbb-cccc"),
                eq("Example PyPI advisory"), eq("..."), eq("HIGH"), isNull(),
                isNull(), eq(OffsetDateTime.parse("2026-02-25T19:13:32Z")), eq(OffsetDateTime.parse("2026-08-26T20:48:48Z")),
                eq("https://osv.dev/vulnerability/PYSEC-2023-1"));
        verify(osvAffectedPackageRepository).deleteByOsvId("PYSEC-2023-1");
        verify(osvAffectedPackageRepository).insertAndGetId("PYSEC-2023-1", "pypi", "Example-Pkg", "example-pkg");
        verify(osvAffectedRangeRepository).insert(1L, "ECOSYSTEM", null, "2.0.0", null);
    }

    @Test
    void normalizesZeroSentinelToNullForPlainZero() throws Exception {
        assertIntroducedSentinelNormalizesToNull("0");
    }

    @Test
    void normalizesZeroSentinelToNullForZeroZeroZero() throws Exception {
        assertIntroducedSentinelNormalizesToNull("0.0.0");
    }

    @Test
    void normalizesZeroSentinelToNullForRustSecZeroZeroZeroDashZero() throws Exception {
        assertIntroducedSentinelNormalizesToNull("0.0.0-0");
    }

    private void assertIntroducedSentinelNormalizesToNull(String sentinel) throws Exception {
        String rustSecStyle = """
                {
                  "id": "RUSTSEC-2023-9", "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                  "aliases": [], "summary": "s",
                  "affected": [
                    {"package": {"ecosystem": "crates.io", "name": "somecrate"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "%s"}, {"fixed": "1.0.0"}]}]}
                  ]
                }
                """
                .formatted(sentinel);

        service.upsertOsvJson(objectMapper.readTree(rustSecStyle));

        verify(osvAffectedRangeRepository).insert(1L, "ECOSYSTEM", null, "1.0.0", null);
    }

    @Test
    void returnsNullAndUpsertsNothingWhenIdIsMissing() throws Exception {
        String malformed = """
                { "modified": "2026-01-01T00:00:00Z", "summary": "no id" }
                """;
        String result = service.upsertOsvJson(objectMapper.readTree(malformed));

        assertThat(result).isNull();
        verifyNoInteractions(osvAdvisoryRepository);
        verifyNoInteractions(osvAffectedPackageRepository);
    }

    @Test
    void returnsNullAndUpsertsNothingWhenModifiedTimestampIsMissing() throws Exception {
        String malformed = """
                { "id": "PYSEC-2023-2", "summary": "no modified" }
                """;
        String result = service.upsertOsvJson(objectMapper.readTree(malformed));

        assertThat(result).isNull();
        verifyNoInteractions(osvAdvisoryRepository);
    }

    @Test
    void skipsAffectedEntriesForUnsupportedEcosystemsButKeepsSupportedOnes() throws Exception {
        String mixed = """
                {
                  "id": "GO-2023-1", "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                  "aliases": [], "summary": "s", "details": "d",
                  "affected": [
                    {"package": {"ecosystem": "Debian", "name": "some-deb-pkg"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]},
                    {"package": {"ecosystem": "Go", "name": "example.com/mod"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5.0"}]}]}
                  ]
                }
                """;
        service.upsertOsvJson(objectMapper.readTree(mixed));

        verify(osvAffectedPackageRepository, times(1)).insertAndGetId(anyString(), anyString(), anyString(), anyString());
        verify(osvAffectedPackageRepository).insertAndGetId("GO-2023-1", "go", "example.com/mod", "example.com/mod");
    }

    @Test
    void mergesTwoAffectedEntriesForTheSamePackageIntoOneRow() throws Exception {
        String twoRanges = """
                {
                  "id": "RUSTSEC-2023-1", "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                  "aliases": [], "summary": "s",
                  "affected": [
                    {"package": {"ecosystem": "crates.io", "name": "somecrate"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}]},
                    {"package": {"ecosystem": "crates.io", "name": "somecrate"},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0"}]}]}
                  ]
                }
                """;
        service.upsertOsvJson(objectMapper.readTree(twoRanges));

        verify(osvAffectedPackageRepository, times(1)).insertAndGetId(
                eq("RUSTSEC-2023-1"), eq("crates.io"), eq("somecrate"), eq("somecrate"));
        verify(osvAffectedRangeRepository, times(2)).insert(any(), eq("ECOSYSTEM"), any(), any(), any());
    }

    @Test
    void withdrawnFieldIsParsedIntoWithdrawnAt() throws Exception {
        String withdrawn = """
                {
                  "id": "PYSEC-2023-3", "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                  "withdrawn": "2026-02-01T00:00:00Z", "aliases": [], "summary": "s", "affected": []
                }
                """;
        service.upsertOsvJson(objectMapper.readTree(withdrawn));

        verify(osvAdvisoryRepository).upsert(
                eq("PYSEC-2023-3"), isNull(), isNull(), eq("s"), isNull(), isNull(), isNull(),
                eq(OffsetDateTime.parse("2026-02-01T00:00:00Z")), eq(OffsetDateTime.parse("2026-01-01T00:00:00Z")),
                eq(OffsetDateTime.parse("2026-01-01T00:00:00Z")), anyString());
    }

    @Test
    void exactVersionEnumerationIsStoredIndependentlyOfRanges() throws Exception {
        String exactVersions = """
                {
                  "id": "EEF-CVE-2026-1", "modified": "2026-01-01T00:00:00Z", "published": "2026-01-01T00:00:00Z",
                  "aliases": [], "summary": "s",
                  "affected": [{"package": {"ecosystem": "Hex", "name": "example_pkg"}, "versions": ["1.0.0", "1.0.1"]}]
                }
                """;
        service.upsertOsvJson(objectMapper.readTree(exactVersions));

        verify(osvAffectedVersionRepository).insert(1L, "1.0.0");
        verify(osvAffectedVersionRepository).insert(1L, "1.0.1");
        verify(osvAffectedRangeRepository, never()).insert(any(), any(), any(), any(), any());
    }
}
