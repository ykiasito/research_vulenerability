package com.vulncheck.app.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class CsvParsingServiceTest {

    private final CsvParsingService service = new CsvParsingService();

    @Test
    void parsesValidCsvWithOptionalColumnsBlank() {
        InputStream csv = toStream("""
                product_name,version,vendor,usage_text,install_url
                lodash,4.17.15,,batch job utility,
                flask,2.0.0,Pallets,internal API server,https://example.com/flask
                """);

        List<ParsedCsvRow> rows = service.parse(csv, ColumnMapping.identity());

        assertThat(rows).hasSize(2);
        assertThat(rows.get(0)).isEqualTo(new ParsedCsvRow("lodash", "4.17.15", null, "batch job utility", null));
        assertThat(rows.get(1))
                .isEqualTo(new ParsedCsvRow("flask", "2.0.0", "Pallets", "internal API server", "https://example.com/flask"));
    }

    @Test
    void rejectsCsvMissingRequiredHeader() {
        InputStream csv = toStream("""
                product_name,version
                lodash,4.17.15
                """);

        assertThatThrownBy(() -> service.parse(csv, ColumnMapping.identity()))
                .isInstanceOf(CsvParseException.class)
                .hasMessageContaining("usage_text");
    }

    @Test
    void rejectsRowWithBlankRequiredField() {
        InputStream csv = toStream("""
                product_name,version,usage_text
                lodash,,batch job utility
                """);

        assertThatThrownBy(() -> service.parse(csv, ColumnMapping.identity()))
                .isInstanceOf(CsvParseException.class);
    }

    @Test
    void rejectsCsvWithNoDataRows() {
        InputStream csv = toStream("product_name,version,usage_text\n");

        assertThatThrownBy(() -> service.parse(csv, ColumnMapping.identity()))
                .isInstanceOf(CsvParseException.class)
                .hasMessageContaining("データ行");
    }

    @Test
    void peekHeadersReturnsRawHeaderRowInFileOrder() {
        InputStream csv = toStream("""
                製品名,Ver,備考
                lodash,4.17.15,internal
                """);

        List<String> headers = service.peekHeaders(csv);

        assertThat(headers).containsExactly("製品名", "Ver", "備考");
    }

    @Test
    void matchesKnownHeadersIsTrueWhenTheThreeRequiredFixedNamesArePresent() {
        // Optional columns (vendor/install_url) don't need to be present at all — identity mapping
        // already tolerates a missing optional column exactly like fixed-header parsing always has.
        assertThat(service.matchesKnownHeaders(List.of("product_name", "version", "usage_text"))).isTrue();
        assertThat(service.matchesKnownHeaders(List.of("product_name", "version", "usage_text", "vendor", "install_url")))
                .isTrue();
    }

    @Test
    void matchesKnownHeadersIsFalseForAnArbitraryRealWorldCsv() {
        assertThat(service.matchesKnownHeaders(List.of("製品名", "バージョン", "用途"))).isFalse();
    }

    @Test
    void parsesAnArbitraryCsvUsingAUserSuppliedColumnMapping() {
        // The whole point of the feature: a CSV with completely different column names/order still
        // parses correctly once the caller supplies which column is which.
        InputStream csv = toStream("""
                備考,製品名,Ver
                internal batch job,lodash,4.17.15
                """);
        ColumnMapping mapping = new ColumnMapping("製品名", "Ver", null, "備考", null);

        List<ParsedCsvRow> rows = service.parse(csv, mapping);

        assertThat(rows).containsExactly(new ParsedCsvRow("lodash", "4.17.15", null, "internal batch job", null));
    }

    @Test
    void rejectsAMappingWhoseRequiredColumnIsNotActuallyInTheCsv() {
        InputStream csv = toStream("""
                製品名,Ver
                lodash,4.17.15
                """);
        // "usage_text" column chosen by the mapping doesn't exist in this CSV at all.
        ColumnMapping mapping = new ColumnMapping("製品名", "Ver", null, "usage_text", null);

        assertThatThrownBy(() -> service.parse(csv, mapping))
                .isInstanceOf(CsvParseException.class);
    }

    @Test
    void gracefullyTreatsAnOptionalColumnNotActuallyInTheCsvAsAbsent() {
        // "vendor" is set on the mapping but this CSV has no such column at all — must degrade to
        // null for that field rather than error, same as identity mapping always has for a CSV
        // that simply omits the optional columns.
        InputStream csv = toStream("""
                製品名,Ver,備考
                lodash,4.17.15,internal
                """);
        ColumnMapping mapping = new ColumnMapping("製品名", "Ver", "vendor", "備考", null);

        List<ParsedCsvRow> rows = service.parse(csv, mapping);

        assertThat(rows).containsExactly(new ParsedCsvRow("lodash", "4.17.15", null, "internal", null));
    }

    @Test
    void aLeadingUtf8BomParsesIdenticallyToTheSameCsvWithoutOne() {
        // Excel's "CSV UTF-8" export prefixes a BOM (U+FEFF) — without stripping it, it survives
        // CSVFormat's setTrim(true) (only strips whitespace <= U+0020) and corrupts the first
        // header cell into "<BOM>product_name".
        String csv = "product_name,version,vendor,usage_text,install_url\n"
                + "lodash,4.17.15,,batch job utility,\n";
        InputStream withBom = new ByteArrayInputStream((Character.toString(0xFEFF) + csv).getBytes(StandardCharsets.UTF_8));
        InputStream withoutBom = toStream(csv);

        List<ParsedCsvRow> rowsWithBom = service.parse(withBom, ColumnMapping.identity());
        List<ParsedCsvRow> rowsWithoutBom = service.parse(withoutBom, ColumnMapping.identity());

        assertThat(rowsWithBom).isEqualTo(rowsWithoutBom);
        assertThat(rowsWithBom).containsExactly(new ParsedCsvRow("lodash", "4.17.15", null, "batch job utility", null));
    }

    @Test
    void matchesKnownHeadersIsTrueForABomPrefixedHeaderRow() {
        InputStream csv = new ByteArrayInputStream(
                (Character.toString(0xFEFF) + "product_name,version,usage_text\nlodash,4.17.15,batch job utility\n")
                        .getBytes(StandardCharsets.UTF_8));

        List<String> headers = service.peekHeaders(csv);

        assertThat(service.matchesKnownHeaders(headers)).isTrue();
    }

    private InputStream toStream(String content) {
        return new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8));
    }
}
