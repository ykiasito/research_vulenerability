package com.vulncheck.app.service;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PushbackInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.springframework.stereotype.Service;

/**
 * Parses and validates the CSV a user uploads for a research job. Required fields: product name,
 * version, usage text. Optional: vendor, install URL. Column *names* in the actual CSV don't have
 * to match this app's own — see {@link ColumnMapping}; {@link #matchesKnownHeaders} lets the
 * caller skip the mapping screen entirely when they don't need to (the common case: the user
 * downloaded {@code /jobs/template.csv} and filled it in verbatim).
 */
@Service
public class CsvParsingService {

    private static final Set<String> REQUIRED_FIELD_NAMES =
            Set.of(ColumnMapping.PRODUCT_NAME, ColumnMapping.VERSION, ColumnMapping.USAGE_TEXT);

    private static final CSVFormat FORMAT = CSVFormat.DEFAULT.builder()
            .setHeader()
            .setSkipHeaderRecord(true)
            .setTrim(true)
            .setIgnoreSurroundingSpaces(true)
            .build();

    /** Just the header row, in file order — for rendering the column-mapping screen's dropdowns. */
    public List<String> peekHeaders(InputStream csvInputStream) {
        try (CSVParser parser = CSVParser.parse(new InputStreamReader(stripUtf8Bom(csvInputStream), StandardCharsets.UTF_8), FORMAT)) {
            return List.copyOf(parser.getHeaderNames());
        } catch (IOException e) {
            throw new CsvParseException("CSVの読み込みに失敗しました: " + e.getMessage());
        }
    }

    /** True when this app's own fixed column names for the *required* fields are already present
     *  verbatim — {@link ColumnMapping#identity()} can be used and the mapping screen skipped. The
     *  two optional fields don't need to be present at all (identity mapping already tolerates a
     *  missing {@code vendor}/{@code install_url} column exactly like today's fixed-header parsing
     *  always has), so they're not part of this check. */
    public boolean matchesKnownHeaders(List<String> headers) {
        Set<String> trimmed = headers.stream().map(String::trim).collect(java.util.stream.Collectors.toSet());
        return trimmed.containsAll(REQUIRED_FIELD_NAMES);
    }

    public List<ParsedCsvRow> parse(InputStream csvInputStream, ColumnMapping mapping) {
        try (CSVParser parser = CSVParser.parse(new InputStreamReader(stripUtf8Bom(csvInputStream), StandardCharsets.UTF_8), FORMAT)) {
            Set<String> headers = parser.getHeaderNames().stream().map(String::trim).collect(java.util.stream.Collectors.toSet());
            requireMappedAndPresent(headers, ColumnMapping.PRODUCT_NAME, mapping.productNameColumn());
            requireMappedAndPresent(headers, ColumnMapping.VERSION, mapping.versionColumn());
            requireMappedAndPresent(headers, ColumnMapping.USAGE_TEXT, mapping.usageTextColumn());
            // Optional fields are intentionally NOT validated for presence here: ColumnMapping.
            // identity()'s default "vendor"/"install_url" column names are conventions, not a
            // user-confirmed selection, and a CSV legitimately may not have them at all (the
            // common case: only the 3 required columns) — value() below already degrades a
            // missing/unselected optional column to null via CSVRecord#isMapped, exactly like
            // fixed-header parsing always has.

            List<ParsedCsvRow> rows = new ArrayList<>();
            for (CSVRecord record : parser) {
                String productName = value(record, mapping.productNameColumn());
                String version = value(record, mapping.versionColumn());
                String usageText = value(record, mapping.usageTextColumn());
                String vendor = value(record, mapping.vendorColumn());
                String installUrl = value(record, mapping.installUrlColumn());

                if (isBlank(productName) || isBlank(version) || isBlank(usageText)) {
                    throw new CsvParseException(
                            (record.getRecordNumber() + 1) + "行目: 製品名, バージョン, 用途は必須です。");
                }

                rows.add(new ParsedCsvRow(
                        productName, version, blankToNull(vendor), usageText, blankToNull(installUrl)));
            }

            if (rows.isEmpty()) {
                throw new CsvParseException("CSVにデータ行がありません。");
            }

            return rows;
        } catch (IOException e) {
            throw new CsvParseException("CSVの読み込みに失敗しました: " + e.getMessage());
        }
    }

    /**
     * Strips a leading UTF-8 BOM (EF BB BF), if present, before the stream is handed to {@link
     * InputStreamReader}. Excel's "CSV UTF-8" export writes one, and left in place it survives
     * {@link CSVFormat}'s {@code setTrim(true)} (which only strips whitespace &le; U+0020, not
     * U+FEFF) and silently corrupts the first header cell into e.g. {@code "<BOM>product_name"} —
     * a mismatch {@link #matchesKnownHeaders}/{@link #requireMappedAndPresent} can't see through.
     * Shared by both {@link #peekHeaders} and {@link #parse} so the two never drift. Charset stays
     * fixed at UTF-8 (see class-level scope note) — this only ever looks for the UTF-8 BOM's own
     * 3-byte sequence, nothing else.
     */
    private InputStream stripUtf8Bom(InputStream in) {
        PushbackInputStream pushback = new PushbackInputStream(in, 3);
        try {
            byte[] lookahead = new byte[3];
            int read = pushback.read(lookahead, 0, 3);
            if (read == 3 && (lookahead[0] & 0xFF) == 0xEF && (lookahead[1] & 0xFF) == 0xBB && (lookahead[2] & 0xFF) == 0xBF) {
                return pushback; // BOM consumed, not pushed back — the reader never sees it.
            }
            if (read > 0) {
                pushback.unread(lookahead, 0, read);
            }
            return pushback;
        } catch (IOException e) {
            throw new CsvParseException("CSVの読み込みに失敗しました: " + e.getMessage());
        }
    }

    /** A required logical field's chosen column must actually be selected and exist in this CSV. */
    private void requireMappedAndPresent(Set<String> headers, String fieldLabel, String chosenColumn) {
        if (isBlank(chosenColumn) || !headers.contains(chosenColumn)) {
            throw new CsvParseException("必須項目「" + fieldLabel + "」に対応する列が選択されていないか、CSVに見つかりません。");
        }
    }

    private String value(CSVRecord record, String column) {
        return column != null && record.isMapped(column) ? record.get(column) : null;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private String blankToNull(String value) {
        return isBlank(value) ? null : value;
    }
}
