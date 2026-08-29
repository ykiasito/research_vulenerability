package com.vulncheck.app.service;

/**
 * Maps this app's fixed logical fields to whatever column header a user's actual CSV happens to
 * use for each — lets {@link CsvParsingService} read an arbitrary/messy real-world CSV instead of
 * requiring the exact column names {@code product_name}/{@code version}/{@code vendor}/
 * {@code usage_text}/{@code install_url}. {@code vendorColumn}/{@code installUrlColumn} are the
 * only optional fields; null means "this CSV has no such column, leave it blank."
 */
public record ColumnMapping(
        String productNameColumn,
        String versionColumn,
        String vendorColumn,
        String usageTextColumn,
        String installUrlColumn) {

    public static final String PRODUCT_NAME = "product_name";
    public static final String VERSION = "version";
    public static final String VENDOR = "vendor";
    public static final String USAGE_TEXT = "usage_text";
    public static final String INSTALL_URL = "install_url";

    /** For a CSV that already uses this app's own template column names verbatim — the common
     *  case (downloaded {@code /jobs/template.csv} and filled it in) skips the mapping screen
     *  entirely via this identity mapping. */
    public static ColumnMapping identity() {
        return new ColumnMapping(PRODUCT_NAME, VERSION, VENDOR, USAGE_TEXT, INSTALL_URL);
    }
}
