package com.vulncheck.app.service;

public record ParsedCsvRow(
        String productName,
        String version,
        String vendor,
        String usageText,
        String installUrl) {
}
