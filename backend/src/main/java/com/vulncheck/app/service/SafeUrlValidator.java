package com.vulncheck.app.service;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Scheme allowlist for any URL an LLM- or vendor-feed-driven research path is about to persist —
 * {@code Stage4WebSearchResearchService}'s {@code citation_url}, {@code BundledComponentResearchService}'s
 * NVD/OSV-sourced {@code url}, and {@code CsafDocumentUpsertService}'s vendor CSAF {@code remediations[].url}
 * (task-backlog item 104 follow-up, senior-reviewer REVISE 2026-09-01 — a Red Hat/Siemens CSAF document's
 * own remediation URL is just as untrusted as an LLM's, and was found reaching the same unescaped {@code
 * th:href} sink unsanitized) all flow into {@code vulnerabilities.url}/{@code job_item_vulnerabilities
 * .citation_url}, which {@code jobs/detail.html} renders directly as {@code th:href} — a clickable link with
 * no further escaping of the scheme. Without this gate a prompt-injected or vendor-feed-injected {@code
 * javascript:}/{@code data:} URL would become live XSS in every user's browser that opens the job detail
 * page.
 *
 * <p>Only {@code http}/{@code https} are allowed through; anything else — including a syntactically
 * malformed value or one with no scheme at all — is dropped to {@code null} rather than escaped and shown
 * as inert text. This matches this app's existing "疑わしきは沈黙" (silence over a confident-but-wrong
 * guess) stance for other low-trust input (see {@code known-limitations.md}'s bundled-component-
 * detection entry): a citation link isn't load-bearing for the rest of the finding (severity/description/
 * fixed_version still persist), so dropping just the URL costs nothing but the click-through.
 *
 * <p>Public (not package-private) so that {@code com.vulncheck.app.service.csaf.CsafDocumentUpsertService}
 * can reuse the exact same allowlist at CSAF ingestion time rather than duplicating the scheme check.
 */
public final class SafeUrlValidator {

    private SafeUrlValidator() {
    }

    /**
     * Returns {@code url} unchanged when its scheme is {@code http}/{@code https} (case-insensitive),
     * otherwise {@code null}. Never throws — a malformed URI is treated the same as a disallowed scheme.
     */
    public static String sanitizeHttpUrl(String url) {
        if (url == null || url.isBlank()) {
            return null;
        }
        String scheme;
        try {
            scheme = new URI(url.trim()).getScheme();
        } catch (URISyntaxException e) {
            return null;
        }
        if (scheme == null) {
            return null;
        }
        return ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme)) ? url : null;
    }
}
