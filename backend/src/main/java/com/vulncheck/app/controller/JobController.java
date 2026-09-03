package com.vulncheck.app.controller;

import com.vulncheck.app.entity.IdentifiedProduct;
import com.vulncheck.app.entity.ResearchJob;
import com.vulncheck.app.entity.ResearchJobItem;
import com.vulncheck.app.entity.User;
import com.vulncheck.app.repository.IdentifiedProductRepository;
import com.vulncheck.app.repository.JobItemVulnerabilityCappedView;
import com.vulncheck.app.repository.JobItemVulnerabilityRepository;
import com.vulncheck.app.repository.ResearchJobItemRepository;
import com.vulncheck.app.repository.ResearchJobRepository;
import com.vulncheck.app.repository.UserRepository;
import com.vulncheck.app.service.ColumnMapping;
import com.vulncheck.app.service.CsvParseException;
import com.vulncheck.app.service.CsvParsingService;
import com.vulncheck.app.service.PendingCsvUploadStore;
import com.vulncheck.app.service.ResearchJobProcessingService;
import com.vulncheck.app.service.ResearchJobService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

@Controller
@RequiredArgsConstructor
public class JobController {

    private final ResearchJobService researchJobService;
    private final ResearchJobProcessingService researchJobProcessingService;
    private final ResearchJobRepository researchJobRepository;
    private final ResearchJobItemRepository researchJobItemRepository;
    private final IdentifiedProductRepository identifiedProductRepository;
    private final JobItemVulnerabilityRepository jobItemVulnerabilityRepository;
    private final UserRepository userRepository;
    private final CsvParsingService csvParsingService;
    private final PendingCsvUploadStore pendingCsvUploadStore;

    @GetMapping("/jobs")
    public String list(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User user = currentUser(userDetails);
        model.addAttribute("jobs", researchJobRepository.findByUserIdOrderByCreatedAtDesc(user.getId()));
        return "jobs/list";
    }

    @GetMapping("/jobs/new")
    public String newForm() {
        return "jobs/new";
    }

    /**
     * A ready-to-fill CSV so users don't have to guess the column names/order from prose alone.
     * Prefixed with a UTF-8 BOM — without it, Excel on Windows (the realistic default editor for
     * this app's non-engineer target users) tends to misdetect the encoding and mangle the
     * Japanese usage_text example rows.
     */
    @GetMapping("/jobs/template.csv")
    public ResponseEntity<byte[]> template() {
        String csv = "product_name,version,vendor,usage_text,install_url\r\n"
                + "lodash,4.17.21,,フロントエンドで使う汎用JSユーティリティ,\r\n"
                + "Wireshark,4.6.0,,インフラチームがパケット解析に使用,\r\n";
        byte[] body = ("\uFEFF" + csv).getBytes(StandardCharsets.UTF_8);

        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"vulncheck_template.csv\"")
                .body(body);
    }

    /**
     * The common case — a CSV using this app's own template column names verbatim — is handled
     * inline here with no extra round trip, exactly as before this feature existed. Only a CSV
     * whose headers don't already match gets routed to the column-mapping screen ({@link
     * #confirmMapping}), since asking every user to confirm a mapping even when there's nothing to
     * map would be pure friction for the template-download-and-fill-in workflow this app expects
     * most non-engineer users to follow.
     */
    @PostMapping("/jobs")
    public String upload(
            @AuthenticationPrincipal UserDetails userDetails,
            @RequestParam("csvFile") MultipartFile csvFile,
            @RequestParam(value = "bundledComponentCheck", defaultValue = "false") boolean bundledComponentCheckEnabled,
            Model model) {
        User user = currentUser(userDetails);

        if (csvFile.isEmpty()) {
            model.addAttribute("error", "CSVファイルを選択してください。");
            return "jobs/new";
        }

        byte[] content;
        List<String> headers;
        try {
            content = csvFile.getBytes();
            headers = csvParsingService.peekHeaders(new ByteArrayInputStream(content));
        } catch (CsvParseException e) {
            model.addAttribute("error", e.getMessage());
            return "jobs/new";
        } catch (IOException e) {
            model.addAttribute("error", "アップロードに失敗しました: " + e.getMessage());
            return "jobs/new";
        }

        if (csvParsingService.matchesKnownHeaders(headers)) {
            return createJobAndRedirect(model, user.getId(), csvFile.getOriginalFilename(), content,
                    ColumnMapping.identity(), bundledComponentCheckEnabled);
        }

        String token = pendingCsvUploadStore.store(content, csvFile.getOriginalFilename(), bundledComponentCheckEnabled);
        ColumnMappingForm form = new ColumnMappingForm();
        form.setToken(token);
        autoGuessColumns(form, headers);
        model.addAttribute("headers", headers);
        model.addAttribute("csvFilename", csvFile.getOriginalFilename());
        if (!model.containsAttribute("mappingForm")) {
            model.addAttribute("mappingForm", form);
        }
        return "jobs/mapping";
    }

    /** Best-effort pre-selection so a CSV that's only *slightly* off from the template (different
     *  casing, extra whitespace) doesn't force the user to fill in every dropdown by hand. Purely
     *  a UX nicety — never trusted as a substitute for the user's own confirmation, and every
     *  dropdown remains freely changeable. */
    private void autoGuessColumns(ColumnMappingForm form, List<String> headers) {
        form.setProductNameColumn(guessColumn(headers, ColumnMapping.PRODUCT_NAME));
        form.setVersionColumn(guessColumn(headers, ColumnMapping.VERSION));
        form.setVendorColumn(guessColumn(headers, ColumnMapping.VENDOR));
        form.setUsageTextColumn(guessColumn(headers, ColumnMapping.USAGE_TEXT));
        form.setInstallUrlColumn(guessColumn(headers, ColumnMapping.INSTALL_URL));
    }

    private String guessColumn(List<String> headers, String fieldName) {
        return headers.stream()
                .filter(h -> h.trim().equalsIgnoreCase(fieldName))
                .findFirst()
                .orElse(null);
    }

    @PostMapping("/jobs/confirm-mapping")
    public String confirmMapping(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @ModelAttribute("mappingForm") ColumnMappingForm form,
            BindingResult bindingResult,
            Model model) {
        User user = currentUser(userDetails);

        var pending = pendingCsvUploadStore.get(form.getToken());
        if (pending.isEmpty()) {
            model.addAttribute("error", "アップロードから時間が経過したため、もう一度CSVをアップロードしてください。");
            return "jobs/new";
        }

        if (bindingResult.hasErrors()) {
            model.addAttribute("headers", csvParsingService.peekHeaders(new ByteArrayInputStream(pending.get().content())));
            model.addAttribute("csvFilename", pending.get().filename());
            return "jobs/mapping";
        }

        ColumnMapping mapping = new ColumnMapping(
                form.getProductNameColumn(), form.getVersionColumn(), blankToNull(form.getVendorColumn()),
                form.getUsageTextColumn(), blankToNull(form.getInstallUrlColumn()));

        String result;
        try {
            result = createJobAndRedirect(model, user.getId(), pending.get().filename(), pending.get().content(),
                    mapping, pending.get().bundledComponentCheckEnabled());
        } catch (CsvParseException e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("headers", csvParsingService.peekHeaders(new ByteArrayInputStream(pending.get().content())));
            model.addAttribute("csvFilename", pending.get().filename());
            return "jobs/mapping";
        }
        pendingCsvUploadStore.remove(form.getToken());
        return result;
    }

    /** Lets {@link CsvParseException} propagate to the caller (both {@link #upload} and {@link
     *  #confirmMapping} need to re-render their own, different form view with the error, so
     *  swallowing it here would lose that distinction); only wraps other, unexpected failures. */
    private String createJobAndRedirect(
            Model model, Long userId, String filename, byte[] content, ColumnMapping mapping,
            boolean bundledComponentCheckEnabled) {
        ResearchJob job;
        try {
            job = researchJobService.createJob(
                    userId, filename, new ByteArrayInputStream(content), mapping, bundledComponentCheckEnabled);
        } catch (CsvParseException e) {
            throw e;
        } catch (Exception e) {
            model.addAttribute("error", "アップロードに失敗しました: " + e.getMessage());
            return "jobs/new";
        }

        researchJobProcessingService.processJobAsync(job.getId());
        return "redirect:/jobs/" + job.getId();
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    @Getter
    @Setter
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ColumnMappingForm {

        @NotBlank
        private String token;

        @NotBlank
        private String productNameColumn;

        @NotBlank
        private String versionColumn;

        private String vendorColumn;

        @NotBlank
        private String usageTextColumn;

        private String installUrlColumn;
    }

    /** How many findings the HTML job-detail view renders per item, per category (product findings
     *  and bundled-component findings each capped independently — see {@link
     *  JobItemVulnerabilityRepository#findCappedViewsByJobItemIdIn}'s javadoc). Closed-mode backlog
     *  item 251 (REVISE item 4): item 241's real distribution (64 rows, average ~73 findings/row,
     *  Chrome alone at 2,739) showed the mean already far exceeds anything an HTML table row can
     *  usefully show — 10 keeps the majority of rows (which have far fewer findings than the mean)
     *  fully visible while bounding the worst-case row's rendered size. A CVE never dropped by this
     *  cap: {@code maxFixedVersion} is computed separately (see {@code
     *  Stage2VulnerabilityResearchService}) from the item's full, uncapped finding set, so the
     *  "recommended upgrade version" is never affected by which 10 findings happen to render here. */
    private static final int HTML_DETAIL_FINDING_CAP = 10;

    /** Same idea as {@link #HTML_DETAIL_FINDING_CAP} but for {@link #exportCsv} (REVISE item 4) —
     *  deliberately much larger (200, not 10): a CSV is a downloaded artifact a user may audit
     *  offline, not a live page render, so it's worth keeping far more detail per cell while still
     *  bounding it well clear of Excel's 32,767-character cell limit (200 CVE ids at ~15-17 chars
     *  each plus separators stays in the low thousands of characters, roughly 1/10 of that ceiling —
     *  see {@link #exportCsv}'s own javadoc for the real overflow this replaces: Chrome
     *  127.0.6533.100's 2,739-id unbounded cell measured at ~41,000 characters, already over the
     *  limit). {@code vulnerability_count} itself is never capped (REVISE item 4(a)) — only the
     *  {@code vulnerabilities} cell's own listed ids are. */
    private static final int CSV_EXPORT_FINDING_CAP = 200;

    @GetMapping("/jobs/{id}")
    public String detail(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id, Model model) {
        User user = currentUser(userDetails);
        ResearchJob job = researchJobRepository.findById(id)
                .filter(j -> j.getUserId().equals(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("ジョブが見つかりません。"));

        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(id);
        List<Long> itemIds = items.stream().map(ResearchJobItem::getId).collect(Collectors.toList());
        Map<Long, IdentifiedProduct> identifiedByItemId = identifiedProductRepository.findByJobItemIdIn(itemIds)
                .stream()
                .collect(Collectors.toMap(IdentifiedProduct::getJobItemId, p -> p));
        // Closed-mode backlog items 245/251 (REVISE item 4): capped, not the item's full finding
        // set — see JobItemVulnerabilityRepository#findCappedViewsByJobItemIdIn's javadoc. The
        // "recommended upgrade version" shown per item comes from ResearchJobItem#maxFixedVersion
        // (Stage2-computed from the item's uncapped findings, see that field's own javadoc), not
        // from this capped list, so it's unaffected by which findings happen to be shown here.
        Map<Long, List<JobItemVulnerabilityCappedView>> vulnerabilitiesByItemId =
                jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(itemIds, HTML_DETAIL_FINDING_CAP)
                        .stream()
                        .collect(Collectors.groupingBy(JobItemVulnerabilityCappedView::getJobItemId));

        model.addAttribute("job", job);
        model.addAttribute("items", items);
        model.addAttribute("identifiedByItemId", identifiedByItemId);
        model.addAttribute("vulnerabilitiesByItemId", vulnerabilitiesByItemId);
        return "jobs/detail";
    }

    /** Same UTF-8 BOM {@link #template} prefixes its own CSV with, spelled via code point rather
     *  than an embedded literal so this file never carries an actual raw BOM byte sequence in its
     *  own source. */
    private static final String BOM = Character.toString(0xFEFF);

    private static final CSVFormat EXPORT_CSV_FORMAT = CSVFormat.DEFAULT.builder()
            .setHeader("product_name", "version", "vendor", "status", "ecosystem", "package_or_cpe",
                    "confidence", "vulnerability_count", "vulnerabilities", "bundled_component_findings",
                    "csaf_vendor_status", "research_incomplete_reason")
            .build();

    /**
     * Owner-only (same check as {@link #detail}), same underlying data — a completed or
     * in-progress job's current per-item results as a downloadable CSV, one row per job item.
     * {@code vulnerabilities} is a {@code "; "}-joined list of CVE/GHSA ids (bounded and readable
     * in one cell, unlike the detail view's per-finding severity/link breakdown) so the export
     * stays a flat, spreadsheet-friendly file rather than trying to reproduce every column of the
     * HTML table. Same BOM-prefixed UTF-8 encoding as {@link #template} for Excel compatibility.
     *
     * <p>REVISE item 4 (senior review 2026-08-26): {@code vulnerabilities}/{@code
     * vulnerability_count} keep their original meaning — the product's own findings only — a
     * bundled-component finding (one with a non-null {@code bundledComponentName}) is excluded from
     * both, otherwise an item with a clean product but a vulnerable bundled component (e.g. an
     * embedded 7-Zip) would export as indistinguishable from the product itself having that many
     * real vulnerabilities. Bundled findings instead go in their own {@code
     * bundled_component_findings} column, listing which bundled component(s)/version(s) have known
     * issues — a presence flag for the user to go investigate themselves (this is a triage feature,
     * not an authoritative one — see {@code BundledComponentResearchService}), not a full per-CVE
     * audit trail.
     *
     * <p>REVISE item 10 (senior review 2026-08-27): rows with a non-null {@code csafAdvisoryId} also
     * populate a {@code csaf_vendor_status} column ({@code "CVE-id: status (advisory-id)"} entries,
     * same {@code "; "}-joined shape as {@code vulnerabilities}) — otherwise a CVE a vendor explicitly
     * declared {@code known_not_affected} exported identically to one declared {@code known_affected},
     * which could drive unnecessary remediation work for the CSV's reader. Does not change {@code
     * vulnerability_count}/{@code vulnerabilities} semantics.
     *
     * <p>Task backlog item 103 (2026-08-31): also exports a {@code research_incomplete_reason} column
     * (empty when unset), mirroring {@link ResearchJobItem#getResearchIncompleteReason()} — the job
     * detail view already distinguishes "checked, clean" from "not actually checked" (see item 102),
     * and without this column that distinction was lost the moment the results left the app as a CSV.
     */
    @GetMapping("/jobs/{id}/export.csv")
    public ResponseEntity<byte[]> exportCsv(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        User user = currentUser(userDetails);
        ResearchJob job = researchJobRepository.findById(id)
                .filter(j -> j.getUserId().equals(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("ジョブが見つかりません。"));

        List<ResearchJobItem> items = researchJobItemRepository.findByJobIdOrderById(id);
        List<Long> itemIds = items.stream().map(ResearchJobItem::getId).collect(Collectors.toList());
        Map<Long, IdentifiedProduct> identifiedByItemId = identifiedProductRepository.findByJobItemIdIn(itemIds)
                .stream()
                .collect(Collectors.toMap(IdentifiedProduct::getJobItemId, p -> p));
        // Closed-mode backlog items 245/251 (REVISE item 4): capped at CSV_EXPORT_FINDING_CAP, not
        // the item's full finding set — see findCappedViewsByJobItemIdIn's javadoc. totalCount
        // (below) still reports the TRUE count for vulnerability_count, so capping the listed ids
        // never understates that column.
        Map<Long, List<JobItemVulnerabilityCappedView>> vulnerabilitiesByItemId =
                jobItemVulnerabilityRepository.findCappedViewsByJobItemIdIn(itemIds, CSV_EXPORT_FINDING_CAP)
                        .stream()
                        .collect(Collectors.groupingBy(JobItemVulnerabilityCappedView::getJobItemId));

        String csvBody;
        try (StringWriter writer = new StringWriter();
                CSVPrinter printer = new CSVPrinter(writer, EXPORT_CSV_FORMAT)) {
            for (ResearchJobItem item : items) {
                IdentifiedProduct identified = identifiedByItemId.get(item.getId());
                List<JobItemVulnerabilityCappedView> vulns = vulnerabilitiesByItemId.getOrDefault(item.getId(), List.of());
                List<JobItemVulnerabilityCappedView> productVulns =
                        vulns.stream().filter(v -> v.getBundledComponentName() == null).collect(Collectors.toList());
                List<JobItemVulnerabilityCappedView> bundledVulns =
                        vulns.stream().filter(v -> v.getBundledComponentName() != null).collect(Collectors.toList());
                List<JobItemVulnerabilityCappedView> csafAnnotatedVulns =
                        vulns.stream().filter(v -> v.getCsafAdvisoryId() != null).collect(Collectors.toList());
                // The TRUE total (REVISE item 4(a)) — every row in the same category (product here)
                // carries the same totalCount value from the window query, so the first row's is
                // representative; 0 when there are no product findings for this item at all.
                long trueProductCount = productVulns.isEmpty() ? 0 : productVulns.get(0).getTotalCount();
                String packageOrCpe = identified == null
                        ? null
                        : (identified.getPackageName() != null ? identified.getPackageName() : identified.getCpe());
                printer.printRecord(
                        item.getDisplayProductName(),
                        item.getVersion(),
                        item.getVendor(),
                        item.getStatus(),
                        identified != null ? identified.getEcosystem() : null,
                        packageOrCpe,
                        identified != null ? identified.getConfidence() : null,
                        trueProductCount,
                        capNotice(productVulns.stream().map(JobItemVulnerabilityCappedView::getCveOrGhsaId)
                                .collect(Collectors.joining("; ")), productVulns.size(), trueProductCount),
                        bundledVulns.stream()
                                .map(v -> v.getBundledComponentName() + " " + v.getBundledComponentVersion())
                                .distinct()
                                .collect(Collectors.joining("; ")),
                        csafAnnotatedVulns.stream()
                                .map(v -> v.getCveOrGhsaId() + ": " + v.getCsafStatus() + " (" + v.getCsafAdvisoryId() + ")")
                                .collect(Collectors.joining("; ")),
                        item.getResearchIncompleteReason() != null ? item.getResearchIncompleteReason() : "");
            }
            printer.flush();
            csvBody = writer.toString();
        } catch (IOException e) {
            throw new IllegalStateException("CSVの生成に失敗しました: " + e.getMessage(), e);
        }

        byte[] body = (BOM + csvBody).getBytes(StandardCharsets.UTF_8);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"job_" + id + "_results.csv\"")
                .body(body);
    }

    /** Owner-only. Cascades to the job's items/identified products/vulnerability links at the DB
     *  level (see the FK constraints) — nothing extra to clean up here. */
    @PostMapping("/jobs/{id}/delete")
    public String delete(@AuthenticationPrincipal UserDetails userDetails, @PathVariable Long id) {
        User user = currentUser(userDetails);
        ResearchJob job = researchJobRepository.findById(id)
                .filter(j -> j.getUserId().equals(user.getId()))
                .orElseThrow(() -> new IllegalArgumentException("ジョブが見つかりません。"));
        researchJobRepository.delete(job);
        return "redirect:/jobs";
    }

    private User currentUser(UserDetails userDetails) {
        return userRepository.findByEmail(userDetails.getUsername())
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found: " + userDetails.getUsername()));
    }

    /** Appends a {@code "; 他N件"} suffix to {@code joinedIds} when {@code trueTotal} exceeds {@code
     *  shownCount} (closed-mode backlog item 251, REVISE item 4) — the CSV cell only ever lists the
     *  capped set of ids, but the reader should still be told how many more exist beyond what's
     *  listed (distinct from {@code vulnerability_count}, which is always the true total regardless
     *  of this cell's own cap — REVISE item 4(a)). No-op (returns {@code joinedIds} unchanged) when
     *  every finding is already shown. */
    private String capNotice(String joinedIds, int shownCount, long trueTotal) {
        long hidden = trueTotal - shownCount;
        if (hidden <= 0) {
            return joinedIds;
        }
        String notice = "他" + hidden + "件";
        return joinedIds.isEmpty() ? notice : joinedIds + "; " + notice;
    }
}
