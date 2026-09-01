package com.vulncheck.app.service.csaf;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vulncheck.app.entity.CsafSyncState;
import com.vulncheck.app.repository.CsafSyncStateRepository;
import com.vulncheck.app.service.ratelimit.ExternalRegistryRateLimiter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

/**
 * Syncs Siemens ProductCERT's CSAF advisories (single ROLIE feed, no authentication) into the
 * local mirror via the shared {@link CsafDocumentUpsertService} — see
 * {@code docs/spec/csaf-vendor-advisory-plan.md} §4-1 for the design sketch this follows, and §4-4
 * for why Siemens (not Red Hat) ships first.
 *
 * <p><b>Bulk archive vs. per-document (plan §5-6):</b> confirmed live 2026-08-27 that Siemens'
 * {@code provider-metadata.json} advertises only a ROLIE feed distribution, no directory-style bulk
 * archive (CSAF's own archive convention) — a manual probe of plausible archive paths under {@code
 * cert-portal.siemens.com/productcert/csaf/} (e.g. {@code archive/}, {@code archive/index.json})
 * also returned 403 for all of them. Per-document GET, paced, is therefore the documented fallback
 * this class uses, not a shortcut taken without checking.
 *
 * <p><b>Hash verification (plan §6):</b> confirmed live that Siemens' ROLIE entries do NOT carry an
 * inline hash — each entry's {@code link[rel=hash]} instead points at a {@code .sha512} (never
 * {@code .sha256} in the entries observed) sidecar file containing the bare lowercase hex digest.
 * {@link #verifyHash} fetches that sidecar and compares it before ever calling {@link
 * CsafDocumentUpsertService#upsertCsafDocument} — a mismatch, or a failure to fetch the sidecar at
 * all, skips the document and counts it as a sync failure (conservative: an unverifiable document
 * from a source this app treats as authoritative, per the plan's §0-1 principle 2, is not upserted).
 *
 * <p><b>§5-5 merge-gate table (measured 2026-08-27 against the live feed — mirrored from {@code
 * docs/spec/csaf-vendor-advisory-plan.md} §5-5, which is the authoritative copy; kept in sync
 * manually, same convention as {@code NvdRateLimiter}'s interval constants):</b>
 *
 * <table border="1">
 * <caption>Siemens CSAF sync — measured rate/volume</caption>
 * <tr><th>baseline doc count</th><th>pacing</th><th>baseline wall-clock</th><th>delta docs/day</th><th>cron</th><th>worst-case req/hour</th></tr>
 * <tr><td>831 ROLIE entries (measured)</td><td>500ms/request ({@code
 *     ExternalRegistryRateLimiter}, key {@code siemens_csaf})</td><td>measured 18.7 minutes for
 *     831 single-request fetches at the 500ms floor; this class's actual {@link #syncBaseline}
 *     issues 2 requests/document (content + hash sidecar), so a real run is projected at roughly
 *     30-40 minutes — that projection is an extrapolation, not itself measured, and is labeled as
 *     such deliberately</td><td>measured 0-2/day (19 of 831 entries had an `updated` timestamp
 *     within the trailing 30 days, 2026-08-27)</td><td>daily at 03:45 UTC, offset from {@code
 *     CveOrgScheduledSync}'s 03:30 UTC slot</td><td>7,200 (the fixed-interval ceiling; actual
 *     traffic is far below this except during a baseline run)</td></tr>
 * </table>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SiemensCsafSyncService {

    public static final String VENDOR = "siemens";
    private static final String PROVIDER_METADATA_URL = "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json";
    private static final Set<String> ALLOWED_HOSTS = Set.of("cert-portal.siemens.com");
    private static final String RATE_LIMIT_KEY = "siemens_csaf";

    private static final int MAX_REDIRECTS = 3;
    private static final long MAX_DOCUMENT_BYTES = 10L * 1024 * 1024; // real max observed ~1.1MB (2026-08-27)
    private static final long MAX_HASH_BYTES = 4_096;

    /** Headroom above the measured 831-entry baseline (see class javadoc) — a run that would
     *  otherwise process more than this leaves the remainder for the next scheduled/triggered run
     *  rather than an unbounded single execution (plan §5-7). */
    static final int MAX_DOCUMENTS_PER_RUN = 2_000;

    private final RestClient csafSyncRestClient;
    private final ExternalRegistryRateLimiter rateLimiter;
    private final CsafDocumentUpsertService documentUpsertService;
    private final CsafSyncStateRepository syncStateRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /** Per-vendor "sync already running" guard (plan §5-4) — in-process only, matching this
     *  codebase's existing single-instance assumption ({@code NvdRateLimiter}/{@code
     *  ExternalRegistryRateLimiter} are themselves plain in-JVM state, not distributed locks), so a
     *  manually-triggered baseline sync and the scheduled delta sync can never race each other. */
    private final AtomicBoolean running = new AtomicBoolean(false);

    public record SyncResult(int upserted, int failed, boolean alreadyRunning) {
    }

    /** Full re-walk of the feed (ignores any existing cursor) — manually triggered only, see {@code
     *  AdminController}, mirroring {@code CveOrgSyncService#syncBaseline}'s "never {@code
     *  @Scheduled}" precedent. */
    public SyncResult syncBaseline() {
        return sync(true);
    }

    /** Only entries newer than the last saved cursor — safe to run routinely; see {@link
     *  SiemensCsafScheduledSync}. */
    public SyncResult syncDelta() {
        return sync(false);
    }

    private SyncResult sync(boolean baseline) {
        if (!running.compareAndSet(false, true)) {
            log.warn("Siemens CSAF sync skipped: another sync for this vendor is already running");
            return new SyncResult(0, 0, true);
        }
        try {
            return doSync(baseline);
        } finally {
            running.set(false);
        }
    }

    /** REVISE item 4 (senior review 2026-08-27, HIGH — see {@code RedHatCsafSyncService}'s identical
     *  fix, applied there first since Red Hat's {@code changes.csv} volume makes the bug fire far more
     *  often; this class has the same code shape so gets the same fix for consistency, lower priority
     *  since Siemens' small daily volume rarely crosses the cap at all). A bare {@code
     *  entries.subList(0, cap)} truncation is a HARD cutoff mid-timestamp-group — anything tied with
     *  the boundary entry's {@code updated} timestamp, positioned just after the cutoff index, would
     *  never be {@code isAfter} a cursor already sitting at that same timestamp on a future run,
     *  permanently skipping it. {@code entries} must already be sorted ascending by {@code updated}. */
    // REVISE follow-up item 5 (senior review 2026-08-27) — see RedHatCsafSyncService's identical fix
    // for the full rationale: capWithTiedTimestampExtension stays intentionally unbounded, but a large
    // extension is escalated to WARN so an unusually large bulk republish is observable without INFO
    // logging enabled.
    private static final int CAP_EXTENSION_WARN_THRESHOLD = 100;

    List<RolieEntry> capWithTiedTimestampExtension(List<RolieEntry> entries, int cap) {
        if (entries.size() <= cap) {
            return entries;
        }
        OffsetDateTime boundaryTimestamp = entries.get(cap - 1).updated();
        int end = cap;
        while (end < entries.size() && entries.get(end).updated().equals(boundaryTimestamp)) {
            end++;
        }
        if (end > cap) {
            int extension = end - cap;
            if (extension > CAP_EXTENSION_WARN_THRESHOLD) {
                log.warn("Siemens CSAF sync: extended the {}-entry per-run cap by {} additional entries sharing "
                        + "the boundary timestamp {} — this run will process {} documents in total, well beyond "
                        + "the configured cap (REVISE item 4/5) — possible bulk republish",
                        cap, extension, boundaryTimestamp, end);
            } else {
                log.info("Siemens CSAF sync: extended the {}-entry per-run cap by {} additional entries sharing "
                        + "the boundary timestamp {} — a hard cutoff mid-timestamp-group would silently and "
                        + "permanently skip them (REVISE item 4)", cap, extension, boundaryTimestamp);
            }
        }
        return entries.subList(0, end);
    }

    private SyncResult doSync(boolean baseline) {
        CsafSyncState state = syncStateRepository.findById(VENDOR).orElseGet(() -> new CsafSyncState(VENDOR));
        OffsetDateTime cursor = baseline ? null : parseTimestamp(state.getLastCursor());

        FetchOutcome metadataOutcome = fetchBounded(PROVIDER_METADATA_URL, MAX_DOCUMENT_BYTES);
        if (metadataOutcome.status() != FetchStatus.OK) {
            log.error("Siemens CSAF sync aborted: could not fetch provider-metadata.json ({})", metadataOutcome.status());
            return new SyncResult(0, 0, false);
        }
        String feedUrl = extractFeedUrl(parseJson(metadataOutcome.body()));
        if (feedUrl == null) {
            log.error("Siemens CSAF sync aborted: provider-metadata.json has no ROLIE feed URL");
            return new SyncResult(0, 0, false);
        }

        FetchOutcome feedOutcome = fetchBounded(feedUrl, MAX_DOCUMENT_BYTES);
        if (feedOutcome.status() != FetchStatus.OK) {
            log.error("Siemens CSAF sync aborted: could not fetch ROLIE feed ({})", feedOutcome.status());
            return new SyncResult(0, 0, false);
        }

        List<RolieEntry> entries = parseFeedEntries(parseJson(feedOutcome.body()));
        entries = entries.stream()
                .filter(e -> e.updated() != null && (cursor == null || e.updated().isAfter(cursor)))
                .sorted(Comparator.comparing(RolieEntry::updated)) // ascending — plan §7
                .toList();
        if (entries.size() > MAX_DOCUMENTS_PER_RUN) {
            log.info("Siemens CSAF sync: {} eligible entries exceeds the per-run cap of {} — processing the "
                            + "oldest {} (plus any tied-timestamp extension, REVISE item 4) now, the remainder "
                            + "next run", entries.size(), MAX_DOCUMENTS_PER_RUN, MAX_DOCUMENTS_PER_RUN);
            entries = capWithTiedTimestampExtension(entries, MAX_DOCUMENTS_PER_RUN);
        }

        int upserted = 0;
        int failed = 0;
        // REVISE item 2 (senior review 2026-08-27): every failure path below used to do `failed++;
        // continue;` while the per-entry checkpoint further down still ran on the NEXT successful
        // entry — since entries process in ascending-`updated` order, that moved the cursor PAST the
        // failed one, permanently excluding it from every future delta run (the next run's `updated
        // .isAfter(cursor)` filter would never see it again), with nothing surfacing that it was
        // missing. `sawFailure` gates the checkpoint instead: once true, no further checkpoint is
        // written for the rest of THIS run, even though processing continues (re-fetching already-
        // processed entries next run is idempotent — costs 2 requests/doc again, nothing worse).
        boolean sawFailure = false;
        String firstFailedEntryId = null;
        for (RolieEntry entry : entries) {
            rateLimiter.awaitTurn(RATE_LIMIT_KEY);
            FetchOutcome docOutcome = fetchBounded(entry.contentUrl(), MAX_DOCUMENT_BYTES);
            if (docOutcome.status() == FetchStatus.RATE_LIMITED) {
                log.error("Siemens CSAF sync aborting: got HTTP {} fetching {} — treating as a block signal, "
                                + "not a transient error (plan §5-7). Cursor left at the last successfully "
                                + "processed entry.", docOutcome.httpStatus(), entry.contentUrl());
                break; // cursor NOT advanced past entry — same document retried next run
            }
            if (docOutcome.status() != FetchStatus.OK) {
                log.warn("Siemens CSAF sync: failed to fetch {} ({}) — skipping, cursor not advanced",
                        entry.contentUrl(), docOutcome.status());
                failed++;
                if (!sawFailure) {
                    sawFailure = true;
                    firstFailedEntryId = entry.id();
                }
                continue;
            }

            // REVISE item 4 (senior review 2026-08-27): this class's own javadoc states Siemens
            // always provides a `.sha512` hash link — a missing one is an anomaly, not a normal case,
            // and silently upserting unverified would also be a trivial verification-bypass vector.
            if (entry.hashUrl() == null) {
                log.warn("Siemens CSAF sync: {} has no hash sidecar link (link[rel=hash]) — Siemens always "
                                + "provides one, treating this as an anomaly, not upserting", entry.id());
                failed++;
                if (!sawFailure) {
                    sawFailure = true;
                    firstFailedEntryId = entry.id();
                }
                continue;
            }

            HashVerifyResult hashResult = verifyHash(entry, docOutcome.body());
            if (hashResult == HashVerifyResult.RATE_LIMITED) {
                // REVISE item 5 (senior review 2026-08-27): the document-fetch path already `break`s
                // the whole run on a rate-limited response (above) — the hash-sidecar fetch must do
                // the same, otherwise a block that manifests specifically on `.sha512` requests would
                // degrade into continuing to hammer a host that's actively refusing requests, exactly
                // the scenario the rate-limiting design exists to prevent.
                log.error("Siemens CSAF sync aborting: rate-limited fetching hash sidecar {} for {} — treating "
                                + "as a block signal, not a transient error (plan §5-7). Cursor left at the "
                                + "last successfully processed entry.", entry.hashUrl(), entry.id());
                break;
            }
            if (hashResult == HashVerifyResult.FAILED) {
                failed++;
                if (!sawFailure) {
                    sawFailure = true;
                    firstFailedEntryId = entry.id();
                }
                continue; // cursor NOT advanced
            }

            try {
                String trackingId = documentUpsertService.upsertCsafDocument(VENDOR, parseJson(docOutcome.body()));
                if (trackingId == null) {
                    failed++;
                    if (!sawFailure) {
                        sawFailure = true;
                        firstFailedEntryId = entry.id();
                    }
                    continue; // cursor NOT advanced
                }
                upserted++;
            } catch (Exception e) {
                log.warn("Siemens CSAF sync: failed to upsert {} — skipping, cursor not advanced", entry.id(), e);
                failed++;
                if (!sawFailure) {
                    sawFailure = true;
                    firstFailedEntryId = entry.id();
                }
                continue; // cursor NOT advanced
            }

            // Per-entry checkpoint (plan §7) — commits immediately after each successfully upserted
            // document rather than once at the end of the whole run. Gated on !sawFailure (item 2):
            // once any entry in this run has failed, no later entry's success may advance the cursor
            // past it.
            if (!sawFailure) {
                state.setLastCursor(entry.updated().toString());
                state.setLastSyncedAt(OffsetDateTime.now());
                syncStateRepository.save(state);
            }
        }

        log.info("Siemens CSAF sync complete (baseline={}): {} upserted, {} failed, cursor={}",
                baseline, upserted, failed, state.getLastCursor());
        if (sawFailure) {
            log.warn("Siemens CSAF sync (baseline={}): first failure was entry {} — the cursor was not advanced "
                            + "past it, so this entry and every entry processed after it in this run will be "
                            + "re-fetched on the next run (no skip-after-N-attempts mechanism exists yet)",
                    baseline, firstFailedEntryId);
        }
        return new SyncResult(upserted, failed, false);
    }

    /** Tri-state outcome of {@link #verifyHash} — {@code OK}/{@code FAILED} alone would collapse a
     *  rate-limited sidecar fetch into an ordinary verification failure, losing the "stop hammering
     *  this host" signal the document-fetch path already honors (REVISE item 5). */
    private enum HashVerifyResult {
        OK, FAILED, RATE_LIMITED
    }

    /** Compares {@code entry}'s {@code link[rel=hash]} sidecar (SHA-256 or SHA-512, inferred from
     *  the sidecar URL's own file extension — Siemens only ever provides {@code .sha512} as of
     *  2026-08-27, but this doesn't hardcode that) against the already-fetched document bytes.
     *
     *  <p><b>Honest scope (REVISE item 5, senior review 2026-08-27):</b> this verifies that the exact
     *  bytes upserted match a same-host, HTTPS-fetched sidecar — it catches truncation, in-transit
     *  corruption, and a document/sidecar mismatch. It does NOT defend against a compromised origin
     *  serving a matching bad document+hash pair together; that would require verifying the CSAF
     *  document's OpenPGP {@code .asc} signature against Siemens' published key, which is out of
     *  scope for this phase. */
    private HashVerifyResult verifyHash(RolieEntry entry, byte[] documentBytes) {
        rateLimiter.awaitTurn(RATE_LIMIT_KEY);
        FetchOutcome hashOutcome = fetchBounded(entry.hashUrl(), MAX_HASH_BYTES);
        if (hashOutcome.status() == FetchStatus.RATE_LIMITED) {
            return HashVerifyResult.RATE_LIMITED;
        }
        if (hashOutcome.status() != FetchStatus.OK) {
            log.warn("Siemens CSAF sync: could not fetch hash sidecar {} for {} — treating as unverifiable, skipping",
                    entry.hashUrl(), entry.id());
            return HashVerifyResult.FAILED;
        }
        String algorithm = entry.hashUrl().toLowerCase(java.util.Locale.ROOT).endsWith(".sha256") ? "SHA-256" : "SHA-512";
        String expectedHex = new String(hashOutcome.body(), java.nio.charset.StandardCharsets.US_ASCII).trim().toLowerCase(java.util.Locale.ROOT);
        String actualHex;
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            actualHex = HexFormat.of().formatHex(digest.digest(documentBytes));
        } catch (NoSuchAlgorithmException e) {
            log.warn("Siemens CSAF sync: unsupported hash algorithm {} for {}", algorithm, entry.id());
            return HashVerifyResult.FAILED;
        }
        if (!actualHex.equalsIgnoreCase(expectedHex)) {
            log.warn("Siemens CSAF sync: {} hash mismatch for {} — expected {} got {}, skipping (not upserted)",
                    algorithm, entry.id(), expectedHex, actualHex);
            return HashVerifyResult.FAILED;
        }
        return HashVerifyResult.OK;
    }

    private String extractFeedUrl(JsonNode metadata) {
        for (JsonNode distribution : metadata.path("distributions")) {
            JsonNode feeds = distribution.path("rolie").path("feeds");
            if (feeds.isArray() && !feeds.isEmpty()) {
                String url = feeds.get(0).path("url").asText(null);
                if (url != null) {
                    return url;
                }
            }
        }
        return null;
    }

    // Package-private (not private) — lets SiemensCsafSyncServiceTest exercise
    // capWithTiedTimestampExtension directly with small synthetic lists (REVISE item 4).
    record RolieEntry(String id, String contentUrl, String hashUrl, OffsetDateTime updated) {
    }

    private List<RolieEntry> parseFeedEntries(JsonNode feed) {
        List<RolieEntry> entries = new ArrayList<>();
        for (JsonNode entry : feed.path("feed").path("entry")) {
            String id = entry.path("id").asText(null);
            String contentUrl = entry.path("content").path("src").asText(null);
            OffsetDateTime updated = parseTimestamp(entry.path("updated").asText(null));
            if (id == null || contentUrl == null || updated == null) {
                continue;
            }
            String hashUrl = null;
            for (JsonNode link : entry.path("link")) {
                if ("hash".equals(link.path("rel").asText(null))) {
                    hashUrl = link.path("href").asText(null);
                    break;
                }
            }
            entries.add(new RolieEntry(id, contentUrl, hashUrl, updated));
        }
        return entries;
    }

    private JsonNode parseJson(byte[] body) {
        try {
            return objectMapper.readTree(body);
        } catch (IOException e) {
            throw new IllegalStateException("Malformed JSON from Siemens CSAF endpoint", e);
        }
    }

    private OffsetDateTime parseTimestamp(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value);
        } catch (DateTimeParseException e) {
            return null;
        }
    }

    // --- SSRF-hardened fetch (plan §6): https-only, host allowlist re-checked on every redirect
    // hop (redirects are never auto-followed by csafSyncRestClient — see RestClientConfig), a
    // bounded redirect count, and a bounded response size (read manually rather than trusted from
    // Content-Length, which a malicious/misbehaving server could omit or lie about). -------------

    private enum FetchStatus {
        OK, REJECTED_SCHEME_OR_HOST, TOO_MANY_REDIRECTS, TOO_LARGE, RATE_LIMITED, HTTP_ERROR, TRANSPORT_ERROR
    }

    private record FetchOutcome(FetchStatus status, byte[] body, Integer httpStatus) {
        static FetchOutcome ok(byte[] body) {
            return new FetchOutcome(FetchStatus.OK, body, null);
        }
        static FetchOutcome of(FetchStatus status, Integer httpStatus) {
            return new FetchOutcome(status, null, httpStatus);
        }
    }

    private FetchOutcome fetchBounded(String url, long maxBytes) {
        return fetchBounded(url, maxBytes, MAX_REDIRECTS);
    }

    private FetchOutcome fetchBounded(String url, long maxBytes, int redirectsRemaining) {
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            return FetchOutcome.of(FetchStatus.REJECTED_SCHEME_OR_HOST, null);
        }
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || !ALLOWED_HOSTS.contains(uri.getHost())) {
            log.warn("Siemens CSAF sync: rejecting fetch of {} — not https or not an allowlisted host", url);
            return FetchOutcome.of(FetchStatus.REJECTED_SCHEME_OR_HOST, null);
        }

        try {
            return csafSyncRestClient.get().uri(uri).exchange((request, response) -> {
                HttpStatusCode status = response.getStatusCode();
                if (status.is3xxRedirection()) {
                    String location = response.getHeaders().getFirst(org.springframework.http.HttpHeaders.LOCATION);
                    if (location == null) {
                        return FetchOutcome.of(FetchStatus.HTTP_ERROR, status.value());
                    }
                    if (redirectsRemaining <= 0) {
                        log.warn("Siemens CSAF sync: too many redirects fetching {}", url);
                        return FetchOutcome.of(FetchStatus.TOO_MANY_REDIRECTS, status.value());
                    }
                    URI redirectTarget = uri.resolve(location);
                    return fetchBounded(redirectTarget.toString(), maxBytes, redirectsRemaining - 1);
                }
                if (status.value() == 429 || status.value() == 403) {
                    return FetchOutcome.of(FetchStatus.RATE_LIMITED, status.value());
                }
                if (!status.is2xxSuccessful()) {
                    return FetchOutcome.of(FetchStatus.HTTP_ERROR, status.value());
                }
                byte[] body = readBounded(response.getBody(), maxBytes);
                if (body == null) {
                    return FetchOutcome.of(FetchStatus.TOO_LARGE, status.value());
                }
                return FetchOutcome.ok(body);
            });
        } catch (Exception e) {
            log.warn("Siemens CSAF sync: transport error fetching {}", url, e);
            return FetchOutcome.of(FetchStatus.TRANSPORT_ERROR, null);
        }
    }

    /** Reads at most {@code maxBytes} from {@code in} — returns null (caller treats as "too large")
     *  if the stream still had data past that point, rather than trusting a possibly-absent/lying
     *  {@code Content-Length} header (plan §6). */
    private byte[] readBounded(InputStream in, long maxBytes) {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            long total = 0;
            int read;
            while ((read = in.read(chunk)) != -1) {
                total += read;
                if (total > maxBytes) {
                    return null;
                }
                buffer.write(chunk, 0, read);
            }
            return buffer.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Failed reading response body", e);
        }
    }
}
