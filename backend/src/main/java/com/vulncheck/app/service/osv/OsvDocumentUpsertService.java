package com.vulncheck.app.service.osv;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.OsvAdvisoryRepository;
import com.vulncheck.app.repository.OsvAffectedPackageRepository;
import com.vulncheck.app.repository.OsvAffectedRangeRepository;
import com.vulncheck.app.repository.OsvAffectedVersionRepository;
import com.vulncheck.app.service.vuln.OsvEcosystems;
import com.vulncheck.app.service.vuln.OsvPackageNameNormalizer;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The single shared parser+upsert for one already-fetched, already-id-filtered (non-{@code
 * GHSA-}/{@code MAL-}) OSV.dev advisory document — see {@code docs/spec/osv-mirror-plan.md} §6-3.
 * Both {@code OsvSyncService#syncBaseline} ({@code {ecosystem}/all.zip} entries) and {@code
 * #syncDelta} (per-document {@code {directory}/{id}.json} fetches) call this exact same method, the
 * same "one shared parser for both ingest paths" discipline {@code GhsaDocumentUpsertService}
 * established for the GHSA mirror — this class mirrors that one closely, with two differences: no
 * {@code raw_json} column (plan's most important scope decision), and an extra {@code ghsa_id}
 * alias column (kept alongside {@code cve_id}, both used by {@code
 * OsvVulnerabilityLookupRepository}'s {@code COALESCE} finding-id priority, plan §5-2/§7-1).
 *
 * <p>Callers must already have rejected {@code GHSA-}/{@code MAL-} prefixed ids (plan §4-1) before
 * calling this — it does not re-check that itself, since the check is cheap to do once on the raw
 * id string ahead of ever parsing JSON (see {@code OsvSyncService}'s own filtering).
 *
 * <p>Same idempotent "delete-then-reinsert the child rows, always" shape as {@code
 * GhsaDocumentUpsertService} — a re-synced advisory replaces its {@code osv_affected_packages}/
 * {@code osv_affected_ranges}/{@code osv_affected_versions} rows wholesale rather than diffing.
 * Multiple {@code affected[]} entries for the same (ecosystem, package) are merged into one {@code
 * osv_affected_packages} row (V25's {@code UNIQUE (osv_id, ecosystem, package_name_normalized)}
 * requires this, identical rationale to {@code GhsaDocumentUpsertService}'s own javadoc).
 *
 * <p>{@code affected[]} entries for an ecosystem outside the 10 this app supports are silently
 * skipped here (plan §6-1 step 3b/§6-3) — this is the only ecosystem filter left after baseline
 * switched to per-ecosystem zip downloads; a record whose {@code affected[]} mixes a supported and
 * an unsupported ecosystem still gets a row for the supported one.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OsvDocumentUpsertService {

    private static final Map<String, String> OSV_ECOSYSTEM_TO_INTERNAL = OsvEcosystems.OSV_TO_INTERNAL;

    private final OsvAdvisoryRepository osvAdvisoryRepository;
    private final OsvAffectedPackageRepository osvAffectedPackageRepository;
    private final OsvAffectedRangeRepository osvAffectedRangeRepository;
    private final OsvAffectedVersionRepository osvAffectedVersionRepository;

    /** @return the advisory's {@code id} (e.g. {@code PYSEC-2023-1}), or null if the document was
     *          missing a required field ({@code id} or {@code modified} — {@code updated_at} is
     *          {@code NOT NULL}) and therefore wasn't upserted at all. Callers treat a null return
     *          as this document's processing having failed (plan §8, dead-letter handling). */
    @Transactional
    public String upsertOsvJson(JsonNode root) {
        String osvId = textOrNull(root.path("id"));
        if (osvId == null || osvId.isBlank()) {
            log.warn("OSV document has no id — skipping");
            return null;
        }
        OffsetDateTime updatedAt = parseTimestamp(textOrNull(root.path("modified")));
        if (updatedAt == null) {
            log.warn("OSV document {} has no parseable 'modified' timestamp — skipping (updated_at is NOT NULL)", osvId);
            return null;
        }

        String cveId = extractAlias(root.path("aliases"), "CVE-");
        String ghsaId = extractAlias(root.path("aliases"), "GHSA-");
        String severity = textOrNull(root.path("database_specific").path("severity"));
        if (severity != null) {
            severity = severity.toUpperCase(Locale.ROOT);
        }

        osvAdvisoryRepository.upsert(
                osvId,
                cveId,
                ghsaId,
                textOrNull(root.path("summary")),
                textOrNull(root.path("details")),
                severity,
                null, // cvss_score — see class javadoc / V25 migration comment
                parseTimestamp(textOrNull(root.path("withdrawn"))),
                parseTimestamp(textOrNull(root.path("published"))),
                updatedAt,
                "https://osv.dev/vulnerability/" + osvId);

        osvAffectedPackageRepository.deleteByOsvId(osvId);
        Map<String, PackageAccumulator> packages = parseAffectedEntries(root.path("affected"), osvId);
        int rangeCount = 0;
        int versionCount = 0;
        for (PackageAccumulator pkg : packages.values()) {
            Long affectedPackageId = osvAffectedPackageRepository.insertAndGetId(
                    osvId, pkg.ecosystem, pkg.rawPackageName, pkg.normalizedName);
            if (affectedPackageId == null) {
                continue; // ON CONFLICT DO NOTHING raced with something — shouldn't happen post-delete, defensive only
            }
            for (RangeEntry range : pkg.ranges) {
                osvAffectedRangeRepository.insert(affectedPackageId, range.rangeType, range.introducedVersion,
                        range.fixedVersion, range.lastAffectedVersion);
                rangeCount++;
            }
            for (String version : pkg.exactVersions) {
                osvAffectedVersionRepository.insert(affectedPackageId, version);
                versionCount++;
            }
        }

        log.debug("OSV upsert {}: {} packages, {} ranges, {} exact versions", osvId, packages.size(), rangeCount, versionCount);
        return osvId;
    }

    private String extractAlias(JsonNode aliases, String prefix) {
        for (JsonNode alias : aliases) {
            String value = textOrNull(alias);
            if (value != null && value.startsWith(prefix)) {
                return value;
            }
        }
        return null;
    }

    /** Groups every {@code affected[]} entry by (internal ecosystem, normalized package name) —
     *  identical rationale to {@code GhsaDocumentUpsertService#parseAffectedEntries}. */
    private Map<String, PackageAccumulator> parseAffectedEntries(JsonNode affectedArray, String osvId) {
        Map<String, PackageAccumulator> packages = new LinkedHashMap<>();
        for (JsonNode affected : affectedArray) {
            String osvEcosystem = textOrNull(affected.path("package").path("ecosystem"));
            String internalEcosystem = osvEcosystem != null ? OSV_ECOSYSTEM_TO_INTERNAL.get(osvEcosystem) : null;
            String rawPackageName = textOrNull(affected.path("package").path("name"));
            if (internalEcosystem == null || rawPackageName == null || rawPackageName.isBlank()) {
                continue; // unsupported ecosystem, or malformed entry — skip just this affected[] entry
            }
            String normalizedName = OsvPackageNameNormalizer.normalize(internalEcosystem, rawPackageName);
            String key = internalEcosystem + ' ' + normalizedName;
            PackageAccumulator accumulator =
                    packages.computeIfAbsent(key, k -> new PackageAccumulator(internalEcosystem, rawPackageName, normalizedName));

            for (JsonNode range : affected.path("ranges")) {
                accumulator.ranges.addAll(parseRangeEvents(range, osvId));
            }
            for (JsonNode version : affected.path("versions")) {
                String v = textOrNull(version);
                if (v != null && !v.isBlank()) {
                    accumulator.exactVersions.add(v);
                }
            }
        }
        return packages;
    }

    /** OSV event-pairing — identical semantics to {@code GhsaDocumentUpsertService#parseRangeEvents}
     *  (this app's shared interpretation of OSV's {@code ranges[].events[]} shape, not GHSA-specific
     *  in any way — see {@code docs/spec/osv-mirror-plan.md} §1-2). An {@code introduced} event opens
     *  a range, the next {@code fixed}/{@code last_affected} event closes it; {@code limit} events
     *  are ignored; {@code introduced} sentinel values that all mean "from the very first version" —
     *  {@code "0"}, {@code "0.0.0"}, and RustSec's {@code "0.0.0-0"} — normalize to null. All three are
     *  semantically equivalent lower bounds, so collapsing them to "no lower bound" never narrows a
     *  range and carries zero false-negative/false-positive risk; it only avoids {@code
     *  OsvVersionRange} abstaining from evaluation because it can't parse the literal sentinel as a
     *  real version. */
    private List<RangeEntry> parseRangeEvents(JsonNode range, String osvId) {
        List<RangeEntry> entries = new ArrayList<>();
        String rangeType = textOrNull(range.path("type"));
        if (rangeType == null || rangeType.isBlank()) {
            return entries;
        }

        boolean open = false;
        String openIntroduced = null;
        for (JsonNode event : range.path("events")) {
            if (event.has("introduced")) {
                if (open) {
                    log.warn("OSV document {}: a second 'introduced' event appeared while a range was already "
                            + "open — narrowing the open bound to this later value", osvId);
                }
                String introduced = textOrNull(event.path("introduced"));
                openIntroduced = isZeroSentinel(introduced) ? null : introduced;
                open = true;
            } else if (event.has("fixed")) {
                if (open) {
                    entries.add(new RangeEntry(rangeType, openIntroduced, textOrNull(event.path("fixed")), null));
                    open = false;
                    openIntroduced = null;
                } else {
                    log.warn("OSV document {}: a 'fixed' event appeared before any 'introduced' event opened a "
                            + "range — dropping it", osvId);
                }
            } else if (event.has("last_affected")) {
                if (open) {
                    entries.add(new RangeEntry(rangeType, openIntroduced, null, textOrNull(event.path("last_affected"))));
                    open = false;
                    openIntroduced = null;
                } else {
                    log.warn("OSV document {}: a 'last_affected' event appeared before any 'introduced' event "
                            + "opened a range — dropping it", osvId);
                }
            }
            // "limit" events are deliberately ignored.
        }
        if (open) {
            entries.add(new RangeEntry(rangeType, openIntroduced, null, null)); // unbounded above
        }
        return entries;
    }

    private static String textOrNull(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
    }

    /** {@code "0"}, {@code "0.0.0"}, and RustSec's {@code "0.0.0-0"} all mean "from the very first
     *  version" — see the javadoc on {@link #parseRangeEvents} for why collapsing all three to null
     *  is safe. */
    private static boolean isZeroSentinel(String introduced) {
        return "0".equals(introduced) || "0.0.0".equals(introduced) || "0.0.0-0".equals(introduced);
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

    private static final class PackageAccumulator {
        private final String ecosystem;
        private final String rawPackageName;
        private final String normalizedName;
        private final List<RangeEntry> ranges = new ArrayList<>();
        private final Set<String> exactVersions = new LinkedHashSet<>();

        private PackageAccumulator(String ecosystem, String rawPackageName, String normalizedName) {
            this.ecosystem = ecosystem;
            this.rawPackageName = rawPackageName;
            this.normalizedName = normalizedName;
        }
    }

    private record RangeEntry(String rangeType, String introducedVersion, String fixedVersion, String lastAffectedVersion) {
    }
}
