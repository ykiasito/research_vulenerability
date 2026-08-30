package com.vulncheck.app.service.ghsa;

import com.fasterxml.jackson.databind.JsonNode;
import com.vulncheck.app.repository.GhsaAdvisoryRepository;
import com.vulncheck.app.repository.GhsaAffectedPackageRepository;
import com.vulncheck.app.repository.GhsaAffectedRangeRepository;
import com.vulncheck.app.repository.GhsaAffectedVersionRepository;
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
 * The single shared parser+upsert for one already-fetched GHSA-reviewed advisory document, in its
 * canonical OSV schema shape — see {@code docs/spec/ghsa-mirror-plan.md} §3-1 decision A. Both
 * {@code GhsaSyncService#syncBaseline} (git tarball entries) and {@code #syncDelta} (individual
 * {@code raw.githubusercontent.com} fetches, triggered by the REST {@code /advisories} change-
 * detection signal) call this exact same method — the whole point of decision A is that there is
 * exactly one place in this app that interprets OSV's {@code affected[].ranges[].events[]} version-
 * range shape, so baseline and delta can never drift apart on that logic.
 *
 * <p>Mirrors {@code CveOrgSyncService#upsertCveJson}/{@code CsafDocumentUpsertService}'s idempotent
 * "delete-then-reinsert the child rows, always" shape — a re-synced advisory replaces its {@code
 * ghsa_affected_packages}/{@code ghsa_affected_ranges}/{@code ghsa_affected_versions} rows wholesale
 * rather than diffing.
 *
 * <p><b>Multiple {@code affected[]} entries for the same (ecosystem, package) are merged into one
 * {@code ghsa_affected_packages} row</b> — e.g. a Django advisory listing separate {@code
 * affected[]} entries for its {@code 5.2.x} and {@code 6.0.x} branches, each with its own single-
 * event range, both for the {@code django}/PyPI package (captured live 2026-08-27,
 * GHSA-crhf-3pfg-w68w). V19's {@code UNIQUE (ghsa_id, ecosystem, package_name_normalized)} requires
 * this — {@link #parseAffectedEntries} groups by normalized (ecosystem, package) before ever
 * inserting a package row, and every range from every matching {@code affected[]} entry is attached
 * to that single row, giving {@code OsvVersionRange}'s OR-across-ranges evaluation the full set of
 * disjoint ranges to check.
 *
 * <p><b>{@code cvss_score} is always left NULL</b> — a deliberate scope decision, not an oversight:
 * unlike CSAF's {@code cvss_v3.baseScore}, GHSA's OSV-schema {@code severity[]} entries carry only
 * the raw CVSS vector string (e.g. {@code "CVSS:3.1/AV:N/..."}), never a pre-computed numeric base
 * score — parsing a CVSS vector into a score is out of scope for this phase. {@code severity} (the
 * text column) instead comes from {@code database_specific.severity} (GHSA's own
 * LOW/MODERATE/HIGH/CRITICAL classification), which the old per-item implementation's REST API
 * equivalent already surfaced as plain text.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class GhsaDocumentUpsertService {

    /** OSV's own ecosystem strings (as they appear in {@code affected[].package.ecosystem}) mapped
     *  to this app's internal ecosystem keys — the exact inverse of {@code
     *  OsvVulnerabilitySource#ECOSYSTEM_MAP}'s values, since GHSA-reviewed advisories are published
     *  in the same OSV schema OSV.dev itself uses. An ecosystem not in this map is skipped (this
     *  app has no internal key/candidate-query path for it), same convention as {@code
     *  GhsaVulnerabilitySource}'s/{@code OsvVulnerabilitySource}'s own fixed ecosystem maps. */
    private static final Map<String, String> OSV_ECOSYSTEM_TO_INTERNAL = OsvEcosystems.OSV_TO_INTERNAL;

    private final GhsaAdvisoryRepository ghsaAdvisoryRepository;
    private final GhsaAffectedPackageRepository ghsaAffectedPackageRepository;
    private final GhsaAffectedRangeRepository ghsaAffectedRangeRepository;
    private final GhsaAffectedVersionRepository ghsaAffectedVersionRepository;

    /** @return the advisory's {@code id} ({@code GHSA-xxxx-...}), or null if the document was
     *          missing a required field ({@code id} or {@code modified} — {@code updated_at} is
     *          {@code NOT NULL}) and therefore wasn't upserted at all. Callers (the sync services)
     *          treat a null return as this document's processing having failed — see plan §6-1's
     *          dead-letter handling. */
    @Transactional
    public String upsertGhsaAdvisory(JsonNode root) {
        String ghsaId = textOrNull(root.path("id"));
        if (ghsaId == null || ghsaId.isBlank()) {
            log.warn("GHSA document has no id — skipping");
            return null;
        }
        OffsetDateTime updatedAt = parseTimestamp(textOrNull(root.path("modified")));
        if (updatedAt == null) {
            log.warn("GHSA document {} has no parseable 'modified' timestamp — skipping (updated_at is NOT NULL)", ghsaId);
            return null;
        }

        String cveId = extractCveAlias(root.path("aliases"));
        String severity = textOrNull(root.path("database_specific").path("severity"));
        if (severity != null) {
            severity = severity.toUpperCase(Locale.ROOT);
        }

        ghsaAdvisoryRepository.upsert(
                ghsaId,
                cveId,
                textOrNull(root.path("summary")),
                textOrNull(root.path("details")),
                severity,
                null, // cvss_score — see class javadoc
                parseTimestamp(textOrNull(root.path("withdrawn"))),
                parseTimestamp(textOrNull(root.path("published"))),
                updatedAt,
                "https://github.com/advisories/" + ghsaId,
                root.toString());

        ghsaAffectedPackageRepository.deleteByGhsaId(ghsaId);
        Map<String, PackageAccumulator> packages = parseAffectedEntries(root.path("affected"), ghsaId);
        int rangeCount = 0;
        int versionCount = 0;
        for (PackageAccumulator pkg : packages.values()) {
            Long affectedPackageId = ghsaAffectedPackageRepository.insertAndGetId(
                    ghsaId, pkg.ecosystem, pkg.rawPackageName, pkg.normalizedName);
            if (affectedPackageId == null) {
                continue; // ON CONFLICT DO NOTHING raced with something — shouldn't happen post-delete, defensive only
            }
            for (RangeEntry range : pkg.ranges) {
                ghsaAffectedRangeRepository.insert(affectedPackageId, range.rangeType, range.introducedVersion,
                        range.fixedVersion, range.lastAffectedVersion);
                rangeCount++;
            }
            for (String version : pkg.exactVersions) {
                ghsaAffectedVersionRepository.insert(affectedPackageId, version);
                versionCount++;
            }
        }

        log.debug("GHSA upsert {}: {} packages, {} ranges, {} exact versions", ghsaId, packages.size(), rangeCount, versionCount);
        return ghsaId;
    }

    private String extractCveAlias(JsonNode aliases) {
        for (JsonNode alias : aliases) {
            String value = textOrNull(alias);
            if (value != null && value.startsWith("CVE-")) {
                return value;
            }
        }
        return null;
    }

    /** Groups every {@code affected[]} entry by (internal ecosystem, normalized package name) — see
     *  the class javadoc for why entries must be merged before any package row is inserted. */
    private Map<String, PackageAccumulator> parseAffectedEntries(JsonNode affectedArray, String ghsaId) {
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
                accumulator.ranges.addAll(parseRangeEvents(range, ghsaId));
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

    /** OSV event-pairing (plan §3-1(C)): an {@code introduced} event opens a range, the next {@code
     *  fixed}/{@code last_affected} event closes it — one {@code ranges[]} entry can hold several
     *  such introduced/fixed(-or-last_affected) pairs, each becoming its own {@link RangeEntry} (one
     *  row in {@code ghsa_affected_ranges}). {@code limit} events are ignored. An {@code introduced}
     *  with no closing event before the range's event list ends becomes an unbounded-above range
     *  (still vulnerable, no known fix). {@code introduced:"0"} normalizes to null (plan §3).
     *
     *  <p><b>Senior review item 11 (deliberately NOT changing parsing semantics):</b> two edge cases —
     *  (a) a second {@code introduced} event while a range is already open, which silently narrows
     *  the open bound, and (b) a {@code fixed}/{@code last_affected} event appearing before any {@code
     *  introduced} ever opened a range, which is silently dropped — are both still handled exactly as
     *  before (neither was observed across a 432-real-range sample, and {@code events[]} is treated as
     *  a well-formed ordered list per the OSV spec, per the approved design). Only logging was added
     *  on both branches, so a future data-shape change from GitHub becomes visible in logs rather than
     *  silently mis-parsed — see {@code docs/spec/known-limitations.md}. */
    private List<RangeEntry> parseRangeEvents(JsonNode range, String ghsaId) {
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
                    log.warn("GHSA document {}: a second 'introduced' event appeared while a range was already "
                            + "open — narrowing the open bound to this later value (parsing semantics "
                            + "deliberately unchanged, see known-limitations.md)", ghsaId);
                }
                String introduced = textOrNull(event.path("introduced"));
                openIntroduced = "0".equals(introduced) ? null : introduced;
                open = true;
            } else if (event.has("fixed")) {
                if (open) {
                    entries.add(new RangeEntry(rangeType, openIntroduced, textOrNull(event.path("fixed")), null));
                    open = false;
                    openIntroduced = null;
                } else {
                    log.warn("GHSA document {}: a 'fixed' event appeared before any 'introduced' event opened a "
                            + "range — dropping it (parsing semantics deliberately unchanged, see "
                            + "known-limitations.md)", ghsaId);
                }
            } else if (event.has("last_affected")) {
                if (open) {
                    entries.add(new RangeEntry(rangeType, openIntroduced, null, textOrNull(event.path("last_affected"))));
                    open = false;
                    openIntroduced = null;
                } else {
                    log.warn("GHSA document {}: a 'last_affected' event appeared before any 'introduced' event "
                            + "opened a range — dropping it (parsing semantics deliberately unchanged, see "
                            + "known-limitations.md)", ghsaId);
                }
            }
            // "limit" events are deliberately ignored (plan §3-1(C)).
        }
        if (open) {
            entries.add(new RangeEntry(rangeType, openIntroduced, null, null)); // unbounded above
        }
        return entries;
    }

    /** Senior review item 8: see {@code GhsaSyncService#textOrNull}'s javadoc — the same {@code
     *  MissingNode} vs. {@code NullNode} {@code asText(default)} pitfall applies here (an explicit
     *  JSON {@code null} would otherwise persist as the literal string {@code "null"}). */
    private static String textOrNull(JsonNode node) {
        return node != null && node.isTextual() ? node.asText() : null;
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
