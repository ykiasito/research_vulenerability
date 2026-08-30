-- V7__fixed_version.sql
-- Recommended-upgrade-target version, extracted for free from each source's own structured data
-- (NVD's versionEndExcluding, OSV's "fixed" range event, GHSA's patched_versions) — no extra API
-- call needed. Null when the source didn't provide a clean answer (e.g. no fix released yet).

ALTER TABLE vulnerabilities ADD COLUMN fixed_version TEXT;
