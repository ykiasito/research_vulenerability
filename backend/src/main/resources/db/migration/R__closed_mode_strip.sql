-- R__closed_mode_strip.sql
-- Closed-mode backlog item 262 (Phase B6, docs/spec/closed-mode-plan.md §3-2). A repeatable
-- migration (Flyway "R__" prefix), not a versioned one: this doesn't occupy a version number and
-- re-runs automatically whenever its own checksum changes, matching the pattern already used for
-- V32 (Chocolatey ecosystem row removal) but as an ongoing guarantee rather than a one-time cutover
-- -- if either table below is ever repopulated (e.g. a stray INSERT, a future master-branch merge
-- that reintroduces seed data), the next `mvn` build/deploy on this branch strips it again rather
-- than silently drifting.
--
-- Claude API keys: closed-mode has no AI call sites left (B2, docs/spec/closed-mode-plan.md §9-2)
-- to ever decrypt/use a Claude key, so a row here on this branch is inert data with no legitimate
-- purpose -- and, being a secret, worth not retaining even inert. NVD keys are untouched: NVD sync
-- (bulk CPE/CVE mirror, still live-network on this branch) legitimately still uses them.
DELETE FROM user_secrets WHERE provider = 'claude';

-- Ecosystem registries: this table only ever backed the "connectable ecosystem registries" guide
-- page (GuideController/guide-integrations.html) advertising which live registries this app can
-- query -- closed-mode has no live per-item registry lookups left (B3) for any of those rows to
-- describe. EcosystemRegistry/EcosystemRegistryRepository (the JPA type/repository) are
-- deliberately NOT deleted here -- see this item's own PR description for why the type stays while
-- only its data is stripped.
DELETE FROM ecosystem_registries;
