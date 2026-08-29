-- V16__bundled_component_detection.sql
-- Bundled-package (formerly "Stage 3.5") detection: see docs/spec/bundled-package-detection-plan.md.
--
-- job_item_vulnerabilities gets two nullable columns identifying which bundled component a finding
-- was attributed to (option A from the plan's §3-4 — NOT a description-prefix hack): NULL means
-- "the product's own vulnerability" (every existing Stage2/Stage4 row, unaffected); non-NULL means
-- "found via a same-named CVE/GHSA record for this bundled component, not the product itself".
-- Lives on the join table (not on vulnerabilities) because vulnerabilities is a global CVE/GHSA
-- master row that can legitimately be linked from other items as either "the product itself" or "a
-- bundled component" — this attribution is per (job_item, vulnerability) pair, not global.
ALTER TABLE job_item_vulnerabilities ADD COLUMN bundled_component_name VARCHAR(255);
ALTER TABLE job_item_vulnerabilities ADD COLUMN bundled_component_version VARCHAR(100);

-- Per-job opt-in flag (checkbox on the upload form) — bundled-component checking is off by default
-- and only opted-in jobs get the separate bundled-component cost budget (see
-- JobCostBudgetService#startBundledComponentBudget) on top of the always-on $0.005/item cap.
ALTER TABLE research_jobs ADD COLUMN bundled_component_check_enabled boolean NOT NULL DEFAULT false;
