-- V30__cpe_candidate_provenance.sql
-- Measurement-only columns for the confidence-calibration investigation (docs/spec/task-backlog.md
-- item 16, senior-reviewer analysis 2026-08-30): today cpeCandidates.size() is discarded once
-- Stage1IdentificationService#resolveCandidates picks a CPE, so there is no way to measure whether
-- "the CPE dictionary search found exactly one candidate" vs. "found several and one was picked"
-- correlates with accuracy in the 0.6 confidence bucket. These two columns exist purely to let a
-- future golden-300 re-measurement split that bucket by candidate-pool provenance -- they must
-- NEVER be surfaced in the job detail UI or any API response, and this task deliberately does not
-- change confidence calculation itself.
--
-- Both nullable: NULL whenever the identified product has no CPE at all (cpe IS NULL, e.g. a
-- registry-only match), and for every row written before this migration ran (no way to backfill
-- the candidate pool that has already been discarded).

-- Size of the CPE candidate pool that the chosen CPE came from (the outer cpeCandidates list for
-- the multi-/single-candidate paths, or the rescue lookup's own candidate pool for the
-- rescueCpeAfterRegistryMatchRejected path) -- 1 means no other candidate competed for the slot,
-- >1 means one was chosen among several (via Tier2 AI disambiguation or a no-arbitration
-- best-effort pick of the first).
ALTER TABLE identified_products ADD COLUMN cpe_candidate_count INTEGER;

-- Whether that candidate pool came from the name-variant search (a mechanically-derived guess
-- about what an abbreviation/contraction refers to, e.g. "VM Player" -> vlc_media_player) rather
-- than a literal dictionary/live-NVD match -- see resolveSingleCpeCandidate's javadoc for why this
-- distinction exists independently of candidate count.
ALTER TABLE identified_products ADD COLUMN cpe_candidate_variant_derived BOOLEAN;
