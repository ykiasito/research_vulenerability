-- V32__remove_chocolatey_ecosystem.sql
-- Backlog item 99: Chocolatey integration removed entirely (Chocolatey Community Repository's
-- terms of use restrict commercial use, see docs/spec/task-backlog.md item 93). ChocolateyRegistryClient
-- and all its routing/identification-logic special cases are gone (this same PR); this removes the
-- V14-inserted row so the guide page (GuideController/guide-integrations.html) and Tier3's
-- ecosystem_candidates list (Stage1IdentificationService) stop advertising an ecosystem no
-- PackageRegistryLookup implementation actually serves anymore.
DELETE FROM ecosystem_registries WHERE ecosystem = 'chocolatey';
