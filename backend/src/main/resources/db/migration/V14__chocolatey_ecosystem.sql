-- V14__chocolatey_ecosystem.sql
-- Registers Chocolatey (Windows desktop package manager community feed) as a Stage1 registry
-- ecosystem, same as every other ChocolateyRegistryClient-backed row in this table — makes it
-- visible on the enabled-ecosystems admin page and available to Tier3's AI ecosystem_candidates.
INSERT INTO ecosystem_registries (ecosystem, display_name, lookup_base_url) VALUES
    ('chocolatey', 'Chocolatey (Windows)', 'https://community.chocolatey.org/api/v2/');
