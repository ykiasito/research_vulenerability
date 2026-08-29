-- V5__version_confirmed.sql
-- Tracks whether the CSV-entered version was actually confirmed to exist by a package registry
-- (npm/PyPI/Maven/Go/NuGet all expose their real published-version lists for free). NULL means no
-- registry signal was available (e.g. CPE-only identification, which never validates version at
-- all) — kept distinct from FALSE ("registry checked and this exact version wasn't found") so the
-- UI can be honest about the difference between "unverified" and "verified not to exist".

ALTER TABLE identified_products ADD COLUMN version_confirmed BOOLEAN;
