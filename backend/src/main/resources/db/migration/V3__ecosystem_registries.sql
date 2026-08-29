-- V3__ecosystem_registries.sql
-- Catalog of package-registry ecosystems Stage1 can query. Used as the authoritative "enabled
-- ecosystems" list fed to Tier3's AI package-name resolution (so it only ever proposes an
-- ecosystem the backend can actually act on) and as an admin-visible record of what's supported.

CREATE TABLE ecosystem_registries (
    id                BIGSERIAL PRIMARY KEY,
    ecosystem         VARCHAR(50) NOT NULL UNIQUE,
    display_name      VARCHAR(100) NOT NULL,
    lookup_base_url   VARCHAR(500) NOT NULL,
    enabled           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ecosystem_registries (ecosystem, display_name, lookup_base_url) VALUES
    ('npm',   'npm (Node.js)',        'https://registry.npmjs.org/'),
    ('pypi',  'PyPI (Python)',        'https://pypi.org/pypi/'),
    ('maven', 'Maven Central (Java)', 'https://search.maven.org/solrsearch/select'),
    ('go',    'Go module proxy',      'https://proxy.golang.org/'),
    ('nuget', 'NuGet (.NET)',         'https://api.nuget.org/v3-flatcontainer/');
