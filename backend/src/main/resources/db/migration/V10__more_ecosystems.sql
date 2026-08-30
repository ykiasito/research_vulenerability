-- V10__more_ecosystems.sql
-- Adds 5 more OSV-supported ecosystems (of the 14 total OSV covers): RubyGems, crates.io,
-- Packagist, Hex, Pub. The remaining 4 (SwiftURL, ConanCenter, CRAN, GitHub Actions) are not
-- implemented — each has a fundamentally different identification scheme (git URL, C/C++ recipe
-- protocol, no clean public JSON API, owner/repo tags) that doesn't fit this table's
-- name+version lookup model; see docs/spec/known-limitations.md.
INSERT INTO ecosystem_registries (ecosystem, display_name, lookup_base_url) VALUES
    ('rubygems',  'RubyGems (Ruby)',        'https://rubygems.org/api/v1/versions/'),
    ('crates.io', 'crates.io (Rust)',       'https://crates.io/api/v1/crates/'),
    ('packagist', 'Packagist (PHP)',        'https://packagist.org/packages/'),
    ('hex',       'Hex (Erlang/Elixir)',    'https://hex.pm/api/packages/'),
    ('pub',       'pub.dev (Dart/Flutter)', 'https://pub.dev/api/packages/');
