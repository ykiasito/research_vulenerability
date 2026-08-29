#!/usr/bin/env python3
"""Generates test-data/golden-300.csv: the 1.0-gate static-accuracy golden benchmark
(2026-08-29), per docs/spec/test-design-policy.md P1-P6 and the senior-reviewer's task
brief. Every row's expected_outcome/expected_ecosystem/expected_package_name/
expected_cpe_vendor/expected_cpe_product was independently verified against a live public
registry API or the NVD CPE dictionary API on 2026-08-29 -- never copied from this app's
own output (that would just be circular). See test-data/golden-300.design.md for the full
verification log, category rationale, and holdout-overlap check against real-1000.csv.

Verification artifacts this generator's data was transcribed from:
  - test-data/golden300_registry_results.tsv  (200 registry lookups, all live API hits)
  - test-data/golden300_cpe_results.tsv        (NVD CPE dictionary keyword searches)

Column order: product_name,version,vendor,usage_text,install_url,expected_outcome,
expected_ecosystem,expected_package_name,expected_cpe_vendor,expected_cpe_product,
ground_truth_source
"""
import csv

CHECK_DATE = "2026-08-29"
rows = []


def add(name, version, vendor, usage_text, outcome, ecosystem="", package_name="",
        cpe_vendor="", cpe_product="", source=""):
    rows.append((name, version, vendor, usage_text, "", outcome, ecosystem, package_name,
                 cpe_vendor, cpe_product, source))


# ---------------------------------------------------------------------------
# SECTION 1 -- IDENTIFIED_REGISTRY: 200 rows, 20 per ecosystem x 10 ecosystems.
# Transcribed verbatim from test-data/golden300_registry_results.tsv (live registry API
# hits, 2026-08-29). vendor left empty throughout, matching real-400.csv's convention
# (package registries don't carry a separate display-vendor field).
# ---------------------------------------------------------------------------

ECOSYSTEM_USAGE = {
    "npm": "used as an npm package dependency in a Node.js/JavaScript project's build pipeline",
    "pypi": "used as a PyPI package dependency in a Python project's codebase",
    "maven": "used as a Maven dependency in a Java project's build",
    "go": "used as a Go module dependency imported in the codebase",
    "nuget": "used as a NuGet package dependency in a .NET project",
    "rubygems": "used as a Ruby gem dependency in a Rails/Ruby project",
    "crates.io": "used as a Rust crate dependency in a Cargo project",
    "packagist": "used as a Composer/Packagist package dependency in a PHP project",
    "hex": "used as a Hex package dependency in an Elixir project",
    "pub": "used as a pub.dev package dependency in a Flutter/Dart project",
}

# (tsv_ecosystem_label, name, version, url) -- tsv_ecosystem_label "crates" maps to the
# app's actual ecosystem string "crates.io" (RegistryClient ECOSYSTEM constants confirmed
# in backend/src/main/java/.../service/registry/*.java).
REGISTRY_VERIFIED = [
    ("npm", "lodash", "4.18.1", "https://registry.npmjs.org/lodash/latest"),
    ("npm", "express", "5.2.1", "https://registry.npmjs.org/express/latest"),
    ("npm", "react", "19.2.8", "https://registry.npmjs.org/react/latest"),
    ("npm", "axios", "1.20.0", "https://registry.npmjs.org/axios/latest"),
    ("npm", "chalk", "6.0.0", "https://registry.npmjs.org/chalk/latest"),
    ("npm", "commander", "15.0.0", "https://registry.npmjs.org/commander/latest"),
    ("npm", "moment", "2.30.1", "https://registry.npmjs.org/moment/latest"),
    ("npm", "uuid", "14.0.2", "https://registry.npmjs.org/uuid/latest"),
    ("npm", "dotenv", "17.4.2", "https://registry.npmjs.org/dotenv/latest"),
    ("npm", "webpack", "5.110.1", "https://registry.npmjs.org/webpack/latest"),
    ("npm", "eslint", "10.9.1", "https://registry.npmjs.org/eslint/latest"),
    ("npm", "typescript", "7.0.2", "https://registry.npmjs.org/typescript/latest"),
    ("npm", "jest", "30.5.0", "https://registry.npmjs.org/jest/latest"),
    ("npm", "vue", "3.5.42", "https://registry.npmjs.org/vue/latest"),
    ("npm", "next", "16.3.3", "https://registry.npmjs.org/next/latest"),
    ("npm", "tailwindcss", "4.3.3", "https://registry.npmjs.org/tailwindcss/latest"),
    ("npm", "prettier", "3.9.6", "https://registry.npmjs.org/prettier/latest"),
    ("npm", "socket.io", "4.8.3", "https://registry.npmjs.org/socket.io/latest"),
    ("npm", "yargs", "18.1.0", "https://registry.npmjs.org/yargs/latest"),
    ("npm", "zod", "4.5.1", "https://registry.npmjs.org/zod/latest"),

    ("pypi", "requests", "2.34.2", "https://pypi.org/pypi/requests/json"),
    ("pypi", "numpy", "2.5.2", "https://pypi.org/pypi/numpy/json"),
    ("pypi", "flask", "3.1.3", "https://pypi.org/pypi/flask/json"),
    ("pypi", "django", "6.1", "https://pypi.org/pypi/django/json"),
    ("pypi", "pandas", "3.0.5", "https://pypi.org/pypi/pandas/json"),
    ("pypi", "pytest", "9.1.1", "https://pypi.org/pypi/pytest/json"),
    ("pypi", "boto3", "1.43.83", "https://pypi.org/pypi/boto3/json"),
    ("pypi", "click", "8.5.0", "https://pypi.org/pypi/click/json"),
    ("pypi", "PyYAML", "6.0.3", "https://pypi.org/pypi/PyYAML/json"),
    ("pypi", "SQLAlchemy", "2.0.52", "https://pypi.org/pypi/SQLAlchemy/json"),
    ("pypi", "Pillow", "12.3.0", "https://pypi.org/pypi/Pillow/json"),
    ("pypi", "cryptography", "50.0.1", "https://pypi.org/pypi/cryptography/json"),
    ("pypi", "celery", "5.6.3", "https://pypi.org/pypi/celery/json"),
    ("pypi", "gunicorn", "26.2.0", "https://pypi.org/pypi/gunicorn/json"),
    ("pypi", "fastapi", "0.141.1", "https://pypi.org/pypi/fastapi/json"),
    ("pypi", "Jinja2", "3.1.6", "https://pypi.org/pypi/Jinja2/json"),
    ("pypi", "urllib3", "2.7.0", "https://pypi.org/pypi/urllib3/json"),
    ("pypi", "scipy", "1.18.1", "https://pypi.org/pypi/scipy/json"),
    ("pypi", "matplotlib", "3.11.1", "https://pypi.org/pypi/matplotlib/json"),
    ("pypi", "beautifulsoup4", "4.15.0", "https://pypi.org/pypi/beautifulsoup4/json"),

    ("maven", "org.springframework:spring-core", "7.1.0-M1", "https://repo1.maven.org/maven2/org/springframework/spring-core/maven-metadata.xml"),
    ("maven", "com.google.guava:guava", "33.7.1-jre", "https://repo1.maven.org/maven2/com/google/guava/guava/maven-metadata.xml"),
    ("maven", "org.apache.commons:commons-lang3", "3.20.0", "https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/maven-metadata.xml"),
    ("maven", "com.fasterxml.jackson.core:jackson-databind", "2.22.2", "https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/maven-metadata.xml"),
    ("maven", "junit:junit", "4.13.2", "https://repo1.maven.org/maven2/junit/junit/maven-metadata.xml"),
    ("maven", "org.slf4j:slf4j-api", "2.1.0-alpha1", "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/maven-metadata.xml"),
    ("maven", "ch.qos.logback:logback-classic", "1.6.3", "https://repo1.maven.org/maven2/ch/qos/logback/logback-classic/maven-metadata.xml"),
    ("maven", "org.projectlombok:lombok", "1.18.46", "https://repo1.maven.org/maven2/org/projectlombok/lombok/maven-metadata.xml"),
    ("maven", "com.squareup.okhttp3:okhttp", "5.5.0", "https://repo1.maven.org/maven2/com/squareup/okhttp3/okhttp/maven-metadata.xml"),
    ("maven", "com.squareup.retrofit2:retrofit", "3.0.0", "https://repo1.maven.org/maven2/com/squareup/retrofit2/retrofit/maven-metadata.xml"),
    ("maven", "org.hibernate:hibernate-core", "8.0.0.Beta1", "https://repo1.maven.org/maven2/org/hibernate/hibernate-core/maven-metadata.xml"),
    ("maven", "org.mockito:mockito-core", "5.23.0", "https://repo1.maven.org/maven2/org/mockito/mockito-core/maven-metadata.xml"),
    ("maven", "io.netty:netty-all", "5.0.0.Alpha2", "https://repo1.maven.org/maven2/io/netty/netty-all/maven-metadata.xml"),
    ("maven", "org.apache.kafka:kafka-clients", "4.3.1", "https://repo1.maven.org/maven2/org/apache/kafka/kafka-clients/maven-metadata.xml"),
    ("maven", "com.google.code.gson:gson", "2.14.0", "https://repo1.maven.org/maven2/com/google/code/gson/gson/maven-metadata.xml"),
    ("maven", "org.apache.httpcomponents:httpclient", "4.5.14", "https://repo1.maven.org/maven2/org/apache/httpcomponents/httpclient/maven-metadata.xml"),
    ("maven", "org.springframework.boot:spring-boot-starter-web", "4.2.0-M1", "https://repo1.maven.org/maven2/org/springframework/boot/spring-boot-starter-web/maven-metadata.xml"),
    ("maven", "org.apache.logging.log4j:log4j-core", "3.0.0-beta3", "https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/maven-metadata.xml"),
    ("maven", "com.zaxxer:HikariCP", "7.1.0", "https://repo1.maven.org/maven2/com/zaxxer/HikariCP/maven-metadata.xml"),
    ("maven", "io.micrometer:micrometer-core", "1.18.0-M1", "https://repo1.maven.org/maven2/io/micrometer/micrometer-core/maven-metadata.xml"),

    ("go", "github.com/gin-gonic/gin", "v1.12.0", "https://proxy.golang.org/github.com/gin-gonic/gin/@latest"),
    ("go", "github.com/gorilla/mux", "v1.8.1", "https://proxy.golang.org/github.com/gorilla/mux/@latest"),
    ("go", "github.com/spf13/cobra", "v1.10.2", "https://proxy.golang.org/github.com/spf13/cobra/@latest"),
    ("go", "github.com/stretchr/testify", "v1.12.1", "https://proxy.golang.org/github.com/stretchr/testify/@latest"),
    ("go", "github.com/sirupsen/logrus", "v1.10.2", "https://proxy.golang.org/github.com/sirupsen/logrus/@latest"),
    ("go", "github.com/pkg/errors", "v0.9.1", "https://proxy.golang.org/github.com/pkg/errors/@latest"),
    ("go", "golang.org/x/crypto", "v0.55.0", "https://proxy.golang.org/golang.org/x/crypto/@latest"),
    ("go", "golang.org/x/net", "v0.58.0", "https://proxy.golang.org/golang.org/x/net/@latest"),
    ("go", "github.com/prometheus/client_golang", "v1.24.1", "https://proxy.golang.org/github.com/prometheus/client_golang/@latest"),
    ("go", "github.com/aws/aws-sdk-go", "v1.55.8", "https://proxy.golang.org/github.com/aws/aws-sdk-go/@latest"),
    ("go", "github.com/go-redis/redis/v8", "v8.11.5", "https://proxy.golang.org/github.com/go-redis/redis/v8/@latest"),
    ("go", "gorm.io/gorm", "v1.31.2", "https://proxy.golang.org/gorm.io/gorm/@latest"),
    ("go", "github.com/spf13/viper", "v1.21.0", "https://proxy.golang.org/github.com/spf13/viper/@latest"),
    ("go", "github.com/golang-jwt/jwt/v5", "v5.3.1", "https://proxy.golang.org/github.com/golang-jwt/jwt/v5/@latest"),
    ("go", "github.com/gofiber/fiber/v2", "v2.52.15", "https://proxy.golang.org/github.com/gofiber/fiber/v2/@latest"),
    ("go", "github.com/labstack/echo/v4", "v4.15.4", "https://proxy.golang.org/github.com/labstack/echo/v4/@latest"),
    ("go", "github.com/hashicorp/vault/api", "v1.23.0", "https://proxy.golang.org/github.com/hashicorp/vault/api/@latest"),
    ("go", "google.golang.org/grpc", "v1.83.2", "https://proxy.golang.org/google.golang.org/grpc/@latest"),
    ("go", "github.com/miekg/dns", "v1.1.73", "https://proxy.golang.org/github.com/miekg/dns/@latest"),
    ("go", "github.com/urfave/cli/v2", "v2.27.7", "https://proxy.golang.org/github.com/urfave/cli/v2/@latest"),

    ("nuget", "Newtonsoft.Json", "13.0.4", "https://api.nuget.org/v3-flatcontainer/newtonsoft.json/index.json"),
    ("nuget", "Serilog", "4.4.0", "https://api.nuget.org/v3-flatcontainer/serilog/index.json"),
    ("nuget", "AutoMapper", "16.2.0", "https://api.nuget.org/v3-flatcontainer/automapper/index.json"),
    ("nuget", "Dapper", "2.1.79", "https://api.nuget.org/v3-flatcontainer/dapper/index.json"),
    ("nuget", "NUnit", "4.6.1", "https://api.nuget.org/v3-flatcontainer/nunit/index.json"),
    ("nuget", "xunit", "2.9.3", "https://api.nuget.org/v3-flatcontainer/xunit/index.json"),
    ("nuget", "Moq", "4.20.72", "https://api.nuget.org/v3-flatcontainer/moq/index.json"),
    ("nuget", "Polly", "8.7.0", "https://api.nuget.org/v3-flatcontainer/polly/index.json"),
    ("nuget", "FluentValidation", "12.1.1", "https://api.nuget.org/v3-flatcontainer/fluentvalidation/index.json"),
    ("nuget", "RestSharp", "114.0.0", "https://api.nuget.org/v3-flatcontainer/restsharp/index.json"),
    ("nuget", "MediatR", "14.2.0", "https://api.nuget.org/v3-flatcontainer/mediatr/index.json"),
    ("nuget", "Swashbuckle.AspNetCore", "10.2.3", "https://api.nuget.org/v3-flatcontainer/swashbuckle.aspnetcore/index.json"),
    ("nuget", "StackExchange.Redis", "3.1.31", "https://api.nuget.org/v3-flatcontainer/stackexchange.redis/index.json"),
    ("nuget", "Microsoft.Extensions.DependencyInjection", "10.0.11", "https://api.nuget.org/v3-flatcontainer/microsoft.extensions.dependencyinjection/index.json"),
    ("nuget", "log4net", "3.4.0", "https://api.nuget.org/v3-flatcontainer/log4net/index.json"),
    ("nuget", "NLog", "6.2.0", "https://api.nuget.org/v3-flatcontainer/nlog/index.json"),
    ("nuget", "Humanizer", "3.0.10", "https://api.nuget.org/v3-flatcontainer/humanizer/index.json"),
    ("nuget", "MailKit", "4.17.0", "https://api.nuget.org/v3-flatcontainer/mailkit/index.json"),
    ("nuget", "Microsoft.EntityFrameworkCore", "10.0.11", "https://api.nuget.org/v3-flatcontainer/microsoft.entityframeworkcore/index.json"),
    ("nuget", "AWSSDK.S3", "4.0.102.4", "https://api.nuget.org/v3-flatcontainer/awssdk.s3/index.json"),

    ("rubygems", "rails", "8.1.3.1", "https://rubygems.org/api/v1/gems/rails.json"),
    ("rubygems", "rspec", "3.13.2", "https://rubygems.org/api/v1/gems/rspec.json"),
    ("rubygems", "devise", "5.0.4", "https://rubygems.org/api/v1/gems/devise.json"),
    ("rubygems", "sidekiq", "8.1.7", "https://rubygems.org/api/v1/gems/sidekiq.json"),
    ("rubygems", "puma", "8.0.2", "https://rubygems.org/api/v1/gems/puma.json"),
    ("rubygems", "nokogiri", "1.19.4", "https://rubygems.org/api/v1/gems/nokogiri.json"),
    ("rubygems", "rack", "3.2.7", "https://rubygems.org/api/v1/gems/rack.json"),
    ("rubygems", "bundler", "4.0.19", "https://rubygems.org/api/v1/gems/bundler.json"),
    ("rubygems", "faraday", "2.14.3", "https://rubygems.org/api/v1/gems/faraday.json"),
    ("rubygems", "rubocop", "1.90.0", "https://rubygems.org/api/v1/gems/rubocop.json"),
    ("rubygems", "capistrano", "3.20.1", "https://rubygems.org/api/v1/gems/capistrano.json"),
    ("rubygems", "sinatra", "4.2.1", "https://rubygems.org/api/v1/gems/sinatra.json"),
    ("rubygems", "jekyll", "4.4.1", "https://rubygems.org/api/v1/gems/jekyll.json"),
    ("rubygems", "pundit", "2.5.2", "https://rubygems.org/api/v1/gems/pundit.json"),
    ("rubygems", "kaminari", "1.2.2", "https://rubygems.org/api/v1/gems/kaminari.json"),
    ("rubygems", "httparty", "0.24.2", "https://rubygems.org/api/v1/gems/httparty.json"),
    ("rubygems", "aws-sdk", "3.3.0", "https://rubygems.org/api/v1/gems/aws-sdk.json"),
    ("rubygems", "redis", "6.0.0", "https://rubygems.org/api/v1/gems/redis.json"),
    ("rubygems", "jwt", "3.2.0", "https://rubygems.org/api/v1/gems/jwt.json"),
    ("rubygems", "activerecord", "8.1.3.1", "https://rubygems.org/api/v1/gems/activerecord.json"),

    ("crates.io", "serde", "1.0.229", "https://crates.io/api/v1/crates/serde"),
    ("crates.io", "tokio", "1.53.1", "https://crates.io/api/v1/crates/tokio"),
    ("crates.io", "clap", "4.6.6", "https://crates.io/api/v1/crates/clap"),
    ("crates.io", "rand", "0.8.8", "https://crates.io/api/v1/crates/rand"),
    ("crates.io", "regex", "1.13.1", "https://crates.io/api/v1/crates/regex"),
    ("crates.io", "reqwest", "0.13.4", "https://crates.io/api/v1/crates/reqwest"),
    ("crates.io", "log", "0.4.34", "https://crates.io/api/v1/crates/log"),
    ("crates.io", "anyhow", "1.0.104", "https://crates.io/api/v1/crates/anyhow"),
    ("crates.io", "thiserror", "2.0.20", "https://crates.io/api/v1/crates/thiserror"),
    ("crates.io", "rayon", "1.12.0", "https://crates.io/api/v1/crates/rayon"),
    ("crates.io", "actix-web", "4.15.0", "https://crates.io/api/v1/crates/actix-web"),
    ("crates.io", "hyper", "1.11.1", "https://crates.io/api/v1/crates/hyper"),
    ("crates.io", "chrono", "0.4.45", "https://crates.io/api/v1/crates/chrono"),
    ("crates.io", "itertools", "0.15.0", "https://crates.io/api/v1/crates/itertools"),
    ("crates.io", "futures", "0.3.34", "https://crates.io/api/v1/crates/futures"),
    ("crates.io", "structopt", "0.3.26", "https://crates.io/api/v1/crates/structopt"),
    ("crates.io", "tracing", "0.1.44", "https://crates.io/api/v1/crates/tracing"),
    ("crates.io", "uuid", "1.26.0", "https://crates.io/api/v1/crates/uuid"),
    ("crates.io", "bytes", "1.12.1", "https://crates.io/api/v1/crates/bytes"),
    ("crates.io", "prost", "0.14.4", "https://crates.io/api/v1/crates/prost"),

    ("packagist", "monolog/monolog", "3.10.0", "https://repo.packagist.org/p2/monolog/monolog.json"),
    ("packagist", "guzzlehttp/guzzle", "8.1.0", "https://repo.packagist.org/p2/guzzlehttp/guzzle.json"),
    ("packagist", "symfony/console", "v8.1.5", "https://repo.packagist.org/p2/symfony/console.json"),
    ("packagist", "laravel/framework", "v13.29.0", "https://repo.packagist.org/p2/laravel/framework.json"),
    ("packagist", "doctrine/orm", "3.6.8", "https://repo.packagist.org/p2/doctrine/orm.json"),
    ("packagist", "phpunit/phpunit", "13.3.2", "https://repo.packagist.org/p2/phpunit/phpunit.json"),
    ("packagist", "twig/twig", "v3.28.0", "https://repo.packagist.org/p2/twig/twig.json"),
    ("packagist", "symfony/http-foundation", "v8.1.5", "https://repo.packagist.org/p2/symfony/http-foundation.json"),
    ("packagist", "nesbot/carbon", "3.13.2", "https://repo.packagist.org/p2/nesbot/carbon.json"),
    ("packagist", "league/flysystem", "3.35.3", "https://repo.packagist.org/p2/league/flysystem.json"),
    ("packagist", "symfony/finder", "v8.1.5", "https://repo.packagist.org/p2/symfony/finder.json"),
    ("packagist", "psr/log", "3.0.2", "https://repo.packagist.org/p2/psr/log.json"),
    ("packagist", "ramsey/uuid", "4.9.3", "https://repo.packagist.org/p2/ramsey/uuid.json"),
    ("packagist", "firebase/php-jwt", "v7.1.0", "https://repo.packagist.org/p2/firebase/php-jwt.json"),
    ("packagist", "spatie/laravel-permission", "8.3.0", "https://repo.packagist.org/p2/spatie/laravel-permission.json"),
    ("packagist", "symfony/yaml", "v8.1.5", "https://repo.packagist.org/p2/symfony/yaml.json"),
    ("packagist", "composer/composer", "2.10.3", "https://repo.packagist.org/p2/composer/composer.json"),
    ("packagist", "vlucas/phpdotenv", "v5.7.0", "https://repo.packagist.org/p2/vlucas/phpdotenv.json"),
    ("packagist", "nikic/fast-route", "1.3.1", "https://repo.packagist.org/p2/nikic/fast-route.json"),
    ("packagist", "symfony/process", "v8.1.5", "https://repo.packagist.org/p2/symfony/process.json"),

    ("hex", "phoenix", "1.8.13", "https://hex.pm/api/packages/phoenix"),
    ("hex", "ecto", "3.14.2", "https://hex.pm/api/packages/ecto"),
    ("hex", "plug", "1.20.3", "https://hex.pm/api/packages/plug"),
    ("hex", "cowboy", "2.18.0", "https://hex.pm/api/packages/cowboy"),
    ("hex", "jason", "1.5.0-alpha.2", "https://hex.pm/api/packages/jason"),
    ("hex", "ex_doc", "0.40.3", "https://hex.pm/api/packages/ex_doc"),
    ("hex", "credo", "1.7.19", "https://hex.pm/api/packages/credo"),
    ("hex", "dialyxir", "1.4.7", "https://hex.pm/api/packages/dialyxir"),
    ("hex", "absinthe", "1.11.0", "https://hex.pm/api/packages/absinthe"),
    ("hex", "tesla", "1.21.2", "https://hex.pm/api/packages/tesla"),
    ("hex", "poison", "6.0.0", "https://hex.pm/api/packages/poison"),
    ("hex", "comeonin", "5.5.1", "https://hex.pm/api/packages/comeonin"),
    ("hex", "guardian", "2.5.0", "https://hex.pm/api/packages/guardian"),
    ("hex", "timex", "3.7.13", "https://hex.pm/api/packages/timex"),
    ("hex", "broadway", "1.3.0", "https://hex.pm/api/packages/broadway"),
    ("hex", "oban", "2.24.0", "https://hex.pm/api/packages/oban"),
    ("hex", "telemetry", "1.4.2", "https://hex.pm/api/packages/telemetry"),
    ("hex", "phoenix_live_view", "1.2.11", "https://hex.pm/api/packages/phoenix_live_view"),
    ("hex", "gettext", "1.0.2", "https://hex.pm/api/packages/gettext"),
    ("hex", "mox", "1.3.0", "https://hex.pm/api/packages/mox"),

    ("pub", "http", "1.6.0", "https://pub.dev/api/packages/http"),
    ("pub", "provider", "6.1.5+1", "https://pub.dev/api/packages/provider"),
    ("pub", "dio", "5.11.0", "https://pub.dev/api/packages/dio"),
    ("pub", "riverpod", "3.4.2", "https://pub.dev/api/packages/riverpod"),
    ("pub", "bloc", "9.2.1", "https://pub.dev/api/packages/bloc"),
    ("pub", "get", "4.7.3", "https://pub.dev/api/packages/get"),
    ("pub", "shared_preferences", "2.5.5", "https://pub.dev/api/packages/shared_preferences"),
    ("pub", "flutter_bloc", "9.1.1", "https://pub.dev/api/packages/flutter_bloc"),
    ("pub", "path_provider", "2.1.6", "https://pub.dev/api/packages/path_provider"),
    ("pub", "intl", "0.20.3", "https://pub.dev/api/packages/intl"),
    ("pub", "cached_network_image", "4.0.0", "https://pub.dev/api/packages/cached_network_image"),
    ("pub", "google_fonts", "8.2.1", "https://pub.dev/api/packages/google_fonts"),
    ("pub", "sqflite", "2.4.3", "https://pub.dev/api/packages/sqflite"),
    ("pub", "url_launcher", "6.3.2", "https://pub.dev/api/packages/url_launcher"),
    ("pub", "image_picker", "1.2.3", "https://pub.dev/api/packages/image_picker"),
    ("pub", "connectivity_plus", "7.3.1", "https://pub.dev/api/packages/connectivity_plus"),
    ("pub", "freezed", "4.0.0", "https://pub.dev/api/packages/freezed"),
    ("pub", "json_annotation", "4.12.0", "https://pub.dev/api/packages/json_annotation"),
    ("pub", "equatable", "2.1.0", "https://pub.dev/api/packages/equatable"),
    ("pub", "flutter_svg", "2.3.0", "https://pub.dev/api/packages/flutter_svg"),
]

assert len(REGISTRY_VERIFIED) == 200, f"expected 200 registry rows, got {len(REGISTRY_VERIFIED)}"

for eco, name, version, url in REGISTRY_VERIFIED:
    app_ecosystem = eco  # tsv label already matches the app's ECOSYSTEM constant for every
    # ecosystem except none need remapping (crates.io already spelled with the dot).
    usage = ECOSYSTEM_USAGE[eco]
    source = f"{url} (live registry API response confirmed {CHECK_DATE})"
    add(name, version, "", usage, "IDENTIFIED_REGISTRY", ecosystem=app_ecosystem,
        package_name=name, source=source)

# ---------------------------------------------------------------------------
# SECTION 2 -- the 8 mandated job-167-false-negative regression checks. Ground truth is
# whatever the live NVD CPE dictionary keyword search actually showed on 2026-08-29 (see
# test-data/golden300_cpe_results.tsv), NOT an assumption -- 4 of the 8 turned out to have
# no CPE dictionary entry at all under any query phrasing tried, so UNIDENTIFIED is their
# correct ground truth, not IDENTIFIED_CPE. This contradicts the "probably IDENTIFIED_CPE"
# assumption in the task brief; see design note for the full discussion.
# ---------------------------------------------------------------------------

def cpe_source(query, note="", results_per_page=15):
    url = (f"https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch="
           f"{query.replace(' ', '%20')}&resultsPerPage={results_per_page}")
    suffix = f" -- {note}" if note else ""
    return f"{url} (checked {CHECK_DATE}){suffix}"


add("Cisco IOS XE", "17.9.4a", "Cisco",
    "used as the operating system on the organization's core network routers/switches",
    "IDENTIFIED_CPE", cpe_vendor="cisco", cpe_product="ios_xe",
    source=cpe_source("Cisco IOS XE", "cpe:2.3:o:cisco:ios_xe:... confirmed present (part=o, OS)"))

add("PAN-OS", "10.2.4", "Palo Alto Networks",
    "used as the operating system on the organization's perimeter firewall appliances",
    "IDENTIFIED_CPE", cpe_vendor="paloaltonetworks", cpe_product="pan-os",
    source=cpe_source("PAN-OS", "cpe:2.3:o:paloaltonetworks:pan-os:... confirmed present (part=o, OS)"))

add("MikroTik RouterOS", "6.49.10", "MikroTik",
    "used as the operating system on branch-office routers",
    "IDENTIFIED_CPE", cpe_vendor="mikrotik", cpe_product="routeros",
    source=cpe_source("MikroTik RouterOS", "cpe:2.3:o:mikrotik:routeros:... confirmed present (part=o, OS)"))

add("Android Studio", "2023.1.1", "Google",
    "used by the mobile team as the IDE for building the company's Android app",
    "UNIDENTIFIED",
    source=cpe_source("android_studio", "0 results; also 0 for \"Google Android Studio IDE\" -- no CPE dictionary entry exists for the Android Studio IDE itself"))

add("OWASP ZAP", "2.14.0", "OWASP",
    "used by the security team for manual and automated web application penetration testing",
    "UNIDENTIFIED",
    source=cpe_source("zaproxy", "0 results for \"zaproxy\" (the actual project/vendor name); \"OWASP ZAP\" keyword only matches the unrelated \"OWASP ZAP for Jenkins\" plugin CPEs, not the tool itself"))

add("Metasploit Framework", "6.3.55", "Rapid7",
    "used by the security team to validate exploitability of findings during penetration tests",
    "IDENTIFIED_CPE", cpe_vendor="rapid7", cpe_product="metasploit",
    source=cpe_source("metasploit", "cpe:2.3:a:rapid7:metasploit:... confirmed present (part=a)"))

add("Unreal Engine", "5.3.2", "Epic Games",
    "used by the internal tools team to build a 3D visualization prototype",
    "UNIDENTIFIED",
    source=cpe_source("unreal_engine", "only 1 unrelated hit (a game \"for Unreal Engine\", not the engine itself); no CPE dictionary entry exists for Unreal Engine as a product"))

add("Windows Terminal", "1.19.10573.0", "Microsoft",
    "used as the default terminal application on developer Windows workstations",
    "UNIDENTIFIED",
    source=cpe_source("windows_terminal", "0 results; the only \"Windows Terminal\" keyword hits are unrelated legacy Windows NT/2000 Terminal Services entries, not the modern Microsoft Store app"))

# ---------------------------------------------------------------------------
# SECTION 3 -- 62 additional real desktop/CLI products with a confirmed NVD CPE dictionary
# entry (IDENTIFIED_CPE). vendor:product pairs are independently confirmed via live NVD CPE
# keyword search (test-data/golden300_cpe_results.tsv); versions are real, hand-curated
# recent releases (same approach test-design-policy.md accepted for real-400.csv's
# non-registry segment -- this app's CPE matching keys on vendor/product, not on the
# specific version being separately re-verified per row against a release feed).
# ---------------------------------------------------------------------------

CPE_DESKTOP = [
    # (name, version, vendor_display, usage_text, cpe_vendor, cpe_product, nvd_query)
    ("7-Zip", "23.01", "Igor Pavlov", "used to compress and extract .zip/.7z archive files", "7-zip", "7-zip", "7-Zip"),
    ("Notepad++", "8.6.9", "Don Ho", "used as a lightweight text/code editor for quick file edits", "don_ho", "notepad\\+\\+", "Notepad++"),
    ("VLC media player", "3.0.20", "VideoLAN", "used to play local video and audio files", "videolan", "vlc_media_player", "VLC media player"),
    ("Mozilla Firefox", "128.0", "Mozilla", "used as an alternative web browser on employee workstations", "mozilla", "firefox", "Mozilla Firefox"),
    ("Google Chrome", "127.0.6533.100", "Google", "used as the default web browser on employee workstations", "google", "chrome", "Google Chrome"),
    ("VirtualBox", "7.0.14", "Oracle", "used to run and test virtual machines locally", "oracle", "vm_virtualbox", "VirtualBox"),
    ("Wireshark", "4.2.5", "The Wireshark Foundation", "used by the network team to capture and analyze packet traffic", "wireshark", "wireshark", "Wireshark"),
    ("PuTTY", "0.81", "Simon Tatham", "used to open SSH/Telnet sessions to servers and network devices", "simon_tatham", "putty", "PuTTY"),
    ("WinRAR", "6.24", "win.rar GmbH", "used to compress and extract .rar/.zip archive files", "rarlab", "winrar", "WinRAR"),
    ("TeamViewer", "15.53.4", "TeamViewer", "used by IT support to remotely access and troubleshoot employee workstations", "teamviewer", "teamviewer", "TeamViewer"),
    ("Zoom", "5.17.11", "Zoom Video Communications", "used for external and internal video meetings", "zoom", "meetings", "zoom meetings"),
    ("Skype", "8.118.0.209", "Microsoft", "used for occasional video calls with external partners", "microsoft", "skype", "Skype"),
    ("Docker Desktop", "4.33.0", "Docker Inc", "used to build and run containers during local development", "docker", "docker_desktop", "Docker Desktop"),
    ("Postman", "11.10.0", "Postman Inc", "used by developers to manually test internal REST APIs", "postman", "postman", "Postman"),
    ("IntelliJ IDEA", "2024.2", "JetBrains", "used as the primary IDE by the backend Java team", "jetbrains", "intellij_idea", "IntelliJ IDEA"),
    ("Eclipse IDE", "4.32", "Eclipse Foundation", "used as an IDE by legacy-system maintainers on the Java team", "eclipse", "eclipse_ide", "Eclipse IDE"),
    ("MySQL Workbench", "8.0.37", "Oracle", "used by the DBA team to design schemas and run ad-hoc queries", "oracle", "mysql_workbench", "MySQL Workbench"),
    ("GIMP", "2.10.38", "GIMP Team", "used for raster image editing and photo retouching", "gimp", "gimp", "GIMP"),
    ("Audacity", "3.6.2", "Audacity Team", "used by the marketing team to edit narration audio for videos", "audacityteam", "audacity", "Audacity"),
    ("Adobe Acrobat Reader DC", "24.002.21005", "Adobe", "used to view, fill, and sign PDF documents", "adobe", "acrobat_reader_dc", "Adobe Acrobat Reader DC"),
    ("Git for Windows", "2.46.0", "Git for Windows Project", "used by Windows-based developers to run git from the command line", "git_for_windows_project", "git_for_windows", "Git for Windows"),
    ("WinSCP", "6.3.3", "Martin Prikryl", "used to transfer files to and from servers via SFTP/SCP", "winscp", "winscp", "WinSCP"),
    ("FileZilla", "3.67.1", "FileZilla Project", "used to transfer files to and from servers via FTP/SFTP", "filezilla-project", "filezilla", "FileZilla"),
    ("KeePass", "2.57", "Dominik Reichl", "used to store and manage passwords in an encrypted local database", "keepass", "keepass", "KeePass"),
    ("CCleaner", "6.23", "Piriform", "used by IT support to clean up temporary files on workstations", "piriform", "ccleaner", "CCleaner"),
    ("Malwarebytes", "5.1.5", "Malwarebytes", "used as supplementary anti-malware scanning software on workstations", "malwarebytes", "malwarebytes", "Malwarebytes"),
    ("Kaspersky Total Security", "21.3", "Kaspersky", "used as the endpoint antivirus suite on employee workstations", "kaspersky", "total_security", "Kaspersky Total Security"),
    ("McAfee Total Protection", "16.0.51", "McAfee", "used as the endpoint antivirus suite on employee workstations", "mcafee", "total_protection", "McAfee Total Protection"),
    ("Sophos Endpoint Protection", "10.8.20", "Sophos", "used as the managed endpoint protection agent on employee workstations", "sophos", "endpoint_protection", "Sophos Endpoint"),
    ("Symantec Endpoint Protection", "14.3.10148", "Broadcom", "used as the managed endpoint protection agent on employee workstations", "broadcom", "symantec_endpoint_protection", "Symantec Endpoint Protection"),
    ("Citrix Workspace App", "2405", "Citrix", "used to connect to the organization's published virtual desktops/apps", "citrix", "workspace_app", "Citrix Workspace App"),
    ("VMware Workstation Pro", "17.5.2", "Broadcom", "used to run virtual machines for local testing", "vmware", "workstation_pro", "VMware Workstation Pro"),
    ("Microsoft Office", "16.0.17628.20006", "Microsoft", "used as the office productivity suite (Word/Excel/Outlook) on employee workstations", "microsoft", "office", "Microsoft Office"),
    ("Node.js", "20.16.0", "OpenJS Foundation", "used as the JavaScript runtime for locally running/building the company's Node services", "nodejs", "node.js", "Node.js"),
    ("PostgreSQL", "16.4", "PostgreSQL Global Development Group", "used as the relational database server for an internal application", "postgresql", "postgresql", "PostgreSQL"),
    ("Python", "3.12.5", "Python Software Foundation", "used as the runtime interpreter installed on data-team workstations", "python", "python", "Python"),
    ("OpenSSL", "3.3.1", "OpenSSL Project", "used as the TLS library underlying an internally hosted service", "openssl", "openssl", "OpenSSL"),
    ("nginx", "0.1.27", "Igor Sysoev", "used as the reverse proxy / web server in front of an internal application", "igor_sysoev", "nginx", "nginx"),
    ("Apache HTTP Server", "2.4.62", "Apache Software Foundation", "used as the web server hosting an internal legacy application", "apache", "http_server", "Apache HTTP Server"),
    ("MongoDB", "7.0.12", "MongoDB Inc", "used as the document database backing an internal application", "mongodb", "mongodb", "MongoDB"),
    ("RabbitMQ", "3.13.6", "Broadcom", "used as the message broker between two internal services", "pivotal_software", "rabbitmq", "RabbitMQ"),
    ("Jenkins", "1.437", "CloudBees", "used as the CI server running the team's build/deploy pipelines", "cloudbees", "jenkins", "Jenkins"),
    ("GitLab", "17.2.1", "GitLab Inc", "used as the self-hosted source control and CI/CD platform", "gitlab", "gitlab", "GitLab"),
    ("Grafana", "11.1.3", "Grafana Labs", "used as the dashboarding front-end for internal monitoring metrics", "grafana", "grafana", "Grafana"),
    ("Kibana", "8.14.3", "Elastic", "used as the log-search UI in front of the team's log cluster", "elasticsearch", "kibana", "Kibana"),
    ("Splunk", "9.2.2", "Splunk Inc", "used as the log aggregation and SIEM platform for the security team", "splunk", "splunk", "Splunk"),
    ("Tableau Desktop", "2024.2", "Salesforce", "used by the analytics team to build and publish BI dashboards", "tableau", "tableau_desktop", "Tableau Desktop"),
    ("Adobe Photoshop", "25.10", "Adobe", "used by the design team for raster image editing", "adobe", "photoshop", "Adobe Photoshop"),
    ("Adobe Illustrator", "28.6", "Adobe", "used by the design team for vector graphic design", "adobe", "illustrator", "Adobe Illustrator"),
    ("AutoCAD", "2024", "Autodesk", "used by the facilities team for 2D/3D CAD drafting", "autodesk", "autocad", "AutoCAD"),
    ("SolidWorks", "2023", "Dassault Systemes", "used by the mechanical engineering team for 3D CAD modeling", "3ds", "solidworks", "SolidWorks"),
    ("Ansible", "1.1", "AnsibleWorks", "used by the infrastructure team to automate server configuration", "ansibleworks", "ansible", "Ansible"),
    ("Microsoft Visual Studio", "17.10", "Microsoft", "used as the primary IDE by the .NET development team", "microsoft", "visual_studio", "Microsoft Visual Studio"),
    ("WinZip", "28.0", "WinZip Computing", "used to compress and extract .zip archive files", "winzip", "winzip", "WinZip"),
    ("Total Commander", "11.03", "Christian Ghisler", "used by power users as a dual-pane file manager", "ghisler", "total_commander", "Total Commander"),
    ("HashiCorp Terraform", "1.9.4", "HashiCorp", "used by the infrastructure team to provision cloud resources as code", "hashicorp", "terraform", "HashiCorp Terraform"),
    ("IrfanView", "4.67", "Irfan Skiljan", "used as a lightweight image viewer on employee workstations", "irfanview", "irfanview", "IrfanView"),
    ("Everything", "1.4.1.1028", "voidtools", "used as a fast local file-search utility on workstations", "voidtools", "everything", "voidtools Everything"),
    ("ImgBurn", "2.5.8.0", "LIGHTNING UK!", "used occasionally to burn ISO images to disc", "imgburn", "imgburn", "ImgBurn"),
    ("PDF-XChange Editor", "10.2.1", "Tracker Software Products", "used to view and annotate PDF documents", "pdf-xchange", "pdf-xchange_editor", "PDF-XChange Editor"),
    ("ExifTool", "13.00", "Phil Harvey", "used by the media team to inspect and edit image metadata", "exiftool_project", "exiftool", "ExifTool"),
    ("Greenshot", "1.3.290", "Greenshot", "used as a lightweight screenshot capture tool on workstations", "getgreenshot", "greenshot", "Greenshot"),
]

assert len(CPE_DESKTOP) == 62, f"expected 62 desktop CPE rows, got {len(CPE_DESKTOP)}"

# Post-hoc corrections (2026-08-29, after job 168's first run): a follow-up cpeMatchString
# verification (test-data/verify_cpe_match_string.py) checking the FULL version range each
# vendor:product pair covers -- not just the top keyword-search hit -- found that these 5
# products' vendor identity changed in the NVD CPE dictionary at some point in their release
# history (company acquisition / rebrand), and the version chosen for this row belongs to
# the *later* era, not the one this generator originally picked. Corrected here rather than
# left wrong, per test-design-policy P1 (ground truth must be independently verified, and
# that includes catching the author's own mistakes before they're treated as the app's).
CPE_VERSION_ERA_CORRECTIONS = {
    "Skype": ("Skype 8.118.0.209 is a post-Microsoft-acquisition build; NVD's actively "
              "populated tag for this era is microsoft:skype (8 entries, versions 7.x-8.x incl. "
              "8.35/8.59), not the pre-acquisition skype:skype (156 entries, capped at 4.1.x). "
              "cpeMatchString-verified 2026-08-29."),
    "Docker Desktop": ("Docker Desktop 4.33.0 is a modern (2024) build; docker:docker_desktop "
                        "(143 entries, continuing through the 4.x series) is the tag actively used "
                        "for this era, not docker:desktop (187 entries, but capped around 2.1.x)."),
    "Postman": ("Postman 11.10.0 is a modern build; postman:postman (344 entries, versions into "
                "the 10.x series) is the tag actively used for this era, not the legacy "
                "getpostman:postman (53 entries, capped around 4.9.x)."),
    "Symantec Endpoint Protection": ("Version 14.3.10148 is a post-Broadcom-acquisition build; "
                                       "broadcom:symantec_endpoint_protection (11 entries, 14.3.x "
                                       "range matching this exact build) is correct, not the "
                                       "legacy symantec:endpoint_protection (224 entries, capped "
                                       "around 12.x)."),
    "PDF-XChange Editor": ("Version 10.2.1 is a modern build; pdf-xchange:pdf-xchange_editor "
                            "(97 entries, including 10.3.0.386) covers this era, while "
                            "tracker-software:pdf-xchange_editor (71 entries, capped around "
                            "6.0.x in the sampled range) is the older tag."),
}

for name, version, vendor, usage, cpe_vendor, cpe_product, query in CPE_DESKTOP:
    if name in CPE_VERSION_ERA_CORRECTIONS:
        source = cpe_source(query, CPE_VERSION_ERA_CORRECTIONS[name])
    else:
        source = cpe_source(query)
    add(name, version, vendor, usage, "IDENTIFIED_CPE", cpe_vendor=cpe_vendor,
        cpe_product=cpe_product, source=source)

# ---------------------------------------------------------------------------
# SECTION 4 -- UNIDENTIFIED control rows: 15 fictional products (never existed) + 15 real
# products confirmed absent from both the NVD CPE dictionary and (by category) all 10
# supported package registries. Every row independently re-verified via live NVD CPE
# keyword search 2026-08-29 (see test-data/golden300_cpe_results.tsv); this is NOT the
# app's own output written back as ground truth (test-design-policy.md P1).
# ---------------------------------------------------------------------------

FICTIONAL = [
    ("NebulaSync Workstation Manager", "3.2.1", "Fictively Corp", "used to keep employee workstation configs in sync (fictional product invented for this test)"),
    ("QuantumLeap Ledger Suite", "2.0.4", "Ferrovax Systems", "used as an accounting ledger application (fictional product invented for this test)"),
    ("Chronoscribe Desktop", "1.4.0", "Inkwell Dynamics", "used as a note-taking desktop app (fictional product invented for this test)"),
    ("Vaporlight IDE", "0.9.3", "Glasswing Software", "used as a code editor (fictional product invented for this test)"),
    ("Driftwood Analytics Console", "4.1.0", "Tidebound Inc", "used as a BI dashboard tool (fictional product invented for this test)"),
    ("Emberfall Endpoint Guard", "2.2.0", "Ashcroft Security", "used as endpoint security software (fictional product invented for this test)"),
    ("Palisade VPN Client", "5.0.1", "Bastionworks", "used as a VPN client on employee laptops (fictional product invented for this test)"),
    ("Lumenpost Mail Client", "3.3.3", "Northlyte", "used as a desktop email client (fictional product invented for this test)"),
    ("Cinderloop Automation Studio", "1.1.1", "Foundry Nine", "used as an RPA/automation authoring tool (fictional product invented for this test)"),
    ("Wraithline Packet Inspector", "0.7.2", "Hollowline Labs", "used by the network team as a packet analysis tool (fictional product invented for this test)"),
    ("Fernglow Design Suite", "6.0.0", "Mossgate Creative", "used by the design team for graphic design (fictional product invented for this test)"),
    ("Trellisware Config Manager", "2.5.0", "Ironbark Systems", "used to manage device configuration profiles (fictional product invented for this test)"),
    ("Quietstorm Backup Agent", "3.0.0", "Stillwater Tech", "used as a workstation backup agent (fictional product invented for this test)"),
    ("Bramblecore Compiler", "1.0.0", "Thornfield Software", "used as a build-toolchain compiler (fictional product invented for this test)"),
    ("Glasspine Terminal", "4.4.0", "Cobblewright", "used as a terminal emulator (fictional product invented for this test)"),
]

assert len(FICTIONAL) == 15, f"expected 15 fictional rows, got {len(FICTIONAL)}"

# Corrected 2026-08-29 (senior-reviewer re-review item 3): these 15 rows were actually
# re-verified 2026-08-29 with the item-1-fixed tool (test-data/verify_nvd_cpe_candidates.py,
# RESULTS_PER_PAGE=200, full startIndex pagination) per "Verification coverage" item 4 in
# the design note -- see test-data/golden300_cpe_results.tsv for the resultsPerPage=200
# re-run entries. The recorded source previously still cited the original resultsPerPage=15
# query, understating what was actually executed.
for name, version, vendor, usage in FICTIONAL:
    add(name, version, vendor, usage, "UNIDENTIFIED",
        source=cpe_source(name, "0 results -- fictional product invented for this dataset, confirmed no coincidental NVD CPE match",
                           results_per_page=200))

REAL_ABSENT = [
    ("Slack", "4.39.95", "Slack Technologies", "used for team chat and channel-based collaboration", "slack desktop"),
    ("OBS Studio", "30.2.3", "OBS Project", "used by the marketing team to record and stream product demos", "OBS Studio"),
    ("WinDirStat", "2.2.2", "WinDirStat Team", "used by IT support to visualize disk space usage on workstations", "WinDirStat"),
    ("ExamDiff Pro", "13.0.1.9", "PrestoSoft", "used by developers to visually diff two files or folders", "ExamDiff Pro"),
    ("Bulk Rename Utility", "3.7.0.0", "TGRMN Software", "used by IT support to batch-rename large sets of files", "Bulk Rename Utility"),
    ("WizTree", "4.19", "Antibody Software", "used by IT support to quickly find what's consuming disk space", "WizTree"),
    ("Directory Opus", "13.5", "GPSoftware", "used by power users as a dual-pane file manager", "Directory Opus"),
    ("ShareX", "15.0.0", "ShareX Team", "used to capture and annotate screenshots", "ShareX"),
    ("ClipboardFusion", "5.5", "Binary Fortress Software", "used to manage and sync clipboard history across workstations", "ClipboardFusion"),
    ("Q-Dir", "11.68", "SoftwareOK", "used by power users as a quad-pane file manager", "Q-Dir"),
    ("XYplorer", "24.90.0100", "Donald Lessau", "used by power users as an alternative Windows file manager", "XYplorer"),
    ("Ditto", "3.24.234.0", "Ditto Project", "used as a clipboard history manager on workstations", "Ditto clipboard manager"),
    ("Process Hacker", "2.39", "wj32", "used by IT support to inspect and troubleshoot running processes", "Process Hacker"),
]

assert len(REAL_ABSENT) == 13, f"expected 13 real-absent rows, got {len(REAL_ABSENT)}"

# Corrected 2026-08-29 (senior-reviewer review item 6): the app actually supports 11
# registries, not 10 -- ChocolateyRegistryClient.java is an 11th, added to cover
# desktop-installer software the other 10 (all language/library package managers) never had
# any chance of identifying. Several of these REAL_ABSENT rows genuinely ARE listed in
# Chocolatey's community catalog (job 168 confirmed live hits for OBS Studio, WinDirStat,
# WizTree, ShareX, ClipboardFusion, XYplorer, Slack) -- the original "not distributed via any
# of the 10 supported registries" claim was simply wrong for those rows, not just off by one
# in the registry count. The correct claim, and the reason expected_outcome stays UNIDENTIFIED
# regardless: Chocolatey carries no CPE mapping and is not one of the 10 OSV-native
# ecosystems this app fetches vulnerability data for (OsvSyncService.java), so a
# Chocolatey-only match is not tied to any vulnerability source and provides no path to the
# actual purpose of identification -- functionally indistinguishable from UNIDENTIFIED for
# this app's goal, even though the catalog entry itself exists. See
# test-data/golden-300.design.md "Chocolatey and the UNIDENTIFIED control bucket" for the
# full reasoning and the resulting false-positive recount.
REAL_ABSENT_NOTE = ("0 relevant results in the NVD CPE dictionary; not distributed via any of "
                     "the 10 OSV-backed registries this app fetches vulnerability data for. "
                     "May or may not be listed in Chocolatey (the app's 11th, non-OSV-backed "
                     "registry) -- irrelevant to this row's expected_outcome either way, since "
                     "a Chocolatey-only match carries no CPE/OSV vulnerability-data mapping and "
                     "is not scored as a correct identification here (see design note).")

# Slack-specific addendum (2026-08-29, senior-reviewer re-review item 3): this row's recorded
# query ("slack desktop") is narrower than ideal and, unlike Everything/Ditto/Android
# Studio/OWASP ZAP elsewhere in this file, the note text didn't mention any broader query --
# design.md's "ground_truth_source recording rule" claim that every other row already
# satisfies the broad-query-citation rule was wrong for this row specifically. Senior-reviewer
# independently re-checked both the narrow cpeMatchString and a broad keywordSearch=slack and
# confirmed the ground truth itself (UNIDENTIFIED) is still correct -- this only tightens the
# recorded evidence, it does not change expected_outcome.
SLACK_EXTRA_NOTE = (
    "Additional senior-reviewer-independent check (2026-08-29, re-review item 3): "
    "cpeMatchString=cpe:2.3:a:slack:slack returns totalResults=0; the broader "
    "keywordSearch=slack (no other qualifier) also has no desktop-Slack hit -- only "
    "jenkins:slack, atlassian:jira_server_for_slack, slack-chat_project:slack-chat, "
    "slackware:slackware, slack:nebula, and slack:wp_slacksync exist, none of which is the "
    "Slack desktop chat app this row describes. Ground truth (UNIDENTIFIED) itself was "
    "already correct; this only corrects the precision of the recorded evidence.")

# Re-verified 2026-08-29 with the item-1-fixed tool (RESULTS_PER_PAGE=200, full startIndex
# pagination) for all 13 rows below -- see test-data/golden300_cpe_results.tsv's
# resultsPerPage=200 re-run entries (senior-reviewer re-review item 3).
for name, version, vendor, usage, query in REAL_ABSENT:
    note = REAL_ABSENT_NOTE + " " + SLACK_EXTRA_NOTE if name == "Slack" else REAL_ABSENT_NOTE
    add(name, version, vendor, usage, "UNIDENTIFIED",
        source=cpe_source(query, note, results_per_page=200))

# ---------------------------------------------------------------------------
# SECTION 5 -- Blender and Rufus, corrected (2026-08-29, senior-reviewer review item 1-3):
# both were originally placed in REAL_ABSENT above, on the basis of a keyword search that
# came back "0 relevant results". That search used an over-narrowed query (adding the
# vendor name -- "blender foundation", "Rufus Pete Batard") AND the verification tool's
# original resultsPerPage=15 + "stop after 8 distinct vendor:product pairs" cap (see
# test-data/verify_nvd_cpe_candidates.py's docstring) discarded the real entry before it was
# ever reached even for a correctly-broad query. Re-run with the fixed tool (full pagination,
# no early-exit cap) against the bare product name:
#   - "blender": totalResults=232, includes cpe:2.3:a:blender:blender (159 dictionary entries
#     per direct product-name count; confirmed present, e.g. 2.78c in the sampled page).
#   - "rufus": totalResults=154, includes cpe:2.3:a:akeo:rufus (91 dictionary entries per
#     direct product-name count; confirmed present, e.g. 1.0.3 in the sampled page) -- a
#     second candidate, rufus_project:rufus, also exists but job 168's own match
#     (cpe:2.3:a:akeo:rufus:4.5) is the one independently confirmed present in the
#     dictionary, so it is adopted as ground truth rather than left ambiguous.
# Both rows are IDENTIFIED_CPE, not UNIDENTIFIED -- job 168's original output
# (cpe:2.3:a:blender:blender:4.2.1, cpe:2.3:a:akeo:rufus:4.5) was correct all along; this
# dataset's ground truth was wrong, not the app. See test-data/golden-300.design.md
# "Ground-truth correction: Blender and Rufus" for the full narrative and the
# ground_truth_source recording-rule fix (item 2) that this correction is also an example of
# -- the source below cites the broad query that actually produced the answer, not the
# narrow follow-up query that returned zero.
# ---------------------------------------------------------------------------

add("Blender", "4.2.1", "Blender Foundation",
    "used by the design team for 3D modeling and rendering",
    "IDENTIFIED_CPE", cpe_vendor="blender", cpe_product="blender",
    source=cpe_source("blender", "totalResults=232, cpe:2.3:a:blender:blender:... confirmed "
                       "present (159 dictionary entries); the original ground truth queried the "
                       "over-narrow \"blender foundation\" (0 hits) and, even for a correctly "
                       "broad query, the verification tool's original resultsPerPage=15 + 8-pair "
                       "cap would have discarded this entry behind unrelated \"tweet-blender\" "
                       "WordPress-plugin CPEs -- fixed in both the query and the tool, see "
                       "test-data/verify_nvd_cpe_candidates.py.", results_per_page=200))

add("Rufus", "4.5", "Pete Batard",
    "used by IT support to create bootable USB installer drives",
    "IDENTIFIED_CPE", cpe_vendor="akeo", cpe_product="rufus",
    source=cpe_source("rufus", "totalResults=154, cpe:2.3:a:akeo:rufus:... confirmed present (91 "
                       "dictionary entries); the original ground truth queried the over-narrow "
                       "\"Rufus Pete Batard\" (0 hits) and, even for a correctly broad query, the "
                       "verification tool's original resultsPerPage=15 + 8-pair cap risked missing "
                       "this entry -- fixed in both the query and the tool, see "
                       "test-data/verify_nvd_cpe_candidates.py.", results_per_page=200))

# ---------------------------------------------------------------------------
assert len(rows) == 300, f"expected 300 total rows, got {len(rows)}"

with open("test-data/golden-300.csv", "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["product_name", "version", "vendor", "usage_text", "install_url",
                      "expected_outcome", "expected_ecosystem", "expected_package_name",
                      "expected_cpe_vendor", "expected_cpe_product", "ground_truth_source"])
    writer.writerows(rows)

print(f"Wrote {len(rows)} rows to test-data/golden-300.csv")
