#!/usr/bin/env python3
"""Generates test-data/real-1000-additional-600.csv: ~600 additional rows for the 1.0-gate
1,000-item clean throughput measurement (see docs/spec/infra-rollout-plan.md #207 /
docs/spec/nfr-status-2026-08.md). Meant to be combined with the existing
test-data/real-400.csv (400 rows) to reach ~1,000 total.

Unlike real-400.csv (hand-curated, versions chosen to be plausible for the 2022-2023 era,
NOT fetched live per test-data/real-400.design.md), this generator queries the public
package-registry APIs live (stdlib urllib only, no third-party deps) for the 10 ecosystems
below, so registry rows carry genuinely current (at generation time) latest versions.
Desktop/CLI software (no registry to query) and the small UNIDENTIFIED-control block are
hand-curated, same methodology as real-400.

No correctness/identification labels are required -- this file is throughput-measurement
input only. The one invariant enforced here is: no (product_name, version) pair duplicates
a row already present in real-400.csv.

Composition (target 600 rows):
  - Registry (live-fetched from public APIs): 400 rows, 40 per ecosystem x 10 ecosystems.
    ~15 of those are deliberate "generic name collision" pairs (same literal package name,
    two different ecosystems, two unrelated real projects) -- these count toward their
    ecosystem's 40-row quota, they are not additional rows.
  - Desktop/CLI software identified via CPE only (no package registry): 190 rows,
    hand-curated, real products not already present in real-400.csv's non-registry segment.
  - UNIDENTIFIED negative controls (fictional products): 10 rows, hand-written.

Rate limits (self-enforced, per task instructions -- this traffic does NOT go through the
app's own ExternalRegistryRateLimiter):
  - crates.io: max 1 req/sec
  - Maven Central (search.maven.org): conservative spacing (has blocked bursts before)
  - all others: 300-500ms between requests
"""
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HEADERS = {
    "User-Agent": "research-vulncheck-testdata-generator/1.0 (internal test-data generation; "
    "single one-off run, low volume, rate-limited)"
}

MIN_INTERVAL = {
    "npm": 0.35,
    "pypi": 0.35,
    "crates": 1.05,
    "maven": 1.6,
    "go": 0.4,
    "nuget": 0.4,
    "rubygems": 0.4,
    "hex": 0.4,
    "packagist": 0.4,
    "pubdev": 0.4,
}
_LAST_CALL = {}


def throttle(eco):
    last = _LAST_CALL.get(eco, 0.0)
    wait = MIN_INTERVAL[eco] - (time.time() - last)
    if wait > 0:
        time.sleep(wait)
    _LAST_CALL[eco] = time.time()


def fetch_json(url, timeout=15):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, ValueError, OSError):
        return None


# ---------------------------------------------------------------------------
# Per-ecosystem "latest version" fetchers
# ---------------------------------------------------------------------------

def npm_latest(name):
    throttle("npm")
    safe = urllib.parse.quote(name, safe="@/")
    data = fetch_json(f"https://registry.npmjs.org/{safe}/latest")
    return data.get("version") if data else None


def pypi_latest(name):
    throttle("pypi")
    data = fetch_json(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json")
    if not data:
        return None
    return data.get("info", {}).get("version")


def crates_latest(name):
    throttle("crates")
    data = fetch_json(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}")
    if not data:
        return None
    c = data.get("crate", {})
    return c.get("max_stable_version") or c.get("newest_version")


def maven_latest(group, artifact):
    throttle("maven")
    # NOTE: the default (non-gav) solrsearch endpoint's "latestVersion" field is a plain
    # lexicographic max over version strings, which misorders legacy CalVer-style
    # releases (e.g. "20030203.000550") above current SemVer ones (e.g. "2.16.1") for a
    # few older Apache Commons artifacts. Query the gav core instead and sort by
    # timestamp desc, which reflects actual publish recency.
    q = f'g:"{group}" AND a:"{artifact}"'
    url = (
        "https://search.maven.org/solrsearch/select?q="
        + urllib.parse.quote(q)
        + "&core=gav&rows=1&sort="
        + urllib.parse.quote("timestamp desc")
        + "&wt=json"
    )
    data = fetch_json(url)
    if not data:
        return None
    docs = data.get("response", {}).get("docs", [])
    return docs[0].get("v") if docs else None


def _go_encode(path):
    return "".join("!" + c.lower() if c.isupper() else c for c in path)


def go_latest(module):
    throttle("go")
    enc = _go_encode(module)
    data = fetch_json(f"https://proxy.golang.org/{enc}/@latest")
    return data.get("Version") if data else None


def nuget_latest(pkg_id):
    throttle("nuget")
    data = fetch_json(f"https://api.nuget.org/v3-flatcontainer/{pkg_id.lower()}/index.json")
    if not data:
        return None
    versions = data.get("versions", [])
    stable = [v for v in versions if "-" not in v]
    if stable:
        return stable[-1]
    return versions[-1] if versions else None


def rubygems_latest(name):
    throttle("rubygems")
    data = fetch_json(f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(name)}/latest.json")
    if not data:
        return None
    v = data.get("version")
    return v if v and v != "unknown" else None


def hex_latest(name):
    throttle("hex")
    data = fetch_json(f"https://hex.pm/api/packages/{urllib.parse.quote(name)}")
    if not data:
        return None
    return data.get("latest_stable_version") or data.get("latest_version")


def packagist_latest(vendor_pkg):
    throttle("packagist")
    data = fetch_json(f"https://repo.packagist.org/p2/{vendor_pkg}.json")
    if not data:
        return None
    pkgs = data.get("packages", {}).get(vendor_pkg, [])
    for entry in pkgs:
        v = entry.get("version", "")
        if v and not v.startswith("dev-") and "dev" not in v:
            return v.lstrip("v")
    return pkgs[0].get("version") if pkgs else None


def pubdev_latest(name):
    throttle("pubdev")
    data = fetch_json(f"https://pub.dev/api/packages/{urllib.parse.quote(name)}")
    if not data:
        return None
    return data.get("latest", {}).get("version")


ECOSYSTEM_USAGE = {
    "npm": "used as an npm package dependency in a Node.js/JavaScript project's build pipeline",
    "pypi": "used as a PyPI package dependency in a Python application",
    "crates": "used as a Rust crate dependency pulled in via Cargo",
    "maven": "used as a Java/Maven dependency pulled in via the build",
    "go": "used as a Go module dependency imported in the codebase",
    "nuget": "used as a NuGet package dependency in a .NET application",
    "rubygems": "used as a Ruby gem dependency in a Rails/Ruby application",
    "hex": "used as an Elixir Hex package dependency in a Phoenix/Elixir application",
    "packagist": "used as a Composer/PHP package dependency in the application",
    "pubdev": "used as a Dart/Flutter pub.dev package dependency in a mobile app",
}

QUOTA = 40

# ---------------------------------------------------------------------------
# Candidate pools (deliberately larger than QUOTA to absorb 404s/renames).
# All chosen to NOT overlap with the package names already used in
# test-data/real-400.csv's registry segment, for diversity.
# ---------------------------------------------------------------------------

NPM_CANDIDATES = [
    "next", "nuxt", "svelte", "vite", "rollup", "@babel/core", "prettier", "husky",
    "nodemon", "dotenv", "cors", "body-parser", "mongoose", "sequelize", "prisma",
    "graphql", "apollo-server", "socket.io", "ws", "ioredis", "bcrypt", "jsonwebtoken",
    "passport", "multer", "sharp", "puppeteer", "playwright", "cypress", "mocha", "chai",
    "sinon", "tailwindcss", "postcss", "autoprefixer", "sass", "less", "styled-components",
    "immer", "redux", "zustand", "rxjs", "dayjs", "date-fns", "nanoid", "yargs",
    "inquirer", "ora", "chokidar", "minimatch", "yup", "zod", "joi", "node-fetch",
    "form-data", "qs", "cookie-parser", "helmet", "morgan", "winston", "pino", "knex",
    "pg", "mysql2", "sqlite3", "firebase", "stripe", "openai", "@octokit/rest",
]

PYPI_CANDIDATES = [
    "fastapi", "uvicorn", "starlette", "pydantic", "httpx", "aiohttp", "boto3",
    "botocore", "paramiko", "selenium", "scrapy", "matplotlib", "seaborn", "plotly",
    "scikit-learn", "tensorflow", "torch", "transformers", "spacy", "nltk", "gensim",
    "opencv-python", "pytesseract", "pymongo", "redis", "psycopg2-binary", "pymysql",
    "alembic", "gunicorn", "tornado", "twisted", "tqdm", "rich", "typer", "attrs",
    "marshmallow", "jsonschema", "lxml", "xmltodict", "pyjwt", "passlib", "cffi", "six",
    "python-dateutil", "pytz", "arrow", "pendulum", "loguru", "structlog", "sentry-sdk",
    "gitpython", "docker", "kubernetes", "ansible", "fabric", "invoke", "poetry",
    "virtualenv", "wheel", "cython", "numba",
]

CRATES_CANDIDATES = [
    "async-std", "tonic", "prost", "axum", "warp", "actix", "diesel", "sqlx", "sea-orm",
    "rusqlite", "postgres", "mysql", "lazy_static", "once_cell", "itertools", "chrono",
    "num", "num-traits", "getrandom", "byteorder", "bitflags", "crossbeam", "parking_lot",
    "mio", "tower", "tower-http", "native-tls", "rustls", "ring", "base64", "hex",
    "sha2", "digest", "aes", "structopt", "env_logger", "tracing", "tracing-subscriber",
    "slog", "tempfile", "walkdir", "notify", "indicatif", "console", "colored",
    "termcolor", "ansi_term", "toml", "serde_yaml", "quick-xml",
]

MAVEN_CANDIDATES = [
    ("org.apache.commons", "commons-collections4"),
    ("org.apache.commons", "commons-text"),
    ("com.google.protobuf", "protobuf-java"),
    ("com.google.inject", "guice"),
    ("org.mockito", "mockito-core"),
    ("org.assertj", "assertj-core"),
    ("io.projectreactor", "reactor-core"),
    ("org.springframework.boot", "spring-boot"),
    ("org.springframework", "spring-webmvc"),
    ("org.springframework.security", "spring-security-core"),
    ("com.h2database", "h2"),
    ("mysql", "mysql-connector-java"),
    ("org.apache.logging.log4j", "log4j-core"),
    ("org.apache.logging.log4j", "log4j-api"),
    ("ch.qos.logback", "logback-core"),
    ("com.google.code.findbugs", "jsr305"),
    ("org.apache.poi", "poi"),
    ("org.apache.poi", "poi-ooxml"),
    ("com.opencsv", "opencsv"),
    ("org.yaml", "snakeyaml"),
    ("io.jsonwebtoken", "jjwt-api"),
    ("org.apache.commons", "commons-compress"),
    ("commons-io", "commons-io"),
    ("commons-codec", "commons-codec"),
    ("jakarta.servlet", "jakarta.servlet-api"),
    ("org.hibernate.validator", "hibernate-validator"),
    ("com.amazonaws", "aws-java-sdk-core"),
    ("software.amazon.awssdk", "s3"),
    ("redis.clients", "jedis"),
    ("org.apache.zookeeper", "zookeeper"),
    ("io.micrometer", "micrometer-core"),
    ("org.junit.jupiter", "junit-jupiter"),
    ("org.testng", "testng"),
    ("org.apache.avro", "avro"),
    ("com.squareup.retrofit2", "retrofit"),
    ("com.squareup.okio", "okio"),
    ("io.vertx", "vertx-core"),
    ("org.apache.camel", "camel-core"),
    ("org.jetbrains.kotlin", "kotlin-stdlib"),
    ("org.scala-lang", "scala-library"),
]

GO_CANDIDATES = [
    "github.com/gorilla/websocket", "github.com/gorilla/sessions",
    "github.com/go-chi/chi", "github.com/gofiber/fiber/v2",
    "github.com/valyala/fasthttp", "gorm.io/gorm", "gorm.io/driver/postgres",
    "github.com/lib/pq", "github.com/jmoiron/sqlx", "google.golang.org/grpc",
    "google.golang.org/protobuf", "github.com/spf13/pflag", "github.com/spf13/afero",
    "github.com/urfave/cli/v2", "github.com/joho/godotenv", "github.com/BurntSushi/toml",
    "gopkg.in/yaml.v2", "gopkg.in/yaml.v3", "github.com/mitchellh/mapstructure",
    "github.com/hashicorp/go-multierror", "github.com/hashicorp/consul/api",
    "github.com/hashicorp/vault/api", "github.com/streadway/amqp",
    "github.com/rabbitmq/amqp091-go", "github.com/nats-io/nats.go",
    "github.com/patrickmn/go-cache", "github.com/robfig/cron/v3", "github.com/pkg/errors",
    "go.mongodb.org/mongo-driver", "github.com/olivere/elastic/v7",
    "github.com/segmentio/kafka-go", "github.com/casbin/casbin/v2", "golang.org/x/net",
    "golang.org/x/sync", "golang.org/x/sys", "golang.org/x/text", "golang.org/x/tools",
    "github.com/fsnotify/fsnotify", "github.com/go-chi/chi/v5",
    "github.com/go-playground/validator/v10", "github.com/miekg/dns",
    "github.com/klauspost/compress", "github.com/spf13/cast", "golang.org/x/mod",
    "golang.org/x/oauth2", "github.com/golang/mock", "github.com/stretchr/objx",
]

NUGET_CANDIDATES = [
    "xunit", "xunit.runner.visualstudio", "coverlet.collector",
    "Microsoft.EntityFrameworkCore", "Microsoft.EntityFrameworkCore.SqlServer",
    "Microsoft.EntityFrameworkCore.Sqlite", "Npgsql", "MySql.Data", "AutoFixture",
    "Bogus", "FluentAssertions", "Shouldly", "Microsoft.AspNetCore.Mvc.Testing",
    "Microsoft.Extensions.Logging", "Microsoft.Extensions.Configuration",
    "Microsoft.Extensions.Http", "Microsoft.Extensions.Caching.Memory",
    "IdentityServer4", "Microsoft.AspNetCore.Authentication.JwtBearer",
    "RabbitMQ.Client", "MassTransit", "Quartz", "NLog", "log4net",
    "CommandLineParser", "System.Text.Json", "Grpc.Net.Client", "Grpc.AspNetCore",
    "SharpZipLib", "SixLabors.ImageSharp", "CsvHelper", "EPPlus", "ClosedXML",
    "itext7", "HtmlAgilityPack", "Selenium.WebDriver", "Refit", "Autofac",
    "Castle.Core", "StyleCop.Analyzers",
]

RUBYGEMS_CANDIDATES = [
    "rack-cors", "actionpack", "activerecord", "activesupport", "activejob",
    "actionmailer", "actioncable", "importmap-rails", "turbo-rails", "stimulus-rails",
    "kaminari", "will_paginate", "carrierwave", "shrine", "aws-sdk-s3", "aws-sdk-core",
    "faker", "factory_bot", "simplecov", "guard", "listen", "standard", "brakeman",
    "dotenv", "dotenv-rails", "resque", "delayed_job", "whenever", "sucker_punch",
    "mail", "premailer", "haml", "slim", "sassc", "terser", "bootsnap", "spring",
    "foreman", "pundit", "cancancan", "omniauth", "omniauth-oauth2", "jwt", "bcrypt",
    "graphql", "grape", "jbuilder", "oj", "multi_json", "addressable", "mechanize",
    "money",
]

PACKAGIST_CANDIDATES = [
    "symfony/framework-bundle", "symfony/http-kernel", "symfony/routing",
    "symfony/yaml", "symfony/dependency-injection", "symfony/event-dispatcher",
    "symfony/validator", "symfony/security-bundle", "symfony/serializer",
    "doctrine/dbal", "doctrine/migrations", "doctrine/annotations",
    "laravel/sanctum", "laravel/passport", "laravel/tinker", "laravel/horizon",
    "laravel/telescope", "spatie/laravel-permission", "spatie/laravel-backup",
    "guzzlehttp/psr7", "phpstan/phpstan", "squizlabs/php_codesniffer",
    "friendsofphp/php-cs-fixer", "phpseclib/phpseclib", "league/csv",
    "league/commonmark", "league/oauth2-server", "filp/whoops", "predis/predis",
    "php-di/php-di", "cakephp/cakephp", "slim/slim", "erusev/parsedown",
    "respect/validation", "egulias/email-validator", "psr/log", "psr/http-message",
    "nette/utils", "symfony/mailer", "guzzlehttp/promises", "symfony/cache",
    "symfony/translation", "ramsey/collection", "brick/math", "nikic/php-parser",
    "myclabs/deep-copy", "sebastian/comparator",
]

HEX_CANDIDATES = [
    "phoenix_ecto", "phoenix_html", "phoenix_pubsub", "ecto_sql", "postgrex", "myxql",
    "redix", "hackney", "httpoison", "poison", "jose", "guardian", "comeonin",
    "argon2_elixir", "timex", "nimble_csv", "nimble_options", "castore", "mint",
    "ranch", "gen_stage", "flow", "ex_machina", "stream_data", "mox", "dialyxir",
    "excoveralls", "sobelow", "bandit", "req", "tzdata", "decimal", "cors_plug",
    "remote_ip", "plug_cowboy", "websock_adapter", "phoenix_live_dashboard",
    "phoenix_live_reload", "floki", "earmark", "makeup", "nimble_parsec",
    "typed_struct", "money",
]

PUBDEV_CANDIDATES = [
    "flutter_riverpod", "bloc", "freezed", "freezed_annotation", "json_serializable",
    "build_runner", "hive", "hive_flutter", "get_it", "injectable", "go_router",
    "auto_route", "google_fonts", "flutter_svg", "lottie", "shimmer",
    "carousel_slider", "flutter_slidable", "pull_to_refresh", "image_picker",
    "image_cropper", "permission_handler", "geolocator", "geocoding",
    "google_maps_flutter", "firebase_core", "firebase_auth", "firebase_messaging",
    "cloud_firestore", "firebase_storage", "package_info_plus", "device_info_plus",
    "path_provider", "drift", "isar", "retrofit", "chopper", "graphql_flutter",
    "socket_io_client", "web_socket_channel", "uuid", "collection", "meta",
    "vector_math", "synchronized", "timeago", "flutter_local_notifications",
    "workmanager",
]

FETCHERS = {
    "npm": lambda n: npm_latest(n),
    "pypi": lambda n: pypi_latest(n),
    "crates": lambda n: crates_latest(n),
    "go": lambda n: go_latest(n),
    "nuget": lambda n: nuget_latest(n),
    "rubygems": lambda n: rubygems_latest(n),
    "hex": lambda n: hex_latest(n),
    "packagist": lambda n: packagist_latest(n),
    "pubdev": lambda n: pubdev_latest(n),
}

SIMPLE_CANDIDATES = {
    "npm": NPM_CANDIDATES,
    "pypi": PYPI_CANDIDATES,
    "crates": CRATES_CANDIDATES,
    "go": GO_CANDIDATES,
    "nuget": NUGET_CANDIDATES,
    "rubygems": RUBYGEMS_CANDIDATES,
    "hex": HEX_CANDIDATES,
    "packagist": PACKAGIST_CANDIDATES,
    "pubdev": PUBDEV_CANDIDATES,
}

# ---------------------------------------------------------------------------
# Generic name-collision candidates: identical literal package name, two
# different ecosystems, two unrelated real projects. Verified live (dropped
# silently if either side 404s -- see below).
# ---------------------------------------------------------------------------
COLLISION_CANDIDATES = [
    ("glob", "npm", "crates"),
    ("tar", "npm", "crates"),
    ("csv", "npm", "crates"),
    ("semver", "npm", "crates"),
    ("toml", "npm", "crates"),
    ("events", "npm", "crates"),
    ("config", "npm", "crates"),
    ("log", "npm", "crates"),
    ("cache", "npm", "crates"),
    ("time", "npm", "crates"),
    ("hash", "npm", "crates"),
    ("uuid", "pypi", "crates"),
    ("money", "hex", "rubygems"),
    ("faker", "npm", "rubygems"),
    ("mail", "rubygems", "hex"),
]

rows = []  # (product_name, version, vendor, usage_text, install_url)
eco_counts = {eco: 0 for eco in ECOSYSTEM_USAGE}
used_names = {eco: set() for eco in ECOSYSTEM_USAGE}
log_lines = []


def add_row(name, version, vendor, usage_text):
    rows.append((name, version, vendor, usage_text, ""))


def display_name(eco, name):
    return name


# --- collisions first ---
for name, eco_a, eco_b in COLLISION_CANDIDATES:
    if eco_counts[eco_a] >= QUOTA or eco_counts[eco_b] >= QUOTA:
        continue
    ver_a = FETCHERS[eco_a](name)
    ver_b = FETCHERS[eco_b](name)
    if ver_a and ver_b:
        add_row(name, ver_a, "", ECOSYSTEM_USAGE[eco_a] + " (generic-name collision probe)")
        add_row(name, ver_b, "", ECOSYSTEM_USAGE[eco_b] + " (generic-name collision probe)")
        used_names[eco_a].add(name)
        used_names[eco_b].add(name)
        eco_counts[eco_a] += 1
        eco_counts[eco_b] += 1
        log_lines.append(f"COLLISION OK: {name} -- {eco_a}={ver_a} {eco_b}={ver_b}")
    else:
        log_lines.append(f"COLLISION SKIP: {name} -- {eco_a}={ver_a} {eco_b}={ver_b}")

# --- maven (handled separately, group:artifact display name) ---
mi = 0
while eco_counts["maven"] < QUOTA and mi < len(MAVEN_CANDIDATES):
    group, artifact = MAVEN_CANDIDATES[mi]
    mi += 1
    disp = f"{group}:{artifact}"
    if disp in used_names["maven"]:
        continue
    ver = maven_latest(group, artifact)
    if ver:
        add_row(disp, ver, "", ECOSYSTEM_USAGE["maven"])
        used_names["maven"].add(disp)
        eco_counts["maven"] += 1
        log_lines.append(f"maven OK: {disp} -> {ver}")
    else:
        log_lines.append(f"maven SKIP (not found): {disp}")

# --- remaining simple ecosystems ---
for eco, candidates in SIMPLE_CANDIDATES.items():
    ci = 0
    while eco_counts[eco] < QUOTA and ci < len(candidates):
        name = candidates[ci]
        ci += 1
        if name in used_names[eco]:
            continue
        ver = FETCHERS[eco](name)
        if ver:
            add_row(name, ver, "", ECOSYSTEM_USAGE[eco])
            used_names[eco].add(name)
            eco_counts[eco] += 1
            log_lines.append(f"{eco} OK: {name} -> {ver}")
        else:
            log_lines.append(f"{eco} SKIP (not found): {name}")

registry_row_count = len(rows)

# ---------------------------------------------------------------------------
# Desktop / CLI software identified via CPE only (no package registry).
# Hand-curated, real products with real (recent) release versions, chosen to
# NOT duplicate names already present in real-400.csv's non-registry segment.
# vendor is always populated (matches real-400.csv convention for this
# segment).
# ---------------------------------------------------------------------------
DESKTOP_CATEGORY_USAGE = {
    "browser": "used as an alternative web browser on some employee workstations",
    "password_manager": "used to store and manage passwords in an encrypted vault",
    "vpn_client": "used to connect to the corporate or a commercial VPN for remote access",
    "backup_sync": "used to sync or back up files to cloud/remote storage",
    "endpoint_security": "used as endpoint antivirus/EDR software on workstations or servers",
    "virtualization": "used to run virtual machines for local testing",
    "db_client": "used to connect to and manage databases",
    "ide": "used as a code editor/IDE by developers",
    "devops_cli": "used as a DevOps/infrastructure-as-code command-line tool",
    "vcs_client": "used as a version control client by the engineering team",
    "network_sec_scan": "used by the security team to scan for and assess vulnerabilities",
    "creative_media": "used for video/photo editing and creative production",
    "collab_tool": "used for team collaboration, task tracking, or documentation",
    "note_taking": "used for internal note-taking and knowledge management",
    "diagramming": "used to create diagrams and flowcharts",
    "api_testing": "used to build and test HTTP API requests during development",
    "container_k8s": "used to build/run containers or manage Kubernetes clusters locally",
    "monitoring_agent": "used as a monitoring/observability agent installed on servers",
    "msg_broker_tool": "used as the message broker or a GUI to inspect it",
    "firmware_network_os": "used as network device firmware/OS running infrastructure hardware",
    "business_erp": "used for internal accounting or business operations",
    "cad_3d": "used for CAD and 3D modeling",
    "terminal_emulator": "used as the command-line shell/terminal for administration and scripting",
    "package_manager_tool": "used as a system package manager to install developer tools",
    "sysinternals_util": "used to inspect and troubleshoot running processes and system activity",
    "storage_util": "used to clean up disk space or analyze storage usage",
    "office_app": "used for document creation as part of the office productivity suite",
    "email_client": "used as the desktop email client for corporate email",
    "video_meeting": "used for external and internal video meetings",
    "cloud_cli": "used as a cloud provider's command-line tool to manage resources",
    "design_prototyping": "used for UI/UX design and prototyping",
    "bi_reporting": "used for data visualization and business intelligence reporting",
    "qa_testing": "used by QA to author and run automated or load tests",
    "siem_logging": "used to collect, index, or analyze security/operational logs",
    "remote_support": "used to remotely connect to and control other machines",
    "config_mgmt": "used to manage server configuration via an automation/config-management tool",
    "pc_utility": "used as a general-purpose Windows PC maintenance/optimization utility",
    "disk_encryption": "used for full-disk or container-based encryption of sensitive data",
}

DESKTOP_PRODUCTS = [
    # (name, version, vendor, category)
    ("Opera", "106.0.4998.19", "Opera Software", "browser"),
    ("Brave", "1.61.114", "Brave Software", "browser"),
    ("Vivaldi", "6.1.3035.111", "Vivaldi Technologies", "browser"),
    ("Tor Browser", "12.5.6", "The Tor Project", "browser"),
    ("1Password", "8.10.19", "AgileBits", "password_manager"),
    ("Bitwarden", "2023.9.1", "Bitwarden Inc", "password_manager"),
    ("LastPass", "4.115.0", "LastPass", "password_manager"),
    ("Dashlane", "6.2306.1", "Dashlane Inc", "password_manager"),
    ("OpenVPN Connect", "3.4.1", "OpenVPN Inc", "vpn_client"),
    ("WireGuard", "0.5.3", "WireGuard", "vpn_client"),
    ("NordVPN", "7.16.0", "Nord Security", "vpn_client"),
    ("ExpressVPN", "12.44.0", "Express VPN International", "vpn_client"),
    ("GlobalProtect", "6.2.0", "Palo Alto Networks", "vpn_client"),
    ("Pulse Secure Client", "9.1.18", "Ivanti", "vpn_client"),
    ("FortiClient", "7.2.4", "Fortinet", "vpn_client"),
    ("Google Drive for Desktop", "79.0.3", "Google", "backup_sync"),
    ("OneDrive", "23.146.0703.0001", "Microsoft", "backup_sync"),
    ("Box Drive", "2.35.174", "Box Inc", "backup_sync"),
    ("Backblaze", "9.0.1", "Backblaze Inc", "backup_sync"),
    ("Carbonite", "6.4.1", "Carbonite Inc", "backup_sync"),
    ("Veeam Backup & Replication", "12.1", "Veeam Software", "backup_sync"),
    ("Acronis Cyber Protect", "15.0.28224", "Acronis", "backup_sync"),
    ("CrowdStrike Falcon Sensor", "7.10.0", "CrowdStrike", "endpoint_security"),
    ("SentinelOne Agent", "23.3.2.5", "SentinelOne", "endpoint_security"),
    ("Microsoft Defender for Endpoint", "4.18.2305", "Microsoft", "endpoint_security"),
    ("Symantec Endpoint Protection", "14.3.9", "Broadcom", "endpoint_security"),
    ("Trend Micro Apex One", "14.0", "Trend Micro", "endpoint_security"),
    ("Cortex XDR Agent", "8.1", "Palo Alto Networks", "endpoint_security"),
    ("Avira Antivirus", "1.1.85", "Avira", "endpoint_security"),
    ("F-Secure SAFE", "17.9", "F-Secure", "endpoint_security"),
    ("Bitdefender GravityZone", "6.6", "Bitdefender", "endpoint_security"),
    ("Cylance Protect", "3.1", "BlackBerry", "endpoint_security"),
    ("Trellix Endpoint Security", "10.7", "Trellix", "endpoint_security"),
    ("Parallels Desktop", "19.0.0", "Parallels", "virtualization"),
    ("QEMU", "8.0.2", "QEMU Project", "virtualization"),
    ("Azure Data Studio", "1.46.0", "Microsoft", "db_client"),
    ("SQL Server Management Studio", "19.1", "Microsoft", "db_client"),
    ("Navicat Premium", "16.2.6", "PremiumSoft", "db_client"),
    ("HeidiSQL", "12.4", "Ansgar Becker", "db_client"),
    ("DataGrip", "2023.1", "JetBrains", "db_client"),
    ("RedisInsight", "2.30.0", "Redis Ltd", "db_client"),
    ("CLion", "2023.1", "JetBrains", "ide"),
    ("GoLand", "2023.1", "JetBrains", "ide"),
    ("Rider", "2023.1", "JetBrains", "ide"),
    ("RubyMine", "2023.1", "JetBrains", "ide"),
    ("Neovim", "0.9.1", "Neovim Team", "ide"),
    ("Helix", "23.05", "Helix Editor Project", "ide"),
    ("Zed", "0.94.0", "Zed Industries", "ide"),
    ("GitHub Desktop", "3.2.4", "GitHub", "vcs_client"),
    ("GitHub CLI", "2.31.0", "GitHub", "devops_cli"),
    ("TeamCity", "2023.05", "JetBrains", "devops_cli"),
    ("Bamboo", "9.4.1", "Atlassian", "devops_cli"),
    ("Octopus Deploy", "2023.3.1", "Octopus Deploy", "devops_cli"),
    ("Terraform", "1.5.2", "HashiCorp", "devops_cli"),
    ("Packer", "1.9.1", "HashiCorp", "devops_cli"),
    ("Vagrant", "2.3.7", "HashiCorp", "devops_cli"),
    ("kubectl", "1.27.3", "Kubernetes", "container_k8s"),
    ("Helm", "3.12.2", "Helm", "container_k8s"),
    ("k9s", "0.27.4", "Derailed", "container_k8s"),
    ("Lens", "6.4.16", "Mirantis", "container_k8s"),
    ("Rancher Desktop", "1.9.1", "SUSE", "container_k8s"),
    ("Minikube", "1.30.1", "Kubernetes", "container_k8s"),
    ("Nessus", "10.5.2", "Tenable", "network_sec_scan"),
    ("OpenVAS", "22.4.1", "Greenbone", "network_sec_scan"),
    ("Metasploit Framework", "6.3.25", "Rapid7", "network_sec_scan"),
    ("Snort", "2.9.20", "Cisco", "network_sec_scan"),
    ("DaVinci Resolve", "18.5", "Blackmagic Design", "creative_media"),
    ("Adobe Lightroom", "6.3", "Adobe", "creative_media"),
    ("Adobe Media Encoder", "23.5.0", "Adobe", "creative_media"),
    ("Affinity Photo", "2.2.0", "Serif", "creative_media"),
    ("Affinity Designer", "2.2.0", "Serif", "creative_media"),
    ("CapCut", "2.5.0", "ByteDance", "creative_media"),
    ("Miro", "1.0", "RealtimeBoard Inc", "collab_tool"),
    ("Mural", "4.0", "Tactivos Inc", "collab_tool"),
    ("Confluence", "8.5.1", "Atlassian", "collab_tool"),
    ("Jira", "9.12.1", "Atlassian", "collab_tool"),
    ("Trello", "3.15.0", "Atlassian", "collab_tool"),
    ("Asana", "1.5.0", "Asana Inc", "collab_tool"),
    ("Monday.com Desktop", "1.2.0", "monday.com", "collab_tool"),
    ("ClickUp", "3.15.0", "ClickUp", "collab_tool"),
    ("Obsidian", "1.4.5", "Obsidian", "note_taking"),
    ("Joplin", "2.12.19", "Laurent Cozic", "note_taking"),
    ("Standard Notes", "3.181.10", "Standard Notes", "note_taking"),
    ("Microsoft OneNote", "16.0.16626", "Microsoft", "note_taking"),
    ("draw.io Desktop", "21.6.5", "JGraph", "diagramming"),
    ("yEd Graph Editor", "3.23.2", "yWorks", "diagramming"),
    ("SoapUI", "5.7.0", "SmartBear", "api_testing"),
    ("JMeter", "5.6.2", "Apache Software Foundation", "qa_testing"),
    ("k6", "0.45.1", "Grafana Labs", "qa_testing"),
    ("Bruno", "0.22.1", "Bruno Software", "api_testing"),
    ("Podman", "4.6.0", "Red Hat", "container_k8s"),
    ("Podman Desktop", "1.4.1", "Red Hat", "container_k8s"),
    ("OrbStack", "0.11.0", "OrbStack", "container_k8s"),
    ("Colima", "0.5.6", "Colima Project", "container_k8s"),
    ("Offset Explorer", "2.4", "Kafka Tool", "msg_broker_tool"),
    ("Apache Kafka", "3.4.1", "Apache Software Foundation", "msg_broker_tool"),
    ("ActiveMQ", "5.18.2", "Apache Software Foundation", "msg_broker_tool"),
    ("Datadog Agent", "7.46.0", "Datadog", "monitoring_agent"),
    ("New Relic Infrastructure Agent", "1.40.1", "New Relic", "monitoring_agent"),
    ("Elastic APM Agent", "8.8.2", "Elastic", "monitoring_agent"),
    ("Splunk Universal Forwarder", "9.1.1", "Splunk", "monitoring_agent"),
    ("Splunk Enterprise", "9.1.1", "Splunk", "siem_logging"),
    ("SAP GUI", "7.70", "SAP", "business_erp"),
    ("QuickBooks Desktop", "2023", "Intuit", "business_erp"),
    ("Sage 50", "2023.1", "Sage Group", "business_erp"),
    ("Cisco IOS XE", "17.9.4", "Cisco", "firmware_network_os"),
    ("FortiOS", "7.2.4", "Fortinet", "firmware_network_os"),
    ("PAN-OS", "11.0.2", "Palo Alto Networks", "firmware_network_os"),
    ("UniFi Network Application", "7.5.176", "Ubiquiti", "firmware_network_os"),
    ("pfSense CE", "2.7.0", "Netgate", "firmware_network_os"),
    ("SolidWorks", "2023", "Dassault Systemes", "cad_3d"),
    ("Fusion 360", "2.0.16985", "Autodesk", "cad_3d"),
    ("Autodesk Revit", "2023.1", "Autodesk", "cad_3d"),
    ("FreeCAD", "0.20.2", "FreeCAD Project", "cad_3d"),
    ("Alacritty", "0.12.2", "Alacritty", "terminal_emulator"),
    ("WezTerm", "20230712", "Wez Furlong", "terminal_emulator"),
    ("Warp", "0.2023.07", "Warp", "terminal_emulator"),
    ("Tabby", "1.0.196", "Eugene Pankov", "terminal_emulator"),
    ("Chocolatey", "2.1.0", "Chocolatey Software", "package_manager_tool"),
    ("Scoop", "0.3.1", "Scoop", "package_manager_tool"),
    ("Homebrew", "4.1.11", "Homebrew", "package_manager_tool"),
    ("Autoruns", "14.11", "Microsoft Sysinternals", "sysinternals_util"),
    ("TCPView", "4.19", "Microsoft Sysinternals", "sysinternals_util"),
    ("BgInfo", "4.28", "Microsoft Sysinternals", "sysinternals_util"),
    ("Sysmon", "15.0", "Microsoft Sysinternals", "sysinternals_util"),
    ("TreeSize Free", "4.6.2", "JAM Software", "storage_util"),
    ("SpaceSniffer", "1.3.0.2", "Uderzo", "storage_util"),
    ("Ventoy", "1.0.96", "Ventoy Project", "storage_util"),
    ("Perforce Helix Core Client (P4V)", "2023.1", "Perforce", "vcs_client"),
    ("Mercurial", "6.4.5", "Mercurial", "vcs_client"),
    ("Subversion", "1.14.2", "Apache Software Foundation", "vcs_client"),
    ("Fork", "2.30", "Fork Dev", "vcs_client"),
    ("Microsoft Outlook", "16.0.16626", "Microsoft", "office_app"),
    ("Microsoft Word", "16.0.16626", "Microsoft", "office_app"),
    ("Microsoft Excel", "16.0.16626", "Microsoft", "office_app"),
    ("Microsoft PowerPoint", "16.0.16626", "Microsoft", "office_app"),
    ("eM Client", "9.2.1", "eM Client", "email_client"),
    ("Mailbird", "3.0.7", "Mailbird", "email_client"),
    ("Webex", "43.6.0", "Cisco", "video_meeting"),
    ("RingCentral", "23.2.0", "RingCentral", "video_meeting"),
    ("GoToMeeting", "11.13.0", "LogMeIn", "video_meeting"),
    ("BlueJeans", "7.3.0", "BlueJeans Network", "video_meeting"),
    ("Skype for Business", "16.0.16626", "Microsoft", "video_meeting"),
    ("Zoom Rooms", "5.15.0", "Zoom Video Communications", "video_meeting"),
    ("Framer", "113.0", "Framer", "design_prototyping"),
    ("Zeplin", "6.5.0", "Zeplin", "design_prototyping"),
    ("Marvel App", "2.4.0", "Marvel", "design_prototyping"),
    ("InVision Studio", "1.9.0", "InVision", "design_prototyping"),
    ("Power BI Desktop", "2.118.943.0", "Microsoft", "bi_reporting"),
    ("Qlik Sense Desktop", "14.31.2", "Qlik", "bi_reporting"),
    ("Alteryx Designer", "2023.1", "Alteryx", "bi_reporting"),
    ("SAS Enterprise Guide", "8.3", "SAS Institute", "bi_reporting"),
    ("Selenium IDE", "4.0.4", "Selenium Project", "qa_testing"),
    ("TestComplete", "15.70", "SmartBear", "qa_testing"),
    ("Katalon Studio", "9.4.0", "Katalon", "qa_testing"),
    ("LoadRunner", "2023", "OpenText", "qa_testing"),
    ("LogRhythm", "7.12", "LogRhythm", "siem_logging"),
    ("IBM Security QRadar SIEM", "7.5", "IBM", "siem_logging"),
    ("Elasticsearch", "8.9.0", "Elastic", "siem_logging"),
    ("BeyondTrust Remote Support", "23.2", "BeyondTrust", "remote_support"),
    ("Zoho Assist", "6.5", "Zoho", "remote_support"),
    ("Datto RMM Agent", "1.0", "Datto (Kaseya)", "remote_support"),
    ("Macrium Reflect", "8.1.7024", "Paramount Software", "backup_sync"),
    ("Clonezilla", "3.1.2", "NCHC Free Software Labs", "backup_sync"),
    ("EaseUS Todo Backup", "15.5", "EaseUS", "backup_sync"),
    ("Wise Registry Cleaner", "11.0.2", "WiseCleaner", "pc_utility"),
    ("Advanced SystemCare", "16.4", "IObit", "pc_utility"),
    ("Glary Utilities", "5.208", "Glarysoft", "pc_utility"),
    ("Ubiquiti EdgeOS", "2.0.9", "Ubiquiti", "firmware_network_os"),
    ("MikroTik RouterOS", "7.11", "MikroTik", "firmware_network_os"),
    ("Aruba ClearPass", "6.11", "HPE Aruba", "firmware_network_os"),
    ("Epicor ERP", "10.2.700", "Epicor", "business_erp"),
    ("Odoo", "16.0", "Odoo S.A.", "business_erp"),
    ("Procreate", "5.3.6", "Savage Interactive", "creative_media"),
    ("CorelDRAW Technical Suite", "2023", "Corel", "creative_media"),
    ("HTTPie Desktop", "2023.4.1", "HTTPie", "api_testing"),
    ("Hoppscotch Desktop", "23.5.3", "Hoppscotch", "api_testing"),
    ("pCloud", "3.13.4", "pCloud", "backup_sync"),
    ("Sync.com", "2.4.0", "Sync.com", "backup_sync"),
    ("AWX", "23.3.0", "Red Hat", "config_mgmt"),
    ("Chef Client", "18.2.7", "Progress Software", "config_mgmt"),
    ("Puppet Agent", "7.24.0", "Puppet Inc", "config_mgmt"),
    ("Salt", "3006.1", "VMware", "config_mgmt"),
    ("CFEngine", "3.21.0", "Northern.tech", "config_mgmt"),
    ("AWS CLI", "2.13.5", "Amazon Web Services", "cloud_cli"),
    ("Azure CLI", "2.50.0", "Microsoft", "cloud_cli"),
    ("Google Cloud CLI", "439.0.0", "Google", "cloud_cli"),
    ("doctl", "1.98.1", "DigitalOcean", "cloud_cli"),
    ("Heroku CLI", "8.8.0", "Salesforce", "cloud_cli"),
    ("VeraCrypt", "1.26.7", "IDRIX", "disk_encryption"),
]

for name, version, vendor, category in DESKTOP_PRODUCTS:
    add_row(name, version, vendor, DESKTOP_CATEGORY_USAGE[category])

desktop_row_count = len(rows) - registry_row_count

# ---------------------------------------------------------------------------
# UNIDENTIFIED negative controls: fictional products, no real registry/CPE
# entry should exist. Small number, per task instructions.
# ---------------------------------------------------------------------------
FICTIONAL_PRODUCTS = [
    ("QuantumFlowSyncPro", "9.9.9", "", "used internally per engineering; could not be located in any inventory system"),
    ("Zylotrex Enterprise Suite", "4.2.1-beta", "ZyloCorp", "product mentioned in an old procurement email; no further details available"),
    ("NebulaGridManager", "2023.7.0", "", "referenced in a legacy asset list with no vendor information"),
    ("Fictiontech Workbench", "1.0.0", "Fictiontech Inc", "internal tool name that does not correspond to any known commercial or open-source product"),
    ("PhantomOps Console", "3.14.15", "", "listed in a spreadsheet with no other identifying information"),
    ("Glimmerwave Studio", "12.0", "Glimmerwave LLC", "unclear origin; possibly a rebranded or discontinued product"),
    ("Krakenfile Vault", "5.5.5", "", "name appears to be a placeholder or typo in the source inventory"),
    ("Solarpeak Manager", "2.2.2", "SolarPeak Systems", "no matching product found in any public registry or CPE dictionary"),
    ("Thunderclap CLI", "0.0.1", "", "referenced once in a build log with no further context"),
    ("Obscura Deploy Toolkit", "7.7.7", "Obscura Labs", "name does not match any known real-world software product"),
]

for name, version, vendor, usage_text in FICTIONAL_PRODUCTS:
    add_row(name, version, vendor, usage_text)

fictional_row_count = len(rows) - registry_row_count - desktop_row_count

# ---------------------------------------------------------------------------
# Dedup check against real-400.csv, then write output.
# ---------------------------------------------------------------------------
existing = set()
with open("test-data/real-400.csv", newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    for r in reader:
        existing.add((r["product_name"], r["version"]))

dupes = [(n, v) for (n, v, *_rest) in rows if (n, v) in existing]

# Also check for exact duplicate (name, version) pairs within the new file itself.
seen = set()
internal_dupes = []
for n, v, *_rest in rows:
    key = (n, v)
    if key in seen:
        internal_dupes.append(key)
    seen.add(key)

with open("test-data/real-1000-additional-600.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["product_name", "version", "vendor", "usage_text", "install_url"])
    for row in rows:
        writer.writerow(row)

print("=== per-ecosystem fetch log ===")
for line in log_lines:
    print(line)
print()
print("=== summary ===")
print(f"registry rows: {registry_row_count}")
for eco in ECOSYSTEM_USAGE:
    print(f"  {eco}: {eco_counts[eco]}")
print(f"desktop/CPE-only rows: {desktop_row_count}")
print(f"fictional/UNIDENTIFIED rows: {fictional_row_count}")
print(f"TOTAL rows: {len(rows)}")
print(f"duplicates against real-400.csv (product_name, version): {len(dupes)}")
if dupes:
    print(dupes)
print(f"internal duplicate (product_name, version) pairs within new file: {len(internal_dupes)}")
if internal_dupes:
    print(internal_dupes)

if dupes or internal_dupes:
    sys.exit(1)
