#!/usr/bin/env python3
"""One-off ground-truth verification tool for test-data/golden-300.csv (NOT the app's own
pipeline; this is a standalone script that independently queries each public package
registry's own API to confirm a real package name exists and to fetch its current latest
version, so the golden set's `expected_outcome=IDENTIFIED_REGISTRY` rows are backed by an
actual, freshly-checked registry response rather than a hand-remembered version number
(test-design-policy.md P1). Prints one line per candidate: OK/MISS, ecosystem, name,
version, and the exact query URL used (to be copied verbatim into golden-300.csv's
ground_truth_source column). Sequential, one request at a time, with a fixed per-request
sleep chosen conservatively per ecosystem (crates.io policy requires >=1s between requests
and a descriptive User-Agent; the rest have no published hard limit but are throttled
the same way here to be a good citizen).
"""
import json
import sys
import time
import urllib.request
import urllib.error

UA = "vulncheck-research-golden300-dataset-builder/1.0 (+internal research tool, non-commercial)"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.read().decode("utf-8")


def npm(name):
    url = f"https://registry.npmjs.org/{name}/latest"
    data = json.loads(fetch(url))
    return data["version"], url


def pypi(name):
    url = f"https://pypi.org/pypi/{name}/json"
    data = json.loads(fetch(url))
    return data["info"]["version"], url


def crates(name):
    url = f"https://crates.io/api/v1/crates/{name}"
    data = json.loads(fetch(url))
    return data["crate"]["newest_version"], url


def rubygems(name):
    url = f"https://rubygems.org/api/v1/gems/{name}.json"
    data = json.loads(fetch(url))
    return data["version"], url


def nuget(name):
    lname = name.lower()
    url = f"https://api.nuget.org/v3-flatcontainer/{lname}/index.json"
    data = json.loads(fetch(url))
    versions = data["versions"]
    stable = [v for v in versions if "-" not in v]
    v = stable[-1] if stable else versions[-1]
    return v, url


def packagist(vendor_pkg):
    url = f"https://repo.packagist.org/p2/{vendor_pkg}.json"
    data = json.loads(fetch(url))
    key = vendor_pkg
    versions = data["packages"][key]
    stable = [v["version"] for v in versions if "dev" not in v["version"] and "-" not in v["version"]]
    v = stable[0] if stable else versions[0]["version"]
    return v, url


def hex(name):
    url = f"https://hex.pm/api/packages/{name}"
    data = json.loads(fetch(url))
    releases = data["releases"]
    v = releases[0]["version"]
    return v, url


def pub(name):
    url = f"https://pub.dev/api/packages/{name}"
    data = json.loads(fetch(url))
    return data["latest"]["version"], url


def go(module):
    url = f"https://proxy.golang.org/{module}/@latest"
    data = json.loads(fetch(url))
    return data["Version"], url


def maven(coord):
    group, artifact = coord.split(":")
    gpath = group.replace(".", "/")
    url = f"https://repo1.maven.org/maven2/{gpath}/{artifact}/maven-metadata.xml"
    xml = fetch(url)
    # crude extraction, no external deps
    import re
    m = re.search(r"<release>([^<]+)</release>", xml)
    if not m:
        m = re.search(r"<latest>([^<]+)</latest>", xml)
    return m.group(1), url


FETCHERS = {
    "npm": npm, "pypi": pypi, "crates": crates, "rubygems": rubygems, "nuget": nuget,
    "packagist": packagist, "hex": hex, "pub": pub, "go": go, "maven": maven,
}

SLEEP_S = 1.2

CANDIDATES = [
    ("npm", "lodash"), ("npm", "express"), ("npm", "react"), ("npm", "axios"), ("npm", "chalk"),
    ("npm", "commander"), ("npm", "moment"), ("npm", "uuid"), ("npm", "dotenv"), ("npm", "webpack"),
    ("npm", "eslint"), ("npm", "typescript"), ("npm", "jest"), ("npm", "vue"), ("npm", "next"),
    ("npm", "tailwindcss"), ("npm", "prettier"), ("npm", "socket.io"), ("npm", "yargs"), ("npm", "zod"),

    ("pypi", "requests"), ("pypi", "numpy"), ("pypi", "flask"), ("pypi", "django"), ("pypi", "pandas"),
    ("pypi", "pytest"), ("pypi", "boto3"), ("pypi", "click"), ("pypi", "PyYAML"), ("pypi", "SQLAlchemy"),
    ("pypi", "Pillow"), ("pypi", "cryptography"), ("pypi", "celery"), ("pypi", "gunicorn"),
    ("pypi", "fastapi"), ("pypi", "Jinja2"), ("pypi", "urllib3"), ("pypi", "scipy"),
    ("pypi", "matplotlib"), ("pypi", "beautifulsoup4"),

    ("maven", "org.springframework:spring-core"), ("maven", "com.google.guava:guava"),
    ("maven", "org.apache.commons:commons-lang3"), ("maven", "com.fasterxml.jackson.core:jackson-databind"),
    ("maven", "junit:junit"), ("maven", "org.slf4j:slf4j-api"), ("maven", "ch.qos.logback:logback-classic"),
    ("maven", "org.projectlombok:lombok"), ("maven", "com.squareup.okhttp3:okhttp"),
    ("maven", "com.squareup.retrofit2:retrofit"), ("maven", "org.hibernate:hibernate-core"),
    ("maven", "org.mockito:mockito-core"), ("maven", "io.netty:netty-all"),
    ("maven", "org.apache.kafka:kafka-clients"), ("maven", "com.google.code.gson:gson"),
    ("maven", "org.apache.httpcomponents:httpclient"), ("maven", "org.springframework.boot:spring-boot-starter-web"),
    ("maven", "org.apache.logging.log4j:log4j-core"), ("maven", "com.zaxxer:HikariCP"),
    ("maven", "io.micrometer:micrometer-core"),

    ("go", "github.com/gin-gonic/gin"), ("go", "github.com/gorilla/mux"), ("go", "github.com/spf13/cobra"),
    ("go", "github.com/stretchr/testify"), ("go", "github.com/sirupsen/logrus"), ("go", "github.com/pkg/errors"),
    ("go", "golang.org/x/crypto"), ("go", "golang.org/x/net"), ("go", "github.com/prometheus/client_golang"),
    ("go", "github.com/aws/aws-sdk-go"), ("go", "github.com/go-redis/redis/v8"), ("go", "gorm.io/gorm"),
    ("go", "github.com/spf13/viper"), ("go", "github.com/golang-jwt/jwt/v5"), ("go", "github.com/gofiber/fiber/v2"),
    ("go", "github.com/labstack/echo/v4"), ("go", "github.com/hashicorp/vault/api"),
    ("go", "google.golang.org/grpc"), ("go", "github.com/miekg/dns"), ("go", "github.com/urfave/cli/v2"),

    ("nuget", "Newtonsoft.Json"), ("nuget", "Serilog"), ("nuget", "AutoMapper"), ("nuget", "Dapper"),
    ("nuget", "NUnit"), ("nuget", "xunit"), ("nuget", "Moq"), ("nuget", "Polly"),
    ("nuget", "FluentValidation"), ("nuget", "RestSharp"), ("nuget", "MediatR"),
    ("nuget", "Swashbuckle.AspNetCore"), ("nuget", "StackExchange.Redis"),
    ("nuget", "Microsoft.Extensions.DependencyInjection"), ("nuget", "log4net"), ("nuget", "NLog"),
    ("nuget", "Humanizer"), ("nuget", "MailKit"), ("nuget", "Microsoft.EntityFrameworkCore"),
    ("nuget", "AWSSDK.S3"),

    ("rubygems", "rails"), ("rubygems", "rspec"), ("rubygems", "devise"), ("rubygems", "sidekiq"),
    ("rubygems", "puma"), ("rubygems", "nokogiri"), ("rubygems", "rack"), ("rubygems", "bundler"),
    ("rubygems", "faraday"), ("rubygems", "rubocop"), ("rubygems", "capistrano"), ("rubygems", "sinatra"),
    ("rubygems", "jekyll"), ("rubygems", "pundit"), ("rubygems", "kaminari"), ("rubygems", "httparty"),
    ("rubygems", "aws-sdk"), ("rubygems", "redis"), ("rubygems", "jwt"), ("rubygems", "activerecord"),

    ("crates", "serde"), ("crates", "tokio"), ("crates", "clap"), ("crates", "rand"), ("crates", "regex"),
    ("crates", "reqwest"), ("crates", "log"), ("crates", "anyhow"), ("crates", "thiserror"),
    ("crates", "rayon"), ("crates", "actix-web"), ("crates", "hyper"), ("crates", "chrono"),
    ("crates", "itertools"), ("crates", "futures"), ("crates", "structopt"), ("crates", "tracing"),
    ("crates", "uuid"), ("crates", "bytes"), ("crates", "prost"),

    ("packagist", "monolog/monolog"), ("packagist", "guzzlehttp/guzzle"), ("packagist", "symfony/console"),
    ("packagist", "laravel/framework"), ("packagist", "doctrine/orm"), ("packagist", "phpunit/phpunit"),
    ("packagist", "twig/twig"), ("packagist", "symfony/http-foundation"), ("packagist", "nesbot/carbon"),
    ("packagist", "league/flysystem"), ("packagist", "symfony/finder"), ("packagist", "psr/log"),
    ("packagist", "ramsey/uuid"), ("packagist", "firebase/php-jwt"), ("packagist", "spatie/laravel-permission"),
    ("packagist", "symfony/yaml"), ("packagist", "composer/composer"), ("packagist", "vlucas/phpdotenv"),
    ("packagist", "nikic/fast-route"), ("packagist", "symfony/process"),

    ("hex", "phoenix"), ("hex", "ecto"), ("hex", "plug"), ("hex", "cowboy"), ("hex", "jason"),
    ("hex", "ex_doc"), ("hex", "credo"), ("hex", "dialyxir"), ("hex", "absinthe"), ("hex", "tesla"),
    ("hex", "poison"), ("hex", "comeonin"), ("hex", "guardian"), ("hex", "timex"), ("hex", "broadway"),
    ("hex", "oban"), ("hex", "telemetry"), ("hex", "phoenix_live_view"), ("hex", "gettext"), ("hex", "mox"),

    ("pub", "http"), ("pub", "provider"), ("pub", "dio"), ("pub", "riverpod"), ("pub", "bloc"),
    ("pub", "get"), ("pub", "shared_preferences"), ("pub", "flutter_bloc"), ("pub", "path_provider"),
    ("pub", "intl"), ("pub", "cached_network_image"), ("pub", "google_fonts"), ("pub", "sqflite"),
    ("pub", "url_launcher"), ("pub", "image_picker"), ("pub", "connectivity_plus"), ("pub", "freezed"),
    ("pub", "json_annotation"), ("pub", "equatable"), ("pub", "flutter_svg"),
]


def main():
    out_path = "test-data/golden300_registry_results.tsv"
    with open(out_path, "w") as out:
        out.write("ecosystem\tname\tstatus\tversion\turl\n")
        for eco, name in CANDIDATES:
            fn = FETCHERS[eco]
            try:
                version, url = fn(name)
                line = f"{eco}\t{name}\tOK\t{version}\t{url}"
            except urllib.error.HTTPError as e:
                line = f"{eco}\t{name}\tMISS_HTTP_{e.code}\t\t{e.url if hasattr(e,'url') else ''}"
            except Exception as e:
                line = f"{eco}\t{name}\tERROR_{type(e).__name__}\t{e}\t"
            print(line)
            out.write(line + "\n")
            out.flush()
            time.sleep(SLEEP_S)
    print(f"\nDone. Results written to {out_path}")


if __name__ == "__main__":
    main()
