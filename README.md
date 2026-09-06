# Vulnerability Pre-Screening Web App

A CSV-upload-based vulnerability pre-screening web app. Upload a CSV list of software you plan to deploy (product name, version, purpose, etc.), and it looks up known vulnerabilities (CVEs, etc.) for each product and returns the results. It's designed with a GUI for non-engineers, and **assumes personal, individual use**.

Tech stack: Spring Boot (Java 21, Thymeleaf) + PostgreSQL 16, all orchestrated with Docker Compose.

This is the `closed-mode` branch: it is designed to run fully offline, with **no external LLM/AI API calls anywhere in the CSV upload → identification pipeline**. There is no `llm-service` component here — the Python/FastAPI Claude LLM microservice used on other branches of this project was fully removed on `closed-mode`. `docker-compose.yml` on this branch defines exactly two services, `backend` and `postgres`; if you've read about a third `llm-service` container or port 8000 elsewhere, that does not apply here.

Detailed design and specification documents for this project are for personal use and are not included in this repository.

## Setup

### Prerequisites

- Docker / Docker Compose v2
- `openssl` and `curl` (used by `install.sh` for automatic key generation and startup verification)

### Steps

```
./install.sh
```

On first run, it creates a new `.env` from `.env.example`, auto-generates an encryption key (`APP_SECRET_ENCRYPTION_KEY`) and a DB password (`POSTGRES_PASSWORD`), and then builds and starts everything with Docker Compose. If `.env` already exists, it will not be overwritten.

`.env` also contains items you should set yourself for each environment, such as `ADMIN_EMAIL` (the login email address granted admin privileges) and `JOB_RETENTION_DAYS` (the number of days after which jobs are automatically deleted). Edit `.env` directly as needed.

Once started, the app is available at `http://localhost:8080`.

## Initial Data Setup (Important — Do This Before Trusting Any Results)

Right after a fresh install, the CPE dictionary and all vulnerability data mirrors are **empty**. If you upload a CSV and run a job in this state, everything will come back as "no known vulnerabilities" — but that's simply because there's no data to match against yet, not because the software you listed is actually safe. Do the following, **in this order**, before treating any job's results as meaningful, and before opening this app up to anyone else on your network:

1. **Register the `ADMIN_EMAIL` account first, before anyone else can reach the app.** `/register` is open to anyone who can reach the app, and whoever registers with the email address that matches `ADMIN_EMAIL` in `.env` is granted admin rights (needed for all of the steps below, under `/admin/**`). Port 8080 is reachable from your whole network by default (see "Important Notes" below), and there is no TLS, so register the admin account immediately after the first `docker compose up`, before exposing the app to other users.
2. Run a full CPE dictionary sync from the admin screen (`/admin/cpe-dictionary`). Without this, product/version identification has essentially nothing to match against.
3. Run the GHSA and OSV baseline syncs (`/admin/ghsa` → "sync baseline", `/admin/osv` → "sync baseline"). Their daily automatic sync only keeps things up to date after this initial baseline has been loaded once; it does not populate it in the first place.
4. Run the NVD CVE backfill from the admin screen (`/admin/nvd-cve` → "sync now"). This may take several clicks/ticks to finish (each run is time/request-budgeted and reports whether the baseline is complete yet). This step is not optional in practice: it's the primary vulnerability data source behind CPE-based identifications (e.g. Chrome, OpenSSL, nginx-type entries).
5. Run the registry mirror sync from the admin screen (`/admin/registry-mirror` → "sync all"), which covers all 9 supported package ecosystems (npm, PyPI, crates.io, RubyGems, Packagist, NuGet, Hex, pub.dev, Go modules).
6. Only after all of the above have completed at least once should you rely on job results, or restrict/close off further network access changes.

## Important Notes

**This app assumes personal use on a private, non-public network. Do not deploy it as-is to an environment exposed to the internet.**

Specifically, the current docker-compose configuration has the following constraints:

- TLS (HTTPS) is not configured. Communication is in plain text.
- The `Secure` attribute is not set on the session cookie.

(Addressed on 2026-08-29) PostgreSQL (port 5432) is bound to `127.0.0.1` only in `docker-compose.yml`, and is not reachable from outside the host. However, this only holds when running Docker Compose as-is; it loses meaning if you set up reverse-proxy forwarding or expose the host itself directly to the internet.

**Unlike PostgreSQL, the backend (port 8080) is bound to all host network interfaces, not just localhost** — it is reachable from any machine that can route to the host, which is what lets other machines on your network use the app at all. Docker Compose itself does not restrict this any further, so if you need to limit who can reach it, that's on your host firewall / network segmentation, not this app's configuration. This is also why registering the `ADMIN_EMAIL` account before anyone else can reach the app (see "Initial Data Setup" above) matters more here than it would on a purely localhost-bound port.

If you run this in an environment connected to an untrusted network such as the internet, you must, in addition to the above, terminate TLS via a reverse proxy and set the `Secure` attribute on cookies.

## Running Tests (For Developers)

To run `mvn test`, you need to first create a dedicated `vulncheck_test` role and database against a running Postgres instance. Follow the steps below. **Run these from `psql` inside the Postgres container** (`docker exec -it <postgres-container> psql -U vulncheck -d vulncheck`).

```sql
-- 1. Create a role dedicated to testing (no special attributes beyond LOGIN —
--    SUPERUSER/CREATEDB/CREATEROLE all remain false)
CREATE ROLE vulncheck_test WITH LOGIN PASSWORD 'vulncheck_test';

-- 2. Create a dedicated test database (owner remains the production role vulncheck —
--    do not make vulncheck_test itself the DB owner)
CREATE DATABASE vulncheck_test OWNER vulncheck;

-- 3. Allow the vulncheck_test role to connect to this database
GRANT CONNECT ON DATABASE vulncheck_test TO vulncheck_test;

-- 4. Allow table creation/reference in the public schema
--    (needed for Flyway migrations to run)
--    (run this after connecting to the vulncheck_test database)
\c vulncheck_test
GRANT USAGE, CREATE ON SCHEMA public TO vulncheck_test;

-- 5. [REQUIRED] Block PUBLIC-role connections to the production vulncheck/postgres databases
--    By default, when a database's datacl (database ACL) is NULL, PostgreSQL implicitly
--    grants CONNECT/TEMP privileges to the PUBLIC role. Unless you close this off, the
--    vulncheck_test role created above (whose password is the known, plainly-written value
--    'vulncheck_test' checked into this repository) would be able to connect to the
--    production vulncheck database. Even without being able to read the tables themselves,
--    it could still enumerate the entire catalog (table names, column names, role names,
--    pg_settings) and create unlimited temporary tables (a disk-exhaustion risk).
REVOKE CONNECT ON DATABASE vulncheck FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
```

After running the above, confirm that the following SQL returns `f` (cannot connect):

```sql
SELECT has_database_privilege('vulncheck_test', 'vulncheck', 'CONNECT');
```

**Warning: the `vulncheck_test` password is fixed at `vulncheck_test` and is written in plain text in `backend/src/test/resources/application.yml` (since this is a public repository, this value is known and readable by anyone). Do not create this role/password combination in any environment that can reach the production `vulncheck` database.** If you skip the REVOKE in step 5 above, this role becomes a route for reconnaissance and DoS (disk exhaustion via temporary tables) against the production database. Do not create this role anywhere other than a Postgres instance dedicated to local development (the one started by this repository's `docker-compose.yml`).

Test classes that use `@AutoConfigureTestDatabase(Replace.NONE)` must always be run only against the dedicated `vulncheck_test` database above (hardcoded in `backend/src/test/resources/application.yml`). Running them against the real dev database (`vulncheck`) is prohibited.

---

日本語版は [README_ja.md](README_ja.md) を参照してください。
