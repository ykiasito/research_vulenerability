# Vulnerability Pre-Screening Web App

A CSV-upload-based vulnerability pre-screening web app. Upload a CSV list of software you plan to deploy (product name, version, purpose, etc.), and it looks up known vulnerabilities (CVEs, etc.) for each product and returns the results. It's designed with a GUI for non-engineers, and **assumes personal, individual use**.

Tech stack: Spring Boot (Java 21, Thymeleaf) + Python/FastAPI (Claude LLM microservice) + PostgreSQL 16, all orchestrated with Docker Compose.

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

## Important Notes

**This app assumes personal use on a private, non-public network. Do not deploy it as-is to an environment exposed to the internet.**

Specifically, the current docker-compose configuration has the following constraints:

- TLS (HTTPS) is not configured. Communication is in plain text.
- The `Secure` attribute is not set on the session cookie.

(Addressed on 2026-08-29) PostgreSQL (port 5432) and llm-service (port 8000) have been changed in `docker-compose.yml` to bind to `127.0.0.1` only, and are no longer reachable from outside the host. However, this only holds when running Docker Compose as-is; it loses meaning if you set up reverse-proxy forwarding or expose the host itself directly to the internet.

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
