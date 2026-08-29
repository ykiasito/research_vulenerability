# llm-service

FastAPI microservice wrapping the Anthropic Messages API for Stage1 Tier2/Tier3 identification and
Stage4 vulnerability research. See `main.py`'s module docstring and `docs/spec/pipeline.md` for the
overall design; this file only covers running things locally/in CI.

## Running the app

Normal operation is via `docker compose` (see the repo root `docker-compose.yml`) — the `llm-service`
container builds from `Dockerfile` and installs `requirements.txt`.

## Running the Python tests

There is no host-installed Python environment for this project (same constraint as the backend's
Maven — see the repo root `CLAUDE.md`). Run `tests/` inside a disposable `python:3.12-slim`
container, bind-mounting this directory:

```
docker run --rm -v <absolute-path-to-repo>/llm-service:/app -w /app python:3.12-slim sh -c "pip install --quiet --disable-pip-version-check -r requirements-dev.txt && python -B -m pytest tests -q"
```

Notes:
- `-B` (`PYTHONDONTWRITEBYTECODE`) is required, not just tidy — without it, `pytest` writes
  `__pycache__/*.pyc` into the bind-mounted host directory owned by the container's root user,
  which the host user then can't clean up without another root-owned `docker run`.
- `requirements-dev.txt` pulls in `requirements.txt` (the app's real runtime dependencies) plus
  `pytest` — nothing here is installed into the image itself, so this reinstalls into the
  container's site-packages on every run (a few seconds; there's no persistent test image build
  step for this service).
- Verified working 2026-08-30 against the `tests/test_verify_high_confidence_schema.py` suite (7
  passed) as part of PR #8's REVISE fixes.
