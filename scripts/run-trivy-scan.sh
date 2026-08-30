#!/usr/bin/env bash
#
# run-trivy-scan.sh — dependency vulnerability scan, run after `mvn test`.
#
# What it does (backlog item 44):
#   1. Runs `mvn -B test` for the backend inside the maven:3.9-eclipse-temurin-21
#      container (same command documented in CLAUDE.md), reusing the
#      research_vuln_m2_cache volume so this doesn't hammer Maven Central.
#   2. If (and only if) the tests pass, runs Trivy against:
#        - backend/pom.xml            (Java direct + transitive deps)
#        - llm-service/requirements.txt        (Python direct + transitive deps)
#        - llm-service/requirements-dev.txt     (Python dev/test-only deps, see note below)
#        - the built backend image     (OS layer + baked-in language deps)
#        - the built llm-service image (OS layer + baked-in language deps, catches
#          things a source-manifest scan alone misses — see backlog item 46,
#          starlette was only visible via the image scan)
#   3. Classifies every CRITICAL/HIGH finding into:
#        - "fixable": FixedVersion is set -> an app-side dependency bump can close it
#        - "os-layer": FixedVersion is empty/"-" -> upstream base-image issue, nothing
#          this repo's manifests can do about it (see backlog item 47)
#   4. Writes a Markdown report to $TRIVY_FINDINGS_FILE (default /tmp/trivy-findings.md)
#      containing ONLY the fixable findings, formatted as a ready-to-paste
#      `docs/spec/task-backlog.md` OPEN item candidate. This script never writes to
#      task-backlog.md itself (docs/spec/ is gitignored and usually absent from a
#      worktree checkout) — actually filing the item is left to whoever reviews the
#      report.
#
# requirements-dev.txt handling (backlog item 44, point 4):
#   Trivy's pip analyzer only recognizes files with the exact name "requirements.txt"
#   (tester-confirmed), so requirements-dev.txt is invisible to a plain `trivy fs` scan
#   pointed at the llm-service directory. Rather than skip it, we resolve what it
#   actually installs (`-r requirements.txt` plus `pytest==8.3.3`) into a temp file
#   named requirements.txt and scan that. Coverage was deemed worth the extra ~cheap
#   scan even though pytest is dev/test-only and never ships in the runtime image
#   (llm-service/Dockerfile only COPYs requirements.txt) — a compromised test
#   dependency can still execute arbitrary code on a developer machine or CI runner
#   during `mvn test`/`pytest`, which is exactly the moment this script runs.
#
# This script is informational: it always exits 0 after a successful scan pass,
# even if vulnerabilities were found (CI is not blocked on this; a human decides
# whether/when to act on the report). It only exits non-zero if `mvn test` itself
# fails, or if a scan step errors out (e.g. Docker unavailable).
#
# Usage:
#   scripts/run-trivy-scan.sh                # mvn test, then scan
#   scripts/run-trivy-scan.sh --skip-tests    # scan only, skip mvn test
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BACKEND_DIR="$REPO_ROOT/backend"
LLM_SERVICE_DIR="$REPO_ROOT/llm-service"

TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:latest}"
MAVEN_IMAGE="${MAVEN_IMAGE:-maven:3.9-eclipse-temurin-21}"
DOCKER_NETWORK="${DOCKER_NETWORK:-research_vulenerability_default}"
M2_CACHE_VOLUME="${M2_CACHE_VOLUME:-research_vuln_m2_cache}"
TRIVY_CACHE_DIR="${TRIVY_CACHE_DIR:-/tmp/trivy-cache}"
BACKEND_IMAGE="${BACKEND_IMAGE:-research_vulenerability-backend:latest}"
LLM_SERVICE_IMAGE="${LLM_SERVICE_IMAGE:-research_vulenerability-llm-service:latest}"
TRIVY_FINDINGS_FILE="${TRIVY_FINDINGS_FILE:-/tmp/trivy-findings.md}"

SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=1 ;;
    *)
      echo "[run-trivy-scan] unknown argument: $arg" >&2
      echo "usage: $0 [--skip-tests]" >&2
      exit 2
      ;;
  esac
done

log() { echo "[run-trivy-scan] $*" >&2; }

mkdir -p "$TRIVY_CACHE_DIR"
SCAN_TMP_DIR="$(mktemp -d /tmp/trivy-scan.XXXXXX)"
trap 'rm -rf "$SCAN_TMP_DIR"' EXIT

if [[ "$SKIP_TESTS" -eq 0 ]]; then
  log "Running backend test suite (mvn -B test) before scanning..."
  docker run --rm --network "$DOCKER_NETWORK" \
    -v "$BACKEND_DIR:/build" \
    -v "$M2_CACHE_VOLUME:/root/.m2" \
    -w /build \
    "$MAVEN_IMAGE" mvn -B test
  log "mvn test passed."
else
  log "--skip-tests given, skipping mvn test."
fi

# --- Java: backend/pom.xml -------------------------------------------------
log "Scanning backend/pom.xml (Java deps)..."
docker run --rm --network "$DOCKER_NETWORK" \
  -v "$BACKEND_DIR:/repo:ro" \
  -v "$M2_CACHE_VOLUME:/root/.m2:ro" \
  -v "$TRIVY_CACHE_DIR:/root/.cache/" \
  "$TRIVY_IMAGE" fs --scanners vuln --format json /repo/pom.xml \
  > "$SCAN_TMP_DIR/pom.json"

# --- Python: llm-service/requirements.txt -----------------------------------
log "Scanning llm-service/requirements.txt (Python direct+transitive deps)..."
docker run --rm \
  -v "$LLM_SERVICE_DIR:/repo:ro" \
  -v "$TRIVY_CACHE_DIR:/root/.cache/" \
  "$TRIVY_IMAGE" fs --scanners vuln --format json /repo/requirements.txt \
  > "$SCAN_TMP_DIR/requirements.json"

# --- Python: llm-service/requirements-dev.txt (see header note) -------------
log "Scanning llm-service/requirements-dev.txt (Python dev/test-only deps)..."
DEV_REQ_DIR="$SCAN_TMP_DIR/dev-requirements"
mkdir -p "$DEV_REQ_DIR"
# Resolve what requirements-dev.txt actually installs (main reqs + pytest) into a
# file literally named requirements.txt, since Trivy's pip analyzer matches on
# filename only. See header note for why this isn't just skipped.
grep -v '^-r ' "$LLM_SERVICE_DIR/requirements-dev.txt" > "$DEV_REQ_DIR/extra.txt" || true
cat "$LLM_SERVICE_DIR/requirements.txt" "$DEV_REQ_DIR/extra.txt" > "$DEV_REQ_DIR/requirements.txt"
docker run --rm \
  -v "$DEV_REQ_DIR:/repo:ro" \
  -v "$TRIVY_CACHE_DIR:/root/.cache/" \
  "$TRIVY_IMAGE" fs --scanners vuln --format json /repo/requirements.txt \
  > "$SCAN_TMP_DIR/requirements-dev.json"

# --- Built images (OS layer + baked-in transitive deps) ---------------------
scan_image() {
  local image_name="$1" out_file="$2"
  if docker image inspect "$image_name" >/dev/null 2>&1; then
    log "Scanning image $image_name..."
    docker run --rm \
      -v "$TRIVY_CACHE_DIR:/root/.cache/" \
      -v /var/run/docker.sock:/var/run/docker.sock \
      "$TRIVY_IMAGE" image --scanners vuln --format json "$image_name" \
      > "$out_file"
  else
    log "WARNING: image $image_name not found locally, skipping image scan for it. Build it first (docker compose build) for full coverage."
    echo '{"Results":[]}' > "$out_file"
  fi
}
scan_image "$BACKEND_IMAGE" "$SCAN_TMP_DIR/backend-image.json"
scan_image "$LLM_SERVICE_IMAGE" "$SCAN_TMP_DIR/llm-service-image.json"

# --- Classify + report --------------------------------------------------
log "Classifying findings (fixable vs. OS-layer/upstream) and writing report..."

FLAT_JSON="$SCAN_TMP_DIR/all-findings.json"
jq -s '
  [ .[] | (.Results // [])[] | . as $r |
    ($r.Vulnerabilities // [])[] |
    select(.Severity == "CRITICAL" or .Severity == "HIGH") |
    {
      Target: $r.Target,
      VulnerabilityID: .VulnerabilityID,
      PkgName: .PkgName,
      InstalledVersion: .InstalledVersion,
      FixedVersion: (.FixedVersion // ""),
      Severity: .Severity,
      Title: (.Title // ""),
      PrimaryURL: (.PrimaryURL // "")
    }
  ] | unique
' "$SCAN_TMP_DIR/pom.json" "$SCAN_TMP_DIR/requirements.json" "$SCAN_TMP_DIR/requirements-dev.json" \
  "$SCAN_TMP_DIR/backend-image.json" "$SCAN_TMP_DIR/llm-service-image.json" \
  > "$FLAT_JSON"

FIXABLE_JSON="$SCAN_TMP_DIR/fixable.json"
UNFIXABLE_JSON="$SCAN_TMP_DIR/unfixable.json"
jq '[.[] | select(.FixedVersion != "" and .FixedVersion != "-")]' "$FLAT_JSON" > "$FIXABLE_JSON"
jq '[.[] | select(.FixedVersion == "" or .FixedVersion == "-")]' "$FLAT_JSON" > "$UNFIXABLE_JSON"

FIXABLE_COUNT="$(jq 'length' "$FIXABLE_JSON")"
UNFIXABLE_COUNT="$(jq 'length' "$UNFIXABLE_JSON")"
SCAN_DATE="$(date -u +%Y-%m-%d)"

{
  echo "# Trivy scan findings — $SCAN_DATE"
  echo
  echo "Fixable (app-dependency, CRITICAL/HIGH, has FixedVersion): $FIXABLE_COUNT"
  echo "OS-layer / upstream-only (no FixedVersion, not actionable here): $UNFIXABLE_COUNT"
  echo
  if [[ "$FIXABLE_COUNT" -eq 0 ]]; then
    echo "No fixable CRITICAL/HIGH findings. Nothing to file."
  else
    echo "## Backlog candidate (paste into docs/spec/task-backlog.md ## OPEN after review)"
    echo
    echo "### [NEW]. Trivyスキャンで検出されたCRITICAL/HIGH脆弱性(修正版あり、自動起票候補) [自動生成、要レビュー、$SCAN_DATE]"
    echo "- **状態**: OPEN"
    echo "- **背景**: \`scripts/run-trivy-scan.sh\`の自動実行($SCAN_DATE)で、以下のCRITICAL/HIGH脆弱性が検出された。いずれも\`FixedVersion\`が存在し、依存関係の更新で対応可能と判定されたもの(OS層・上流待ちの${UNFIXABLE_COUNT}件は対応不能のため除外済み、既存記録は項目47参照)。重複や既存バックログ項目との突き合わせは未実施——起票前に確認すること。"
    echo "$(jq -r '
      group_by(.Target) | map(
        "  - **" + .[0].Target + "**\n" +
        (map("    - " + .Severity + " `" + .VulnerabilityID + "` " + .PkgName + " " + .InstalledVersion + " → " + .FixedVersion +
          (if .Title != "" then " — " + .Title else "" end)) | join("\n"))
      ) | join("\n")
    ' "$FIXABLE_JSON")"
    echo "- **やること**: 該当ライブラリを記載の\`FixedVersion\`以上へ更新し、既存テストスイートで回帰が無いことを確認する。"
    echo "- **費用**: 無料(ライブラリ更新のみ、AI不使用)。"
  fi
} > "$TRIVY_FINDINGS_FILE"

cat "$TRIVY_FINDINGS_FILE"
log "Report written to $TRIVY_FINDINGS_FILE"
