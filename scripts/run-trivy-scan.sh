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
#      with the source-manifest findings and the built-image findings kept in two
#      SEPARATE sections (backlog item 44 REVISE, PR#27 review):
#        - source-manifest section (pom.xml / requirements.txt / requirements-dev.txt):
#          this is always as fresh as the current source tree, and its fixable
#          findings are formatted as a ready-to-paste `docs/spec/task-backlog.md`
#          OPEN item candidate.
#        - built-image section (backend/llm-service images): this only reflects
#          whatever was baked into the image at build time, which can lag behind
#          the current source if nobody has rebuilt since a dependency bump. It is
#          reference-only — never formatted as a backlog candidate — and if the
#          image predates the last manifest-touching commit, the report and stderr
#          both carry a WARNING telling the reader to rebuild and re-scan before
#          trusting this section's counts. (A real incident on 2026-08-30: an
#          un-rebuilt backend image reported 92 "findings" — starlette/tomcat/
#          thymeleaf/jackson — that were already fixed on the source side by the
#          Spring Boot 3.5.16 BOM update; none of those should ever have been
#          filed as backlog candidates.)
#      This script never writes to task-backlog.md itself (docs/spec/ is gitignored
#      and usually absent from a worktree checkout) — actually filing an item is
#      left to whoever reviews the report.
#
# requirements-dev.txt handling (backlog item 44, point 4):
#   Trivy's pip analyzer only recognizes files with the exact name "requirements.txt"
#   (tester-confirmed), so requirements-dev.txt is invisible to a plain `trivy fs` scan
#   pointed at the llm-service directory. Rather than skip it, we resolve what it
#   actually installs (`-r requirements.txt` plus `pytest==8.3.3`) into a temp file
#   named requirements.txt and scan that. Because that temp file is scanned under
#   the same in-container path (/repo/requirements.txt) as the real
#   requirements.txt scan, both scans' findings are given a Target label prefix
#   ("requirements.txt" / "requirements-dev.txt", reusing the label mechanism
#   from backlog item 62) before being merged, so `group_by(.Target)` in the
#   report never fuses main-dependency and dev-only findings together
#   (backlog item 66). Coverage was deemed worth the extra ~cheap
#   scan even though pytest is dev/test-only and never ships in the runtime image
#   (llm-service/Dockerfile only COPYs requirements.txt) — a compromised test
#   dependency can still execute arbitrary code on a developer machine or CI runner
#   during `mvn test`/`pytest`, which is exactly the moment this script runs.
#
# Image scanning (backlog item 44 REVISE, PR#27 review): images are scanned via
# `docker save` to a tarball under $SCAN_TMP_DIR, then `trivy image --input <tar>`.
# This intentionally avoids bind-mounting /var/run/docker.sock into the Trivy
# container — a full-control handle to the host Docker daemon is a supply-chain
# risk not worth taking for a script that runs routinely on every PR. This uses a
# temporary ~600MB of /tmp space per run (both images' tarballs together, roughly),
# cleaned up automatically by the EXIT trap on $SCAN_TMP_DIR.
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

# Pinned to the version that was current aquasec/trivy:latest as of 2026-08-30
# (backlog item 44 REVISE, PR#27 review — :latest silently drifts between runs).
# Override via TRIVY_IMAGE if a newer version needs to be picked up deliberately.
TRIVY_IMAGE="${TRIVY_IMAGE:-aquasec/trivy:0.74.0}"
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
# Reference timestamp used to detect a stale (un-rebuilt) image: the most recent
# commit that touched either dependency manifest. Computed once and reused for
# both images (backlog item 44 REVISE, PR#27 review point 1/2).
SOURCE_MANIFEST_COMMIT_TIME="$(git -C "$REPO_ROOT" log -1 --format=%cI -- backend/pom.xml llm-service/requirements.txt || true)"
SOURCE_MANIFEST_COMMIT_EPOCH=""
if [[ -n "$SOURCE_MANIFEST_COMMIT_TIME" ]]; then
  SOURCE_MANIFEST_COMMIT_EPOCH="$(date -d "$SOURCE_MANIFEST_COMMIT_TIME" +%s)"
fi

IMAGE_STALE_WARNINGS=()

# The staleness check above only looks at the last COMMIT time of either
# manifest — it has no way to see an uncommitted edit. If the manifest has
# been edited but not yet committed, the check can wrongly call an image
# "fresh" (or "stale") based on a commit timestamp that no longer reflects
# the manifest's actual current content (backlog item 63, PR#27 2nd review).
DIRTY_MANIFEST_STATUS="$(git -C "$REPO_ROOT" status --porcelain -- backend/pom.xml llm-service/requirements.txt || true)"
if [[ -n "$DIRTY_MANIFEST_STATUS" ]]; then
  DIRTY_MANIFEST_FILES="$(echo "$DIRTY_MANIFEST_STATUS" | awk '{print $2}' | paste -sd ', ' -)"
  MANIFEST_DIRTY_WARNING="WARNING: uncommitted changes detected in dependency manifest(s): $DIRTY_MANIFEST_FILES. The staleness check above is based on each manifest's last COMMIT time and cannot see uncommitted edits, so its verdict on the built images may be inaccurate. Commit the manifest change (or verify manually) before trusting the staleness warning (or its absence) for that image."
  log "$MANIFEST_DIRTY_WARNING"
  IMAGE_STALE_WARNINGS+=("$MANIFEST_DIRTY_WARNING")
fi

scan_image() {
  local image_name="$1" out_file="$2"
  if docker image inspect "$image_name" >/dev/null 2>&1; then
    log "Scanning image $image_name..."

    if [[ -n "$SOURCE_MANIFEST_COMMIT_EPOCH" ]]; then
      local image_created image_created_epoch
      image_created="$(docker image inspect "$image_name" --format '{{.Created}}')"
      image_created_epoch="$(date -d "$image_created" +%s)"
      if (( image_created_epoch < SOURCE_MANIFEST_COMMIT_EPOCH )); then
        local warning
        warning="WARNING: image $image_name was built at $image_created, which is OLDER than the last commit touching backend/pom.xml or llm-service/requirements.txt ($SOURCE_MANIFEST_COMMIT_TIME). Findings from this image may already be fixed in source. Run 'docker compose build' and re-run this script before treating this image's findings as actionable."
        log "$warning"
        IMAGE_STALE_WARNINGS+=("$warning")
      fi
    fi

    local sanitized tar_path
    sanitized="$(echo "$image_name" | tr '/:' '__')"
    tar_path="$SCAN_TMP_DIR/${sanitized}.tar"
    docker save "$image_name" -o "$tar_path"
    docker run --rm \
      -v "$TRIVY_CACHE_DIR:/root/.cache/" \
      -v "$SCAN_TMP_DIR:/scan:ro" \
      "$TRIVY_IMAGE" image --scanners vuln --format json --input "/scan/${sanitized}.tar" \
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

extract_findings() {
  # Flattens CRITICAL/HIGH vulnerabilities out of one or more Trivy JSON reports.
  # $1 = optional label prefix (e.g. "backend-image") to disambiguate Target
  # names that Trivy reports generically (e.g. embedded-jar findings inside an
  # image are just labelled "Java", not the image name — see backlog item 62,
  # PR#27 2nd review). Pass "" for source-manifest scans, where each input
  # already scans a distinct, unambiguous file path.
  local label="$1"
  shift
  jq -s --arg label "$label" '
    [ .[] | (.Results // [])[] | . as $r |
      ($r.Vulnerabilities // [])[] |
      select(.Severity == "CRITICAL" or .Severity == "HIGH") |
      {
        Target: (if $label != "" then ($label + ": " + $r.Target) else $r.Target end),
        VulnerabilityID: .VulnerabilityID,
        PkgName: .PkgName,
        InstalledVersion: .InstalledVersion,
        FixedVersion: (.FixedVersion // ""),
        Severity: .Severity,
        Title: (.Title // ""),
        PrimaryURL: (.PrimaryURL // "")
      }
    ] | unique
  ' "$@"
}

# Source-manifest findings (always as fresh as the current source tree) —
# these are the only findings ever formatted as a backlog candidate.
# requirements.json and requirements-dev.json are both scans of a file that
# Trivy sees as the same in-container path (/repo/requirements.txt — see the
# requirements-dev.txt handling note above for why the dev scan has to be
# named that way), so without a label they'd collide under the same .Target
# once grouped, silently fusing main-dependency and dev-only findings into
# one indistinguishable group (backlog item 66). pom.xml is a single,
# unambiguous file and stays unlabeled.
extract_findings "" "$SCAN_TMP_DIR/pom.json" \
  > "$SCAN_TMP_DIR/pom-findings.json"
extract_findings "requirements.txt" "$SCAN_TMP_DIR/requirements.json" \
  > "$SCAN_TMP_DIR/requirements-findings.json"
extract_findings "requirements-dev.txt" "$SCAN_TMP_DIR/requirements-dev.json" \
  > "$SCAN_TMP_DIR/requirements-dev-findings.json"
SOURCE_FLAT_JSON="$SCAN_TMP_DIR/source-findings.json"
jq -s 'add' "$SCAN_TMP_DIR/pom-findings.json" "$SCAN_TMP_DIR/requirements-findings.json" "$SCAN_TMP_DIR/requirements-dev-findings.json" \
  > "$SOURCE_FLAT_JSON"

# Built-image findings (may lag behind source — see header note + staleness
# warning above). Reference-only, never turned into a backlog candidate.
# Each image is extracted separately with its own label (backlog item 62,
# PR#27 2nd review) so that generic per-language Target names Trivy reports
# for embedded deps (e.g. "Java", "Python") don't collide across the two
# images once merged — without this, group_by(.Target) below would silently
# fuse backend and llm-service findings into one indistinguishable group.
extract_findings "backend-image" "$SCAN_TMP_DIR/backend-image.json" \
  > "$SCAN_TMP_DIR/backend-image-findings.json"
extract_findings "llm-service-image" "$SCAN_TMP_DIR/llm-service-image.json" \
  > "$SCAN_TMP_DIR/llm-service-image-findings.json"
IMAGE_FLAT_JSON="$SCAN_TMP_DIR/image-findings.json"
jq -s 'add' "$SCAN_TMP_DIR/backend-image-findings.json" "$SCAN_TMP_DIR/llm-service-image-findings.json" \
  > "$IMAGE_FLAT_JSON"

SOURCE_FIXABLE_JSON="$SCAN_TMP_DIR/source-fixable.json"
SOURCE_UNFIXABLE_JSON="$SCAN_TMP_DIR/source-unfixable.json"
jq '[.[] | select(.FixedVersion != "" and .FixedVersion != "-")]' "$SOURCE_FLAT_JSON" > "$SOURCE_FIXABLE_JSON"
jq '[.[] | select(.FixedVersion == "" or .FixedVersion == "-")]' "$SOURCE_FLAT_JSON" > "$SOURCE_UNFIXABLE_JSON"
SOURCE_FIXABLE_COUNT="$(jq 'length' "$SOURCE_FIXABLE_JSON")"
SOURCE_UNFIXABLE_COUNT="$(jq 'length' "$SOURCE_UNFIXABLE_JSON")"

IMAGE_FIXABLE_JSON="$SCAN_TMP_DIR/image-fixable.json"
IMAGE_UNFIXABLE_JSON="$SCAN_TMP_DIR/image-unfixable.json"
jq '[.[] | select(.FixedVersion != "" and .FixedVersion != "-")]' "$IMAGE_FLAT_JSON" > "$IMAGE_FIXABLE_JSON"
jq '[.[] | select(.FixedVersion == "" or .FixedVersion == "-")]' "$IMAGE_FLAT_JSON" > "$IMAGE_UNFIXABLE_JSON"
IMAGE_FIXABLE_COUNT="$(jq 'length' "$IMAGE_FIXABLE_JSON")"
IMAGE_UNFIXABLE_COUNT="$(jq 'length' "$IMAGE_UNFIXABLE_JSON")"

format_grouped_findings() {
  jq -r '
    group_by(.Target) | map(
      "  - **" + .[0].Target + "**\n" +
      (map("    - " + .Severity + " `" + .VulnerabilityID + "` " + .PkgName + " " + .InstalledVersion + " → " + .FixedVersion +
        (if .Title != "" then " — " + .Title else "" end)) | join("\n"))
    ) | join("\n")
  ' "$1"
}

SCAN_DATE="$(date -u +%Y-%m-%d)"

{
  echo "# Trivy scan findings — $SCAN_DATE"
  echo

  if [[ "${#IMAGE_STALE_WARNINGS[@]}" -gt 0 ]]; then
    echo "## ⚠ WARNING: built-image staleness verdict may not be trustworthy"
    echo
    for w in "${IMAGE_STALE_WARNINGS[@]}"; do
      echo "- $w"
    done
    echo
    echo "The \"built Docker images\" section below may reflect a stale build, or the staleness check itself may be unreliable (e.g. an uncommitted manifest edit). Do NOT treat its counts as accurate until you commit any pending manifest changes, rebuild (\`docker compose build\`), and re-run this script."
    echo
  fi

  echo "## ソースマニフェスト由来 (backend/pom.xml, llm-service/requirements.txt, requirements-dev.txt)"
  echo
  echo "常にソースツリーの最新状態を反映する。バックログ起票候補はこのセクションの内容のみから作成すること。"
  echo
  echo "Fixable (app-dependency, CRITICAL/HIGH, has FixedVersion): $SOURCE_FIXABLE_COUNT"
  echo "OS-layer / upstream-only (no FixedVersion, not actionable here): $SOURCE_UNFIXABLE_COUNT"
  echo
  if [[ "$SOURCE_FIXABLE_COUNT" -eq 0 ]]; then
    echo "No fixable CRITICAL/HIGH findings. Nothing to file."
  else
    echo "### Backlog candidate (paste into docs/spec/task-backlog.md ## OPEN after review)"
    echo
    echo "#### [NEW]. Trivyスキャンで検出されたCRITICAL/HIGH脆弱性(修正版あり、自動起票候補) [自動生成、要レビュー、$SCAN_DATE]"
    echo "- **状態**: OPEN"
    echo "- **背景**: \`scripts/run-trivy-scan.sh\`の自動実行($SCAN_DATE)で、ソースマニフェスト(pom.xml/requirements.txt/requirements-dev.txt)から以下のCRITICAL/HIGH脆弱性が検出された。いずれも\`FixedVersion\`が存在し、依存関係の更新で対応可能と判定されたもの(OS層・上流待ちの${SOURCE_UNFIXABLE_COUNT}件は対応不能のため除外済み、既存記録は項目47参照)。重複や既存バックログ項目との突き合わせは未実施——起票前に確認すること。"
    echo "$(format_grouped_findings "$SOURCE_FIXABLE_JSON")"
    echo "- **やること**: 該当ライブラリを記載の\`FixedVersion\`以上へ更新し、既存テストスイートで回帰が無いことを確認する。"
    echo "- **費用**: 無料(ライブラリ更新のみ、AI不使用)。"
  fi

  echo
  echo "## ビルド済みDockerイメージ由来(参考情報 — このセクションから直接バックログを起票しないこと)"
  echo
  echo "OS層・言語ランタイムに焼き込まれた依存関係を検出する(ソースマニフェストのスキャンだけでは見えないもの、backlog項目46参照)。ただしスキャン時点でのイメージの中身しか見ておらず、\`docker compose build\`が古いままだと、ソース側では既に修正済みの脆弱性を誤って含む。上のWARNINGが出ている場合は特に、再ビルド・再スキャンするまでこのセクションの件数を信用しないこと。"
  echo
  echo "Fixable (has FixedVersion): $IMAGE_FIXABLE_COUNT"
  echo "OS-layer / upstream-only (no FixedVersion): $IMAGE_UNFIXABLE_COUNT"
  echo
  if [[ "$IMAGE_FIXABLE_COUNT" -eq 0 && "$IMAGE_UNFIXABLE_COUNT" -eq 0 ]]; then
    echo "No CRITICAL/HIGH findings in the built images."
  else
    if [[ "$IMAGE_FIXABLE_COUNT" -gt 0 ]]; then
      echo "### Fixable (reference only)"
      echo
      echo "$(format_grouped_findings "$IMAGE_FIXABLE_JSON")"
      echo
    fi
    if [[ "$IMAGE_UNFIXABLE_COUNT" -gt 0 ]]; then
      echo "### OS-layer / upstream-only (reference only, see backlog item 47)"
      echo
      echo "$(format_grouped_findings "$IMAGE_UNFIXABLE_JSON")"
    fi
  fi
} > "$TRIVY_FINDINGS_FILE"

cat "$TRIVY_FINDINGS_FILE"
log "Report written to $TRIVY_FINDINGS_FILE"
