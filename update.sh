#!/usr/bin/env bash
#
# update.sh — update an already-installed environment of this app (Spring Boot backend +
# FastAPI llm-service + PostgreSQL 16, all via Docker Compose) to the latest code. Unlike
# install.sh (first-time setup), this script assumes .env already exists and never touches
# it. It pulls the latest code via git, rebuilds the images, and restarts the stack.
# PostgreSQL data lives in a named volume, so recreating containers does not lose data.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

info()  { printf '[update] %s\n' "$1"; }
error() { printf '[update] ERROR: %s\n' "$1" >&2; }

# --- 1. Docker / Docker Compose availability ---
if ! command -v docker >/dev/null 2>&1; then
  error "Docker が見つかりません。https://docs.docker.com/get-docker/ を参照してインストールしてください。"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  error "'docker compose' サブコマンドが使えません。Docker Compose v2 (Docker Desktop 同梱、または docker-compose-plugin) を導入してください。"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  error "Docker デーモンに接続できません。Docker が起動しているか確認してください。"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  error "curl が見つかりません。起動確認(5.)に必要です。導入してから再実行してください。"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  error "git が見つかりません。コードの更新に必要です。導入してから再実行してください。"
  exit 1
fi

# --- 2. .env の存在確認(update はインストール済み環境が前提) ---
if [ ! -f .env ]; then
  error ".env が見つかりません。このスクリプトは初回セットアップ済みの環境を更新するためのものです。"
  error "先に install.sh を実行してセットアップを完了してください。"
  exit 1
fi

# --- 3. git で最新化(未コミットの変更があれば安全に中断) ---
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  error "このディレクトリは git リポジトリではありません。git 管理下のリポジトリから実行してください。"
  exit 1
fi

if [ -n "$(git status --porcelain)" ]; then
  error "ローカルに未コミットの変更があるため中断します。変更を退避(stash/commit)してから再実行してください。"
  exit 1
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"
info "git pull を実行します(現在のブランチ: ${CURRENT_BRANCH})..."
if ! git pull; then
  error "git pull に失敗しました。リモートとの競合やネットワーク状況を確認してください。"
  exit 1
fi

# --- 4. リビルド & 再起動 ---
info "docker compose build を実行します(コードの変更量によっては数分かかります)..."
docker compose build

info "docker compose up -d を実行します..."
info "PostgreSQL のデータは名前付きボリュームに保存されているため、コンテナを再作成してもデータは失われません。"
docker compose up -d

# --- 5. 起動確認(backend の /login にアクセスできるまで待機) ---
info "backend の起動を確認しています..."
BACKEND_URL="http://localhost:8080/login"
READY=0
for _ in $(seq 1 30); do
  if curl -sf -o /dev/null "$BACKEND_URL"; then
    READY=1
    break
  fi
  sleep 2
done

if [ "$READY" -ne 1 ]; then
  error "backend (${BACKEND_URL}) に接続できませんでした。'docker compose ps' や 'docker compose logs backend' でログを確認してください。"
  exit 1
fi

echo
info "更新が完了しました。"
docker compose ps
echo
info "以下のURLからアクセスできます:"
info "  ${BACKEND_URL}"
