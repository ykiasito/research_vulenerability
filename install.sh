#!/usr/bin/env bash
#
# install.sh — one-shot setup for this app (Spring Boot backend + PostgreSQL 16, all via
# Docker Compose; this closed-mode branch has no llm-service — the Python/FastAPI Claude
# LLM microservice used on other branches was fully removed here). Checks Docker, prepares
# .env with a freshly generated encryption key/DB password if one doesn't already exist,
# then builds and starts the stack. Safe to re-run: it never overwrites an existing .env.
#
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

info()  { printf '[install] %s\n' "$1"; }
error() { printf '[install] ERROR: %s\n' "$1" >&2; }

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
  error "curl が見つかりません。起動確認(4.)に必要です。導入してから再実行してください。"
  exit 1
fi

# --- 2. .env の用意(既存があれば絶対に上書きしない) ---
if [ -f .env ]; then
  info ".env は既に存在するため、そのまま使用します(上書きしません)。"
else
  if [ ! -f .env.example ]; then
    error ".env.example が見つかりません。リポジトリが壊れていないか確認してください。"
    exit 1
  fi

  info ".env が無いため、.env.example から新規作成します。"
  cp .env.example .env
  # 生成直後、鍵/パスワードを書き込む前に権限を絞る(この後の内容は他ユーザーに読ませてはいけない)。
  chmod 600 .env

  if ! command -v openssl >/dev/null 2>&1; then
    error "openssl が見つかりません。APP_SECRET_ENCRYPTION_KEY / POSTGRES_PASSWORD の自動生成に必要です。"
    error "openssl を導入するか、.env を手動編集して該当行を埋めてから再実行してください。"
    exit 1
  fi

  # APP_SECRET_ENCRYPTION_KEY: AES-256-GCM 用の32バイト鍵(base64)。手入力不要にするため自動生成。
  APP_SECRET_ENCRYPTION_KEY_VALUE="$(openssl rand -base64 32)"
  sed -i "s|^APP_SECRET_ENCRYPTION_KEY=.*|APP_SECRET_ENCRYPTION_KEY=${APP_SECRET_ENCRYPTION_KEY_VALUE}|" .env
  if ! grep -q '^APP_SECRET_ENCRYPTION_KEY=.\+' .env; then
    error "APP_SECRET_ENCRYPTION_KEY の書き込みに失敗しました。.env を手動編集して該当行を埋めてから再実行してください。"
    exit 1
  fi
  info "APP_SECRET_ENCRYPTION_KEY を自動生成しました。"

  # POSTGRES_PASSWORD: .env.example はプレースホルダ無しの空欄(コメントで openssl rand -base64 24 を
  # 例示)なので、同じ方式で自動生成する。
  POSTGRES_PASSWORD_VALUE="$(openssl rand -base64 24)"
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${POSTGRES_PASSWORD_VALUE}|" .env
  if ! grep -q '^POSTGRES_PASSWORD=.\+' .env; then
    error "POSTGRES_PASSWORD の書き込みに失敗しました。.env を手動編集して該当行を埋めてから再実行してください。"
    exit 1
  fi
  info "POSTGRES_PASSWORD を自動生成しました。"

  info ".env を新規作成しました(ADMIN_EMAIL 等、必要に応じて手動で編集してください)。"
fi

# --- 3. ビルド & 起動 ---
info "docker compose build を実行します(初回は数分かかります)..."
docker compose build

info "docker compose up -d を実行します..."
docker compose up -d

# --- 4. 起動確認(backend の /login にアクセスできるまで待機) ---
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
info "セットアップが完了しました。"
docker compose ps
echo
info "以下のURLからアクセスできます:"
info "  ${BACKEND_URL}"
