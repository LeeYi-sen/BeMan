#!/usr/bin/env bash
set -euo pipefail
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose); else COMPOSE=(docker-compose); fi
cd "$(dirname "$0")"
[[ $# -eq 1 && "$1" =~ ^video-[A-Za-z0-9-]+\.db$ ]] || { echo 'Usage: ./restore.sh video-YYYYMMDD-HHMMSS-xxxxxx.db'; exit 1; }
./stop.sh
"${COMPOSE[@]}" run --rm --no-deps backend python maintenance.py restore "/app/backups/$1" --offline
echo 'Restore complete; run ./start.sh.'
