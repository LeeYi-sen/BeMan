#!/usr/bin/env bash
set -euo pipefail
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose); else COMPOSE=(docker-compose); fi
cd "$(dirname "$0")"
[[ $# -eq 1 && "$1" =~ ^management-[A-Za-z0-9-]+\.db$ ]] || exit 1
./stop.sh
"${COMPOSE[@]}" run --rm --no-deps web python maintenance.py restore "$1" --offline
