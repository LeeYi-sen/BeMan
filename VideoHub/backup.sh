#!/usr/bin/env bash
set -euo pipefail
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose); else COMPOSE=(docker-compose); fi
cd "$(dirname "$0")"
"${COMPOSE[@]}" exec -T backend python maintenance.py backup
