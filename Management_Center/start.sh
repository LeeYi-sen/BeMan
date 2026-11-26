#!/usr/bin/env bash
set -euo pipefail
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose); else COMPOSE=(docker-compose); fi
cd "$(dirname "$0")"
if [[ ! -f .env ]]; then cp .env.example .env; chmod 600 .env; echo 'Set MC_PASSWORD (12+), MC_MASTER_KEY (32+) in .env'; exit 1; fi
grep -Eq '^MC_PASSWORD=.{12,}$' .env && grep -Eq '^MC_MASTER_KEY=.{32,}$' .env || { echo 'Set strong credentials'; exit 1; }
mkdir -p data backups logs; chmod 700 data backups
"${COMPOSE[@]}" up -d --build
