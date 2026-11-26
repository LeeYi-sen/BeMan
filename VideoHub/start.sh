#!/usr/bin/env bash
set -euo pipefail
if docker compose version >/dev/null 2>&1; then COMPOSE=(docker compose); else COMPOSE=(docker-compose); fi
cd "$(dirname "$0")"
if [[ ! -f .env ]]; then cp .env.example .env; chmod 600 .env; echo 'Set unique VIDEOHUB_API_KEY and VIDEOHUB_API_SECRET (32+ chars) in .env'; exit 1; fi
if ! grep -Eq '^VIDEOHUB_API_SECRET=.{32,}$' .env; then echo 'Set a strong API secret in .env'; exit 1; fi
mkdir -p data backups logs; chmod 700 data backups
"${COMPOSE[@]}" up -d --build
