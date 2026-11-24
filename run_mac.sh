#!/usr/bin/env bash
# Local runner for macOS/Linux: loads .env, keeps the venv in sync with requirements.txt, starts the bot.
set -e
cd "$(dirname "$0")"
[ -f .env ] || { echo "no .env · run: cp .env.example .env  then fill it in"; exit 1; }
[ -d .venv ] || python3 -m venv .venv
REQ_HASH=$(shasum requirements.txt | cut -d' ' -f1)
if [ "$(cat .venv/.req 2>/dev/null)" != "$REQ_HASH" ]; then
  echo "[....] installing dependencies"
  .venv/bin/pip install -q --upgrade pip
  .venv/bin/pip install -q -r requirements.txt
  echo "$REQ_HASH" > .venv/.req
fi
set -a; source .env; set +a
export DATA_DIR="${DATA_DIR:-./data}"
exec .venv/bin/python -m nullbyte
