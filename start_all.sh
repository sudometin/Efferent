#!/bin/bash
# One command: fresh Cloudflare tunnel → writes WEBAPP_URL into .env → starts the bot.
# Ctrl+C stops both.
cd "$(dirname "$0")"
PORT=$(grep ^WEBAPP_PORT .env 2>/dev/null | cut -d= -f2 | tr -d ' "'); PORT=${PORT:-8088}
LOG=/tmp/efferent-tunnel.log

command -v cloudflared >/dev/null || { echo "✕ cloudflared missing → brew install cloudflared"; exit 1; }
pkill -f "cloudflared tunnel --url http://localhost:$PORT" 2>/dev/null
lsof -ti tcp:$PORT -sTCP:LISTEN | xargs kill 2>/dev/null   # old bot still holding the port
sleep 1

echo "[    ] opening tunnel…"
cloudflared tunnel --url "http://localhost:$PORT" --protocol http2 > "$LOG" 2>&1 &
CF=$!
trap 'kill $CF 2>/dev/null' EXIT

URL=""
for i in $(seq 1 40); do
  URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG" | head -1)
  [ -n "$URL" ] && grep -q "Registered tunnel connection" "$LOG" && break
  sleep 1
done
if [ -z "$URL" ]; then
  echo "✕ tunnel didn't come up (VPN on? try toggling it). log:"; tail -20 "$LOG"; exit 1
fi

if grep -q ^WEBAPP_URL= .env; then
  sed -i '' "s|^WEBAPP_URL=.*|WEBAPP_URL=$URL|" .env
else
  echo "WEBAPP_URL=$URL" >> .env
fi
echo "[ OK ] tunnel  $URL"
echo "[ OK ] .env updated · starting bot…"
./run_mac.sh
