#!/bin/bash
# Pull-based deploy: the host fetches from GitHub instead of GitHub
# reaching in over SSH. Runs as root via dash-autodeploy.timer.
set -uo pipefail

# Overridable so the deploy path can be exercised by tests without
# touching a real install; production uses the defaults.
APP_DIR=${APP_DIR:-/opt/servers-info-dash}
APP_USER=${APP_USER:-serversdash}
SERVICE=${SERVICE:-servers-info-dash.service}
HEALTH_URL=${HEALTH_URL:-http://127.0.0.1:8000/api/health}
HEALTH_TIMEOUT=${HEALTH_TIMEOUT:-90}

log() { echo "$*"; }

notify() {
    # Telegram alert on failures only; credentials stay in the app config
    local text="$1"
    "$APP_DIR/.venv/bin/python" - "$text" <<'PY' 2>/dev/null || true
import json, sys, urllib.parse, urllib.request
from pathlib import Path

import yaml

cfg = yaml.safe_load(Path("/opt/servers-info-dash/config/servers.yaml").read_text())
bot = (cfg or {}).get("bot") or {}
token, chat_id = bot.get("token"), bot.get("chat_id")
if not (bot.get("enabled") and token and chat_id):
    sys.exit(0)
payload = urllib.parse.urlencode({
    "chat_id": str(chat_id),
    "text": sys.argv[1],
    "parse_mode": "HTML",
}).encode()
req = urllib.request.Request(
    f"https://api.telegram.org/bot{token}/sendMessage", data=payload
)
urllib.request.urlopen(req, timeout=10).read()
PY
}

wait_healthy() {
    for _ in $(seq 1 "$HEALTH_TIMEOUT"); do
        if systemctl is-active --quiet "$SERVICE" \
            && curl -fsS "$HEALTH_URL" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

rollback() {
    # $1 — why the deploy is being undone, quoted into the alert.
    local reason="$1"
    log "rolling back to ${local_sha:0:8} ($reason)"
    runuser -u "$APP_USER" -- git reset --hard "$local_sha" 2>&1

    local pip_ok=1
    if ! pip_output=$(runuser -u "$APP_USER" -- \
        "$APP_DIR/.venv/bin/pip" install -r requirements.txt 2>&1); then
        pip_ok=0
        log "pip install failed during rollback:"
        log "$pip_output"
    fi
    systemctl restart "$SERVICE"

    if [ "$pip_ok" -eq 1 ] && wait_healthy; then
        notify "🔄 <b>Откат после неудачного деплоя</b>
Коммит <code>${remote_sha:0:8}</code> не применён: ${reason}.
Вернулись на <code>${local_sha:0:8}</code>, дашборд работает."
    else
        notify "🔥 <b>Дашборд не поднялся</b>
Коммит <code>${remote_sha:0:8}</code> не применён: ${reason}.
Откат на <code>${local_sha:0:8}</code> тоже не помог — нужно вмешательство.
<code>journalctl -u ${SERVICE}</code>"
    fi
    exit 1
}

cd "$APP_DIR" || exit 1

local_sha=$(runuser -u "$APP_USER" -- git rev-parse HEAD 2>/dev/null) || exit 1
remote_sha=$(runuser -u "$APP_USER" -- git ls-remote origin refs/heads/main 2>/dev/null \
    | cut -f1)

if [ -z "$remote_sha" ]; then
    log "cannot reach origin, skipping this run"
    exit 0
fi
if [ "$local_sha" = "$remote_sha" ]; then
    exit 0
fi

log "deploying ${local_sha:0:8} -> ${remote_sha:0:8}"

if ! runuser -u "$APP_USER" -- git fetch origin main 2>&1; then
    log "fetch failed"
    notify $'⚠️ <b>Деплой не удался</b>\ngit fetch завершился с ошибкой'
    exit 1
fi
runuser -u "$APP_USER" -- git reset --hard "$remote_sha" 2>&1 || {
    log "reset failed"
    notify $'⚠️ <b>Деплой не удался</b>\ngit reset завершился с ошибкой'
    exit 1
}

if ! pip_output=$(runuser -u "$APP_USER" -- \
    "$APP_DIR/.venv/bin/pip" install -r requirements.txt 2>&1); then
    # Restarting now would run the new code against a half-installed
    # venv, so roll back without touching the running service first.
    log "pip install failed:"
    log "$pip_output"
    rollback "pip install не удался"
fi
systemctl restart "$SERVICE"

if wait_healthy; then
    log "deploy OK: now on ${remote_sha:0:8}"
    exit 0
fi

rollback "health-check не прошёл"
exit 1
