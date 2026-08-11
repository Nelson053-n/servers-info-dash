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
    APP_DIR="$APP_DIR" "$APP_DIR/.venv/bin/python" - "$text" <<'PY' 2>/dev/null \
        || log "notify failed (Telegram unreachable or config unreadable)"
import os, sys, urllib.parse, urllib.request
from pathlib import Path

import yaml

cfg = yaml.safe_load(Path(os.environ["APP_DIR"], "config/servers.yaml").read_text())
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
    # Deadline by the clock, not by iteration count: a socket that
    # accepts but never answers (a wedged event loop — the failure this
    # health check exists for) would otherwise block a single iteration
    # indefinitely and blow systemd's TimeoutStartSec.
    local deadline=$((SECONDS + HEALTH_TIMEOUT))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if systemctl is-active --quiet "$SERVICE" \
            && curl -fsS --connect-timeout 3 --max-time 5 \
                "$HEALTH_URL" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

rollback() {
    # $1 — why the deploy is being undone, quoted into the alert.
    local reason="$1"
    local pip_output
    log "rolling back to ${local_sha:0:8} ($reason)"
    # An unchecked reset here would leave the tree on the bad commit
    # while the alert below claims recovery.
    if ! runuser -u "$APP_USER" -- git reset --hard "$local_sha" 2>&1; then
        log "rollback reset failed — tree still on ${remote_sha:0:8}"
        notify "🔥 <b>Откат не выполнен</b>
Коммит <code>${remote_sha:0:8}</code> не применён: ${reason}.
<code>git reset --hard ${local_sha:0:8}</code> завершился с ошибкой —
дерево осталось на сломанном коммите. Нужно вмешательство.
<code>journalctl -u ${SERVICE}</code>"
        exit 1
    fi

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

# systemd will not re-trigger a running oneshot, but a manual
# `systemctl start` or a hand-run script during a slow deploy would
# interleave two git resets in the same tree.
exec 9>"${LOCK_FILE:-/run/dash-autodeploy.lock}"
if ! flock -n 9; then
    log "another deploy is in progress, skipping this run"
    exit 0
fi

# TimeoutStartSec eventually sends SIGTERM, and it lands precisely when
# a deploy is slow — i.e. mid-recovery. Say so instead of dying mute.
trap 'log "interrupted by signal — deploy state may be inconsistent"
notify "⚠️ <b>Деплой прерван</b>
Скрипт остановлен сигналом (вероятно, TimeoutStartSec).
Состояние могло остаться несогласованным.
<code>journalctl -u ${SERVICE}</code>"
exit 1' TERM INT

if ! cd "$APP_DIR"; then
    log "cannot enter $APP_DIR"
    notify "⚠️ <b>Деплой не запустился</b>
Каталог <code>${APP_DIR}</code> недоступен."
    exit 1
fi

# git reset --hard runs as root below, so make sure this really is the
# dashboard checkout before mutating anything.
repo_root=$(runuser -u "$APP_USER" -- git rev-parse --show-toplevel 2>/dev/null)
if [ "$repo_root" != "$APP_DIR" ]; then
    log "$APP_DIR is not a git repository root (got '${repo_root}')"
    notify "⚠️ <b>Деплой остановлен</b>
<code>${APP_DIR}</code> не является корнем git-репозитория."
    exit 1
fi

if ! local_sha=$(runuser -u "$APP_USER" -- git rev-parse HEAD 2>&1); then
    log "git rev-parse failed: $local_sha"
    notify "⚠️ <b>Деплой не запустился</b>
<code>git rev-parse HEAD</code> завершился с ошибкой.
Возможна проблема с правами или safe.directory."
    exit 1
fi
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
