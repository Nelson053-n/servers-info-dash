# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Real-time server monitoring dashboard. Collects metrics from Linux servers over SSH (no remote agents), displays them in a single-page web UI, and sends Telegram alerts on threshold violations.

## Commands

```bash
# Run the app
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Run tests
pip install pytest httpx
pytest -q

# Syntax check
python -m py_compile app/main.py

# Validate example config
python -c "import yaml; from pathlib import Path; d=yaml.safe_load(Path('config/servers.example.yaml').read_text()); assert all(k in d for k in ['refresh_interval_sec','ssh','servers'])"
```

## Architecture

**Single-file backend** (`app/main.py`, ~2400 lines) — everything lives in one FastAPI module:

- **Pydantic models** (top): `AppConfig`, `ServerConfig`, `BotConfig`, `SSHSettings`, request/response models
- **`MetricsCollector` class**: core engine — collects metrics from all servers in parallel via `asyncio.gather`. Remote data fetched with a single SSH command per server per cycle (reads `/proc/stat`, `/proc/meminfo`, `/proc/net/dev`, `/proc/uptime`, `df`). CPU/network rates are delta-based (needs two samples). Supports normal (ephemeral connections) and persistent (pooled with keepalive) SSH modes via `asyncssh`
- **Auth system** (`_AuthState`, `_RateLimiter`): PBKDF2-SHA256 passwords, IP-bound sessions stored in `config/auth.yaml`, brute-force protection, CIDR whitelist, CSRF origin checking. Two middleware: `security_headers_middleware` and `auth_middleware`
- **Bootstrap flow** (`_bootstrap_monitor_user`): creates hardened `monitor` user on remote host via root SSH, installs ed25519 key with SSH restrictions
- **Telegram notifications** (`_check_and_notify`): threshold-based alerts with configurable delay (consecutive cycles), recovery messages
- **CSV logging**: per-server daily files in `logs/`, 30-day rotation, used for traffic volume calculations
- **Background collector** (`_background_collector`): runs in a loop at `refresh_interval_sec`, triggers metrics collection, logging, and notifications

**Single-file frontend** (`app/static/index.html`) — vanilla JS SPA, no build step. Dark/light themes, RU/EN i18n, sortable table.

## Config Files

- `config/servers.yaml` — main runtime config (gitignored, contains server IPs/credentials)
- `config/auth.yaml` — auth state: password hash, sessions, login history (gitignored)
- `config/servers.example.yaml` — safe example, committed and validated in CI

## CI/CD

GitHub Actions (`.github/workflows/deploy.yml`): on push to `main` — syntax check, config validation, pytest → SSH deploy to `/opt/servers-info-dash`, systemd restart with health check.

## Key Design Decisions

- All remote metrics collected in a **single SSH command** per server (not multiple connections)
- Error tolerance: up to 5 consecutive SSH failures use cached data before marking server DOWN
- Network interface auto-detection (highest-traffic non-loopback) when not specified
- Bot token can be provided via `TELEGRAM_BOT_TOKEN` env var (overrides config)
- `X-Forwarded-For` is explicitly ignored (direct client IP only)
- SSH `known_hosts` is strictly required — no auto-accept of host keys
