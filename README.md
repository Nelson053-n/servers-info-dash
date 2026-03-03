# Servers Info Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=white" alt="Python 3.12+"/>
  <img src="https://img.shields.io/badge/FastAPI-0.116+-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT"/>
</p>

Real-time single-page dashboard for monitoring Linux servers over SSH.  
No agents on remote hosts — only a locked-down `monitor` user with read access to `/proc`.

---

## Features

| Category | Details |
|---|---|
| **Metrics** | CPU %, RAM (used / total GB), Disk (free / total GB + progress bar), Network RX / TX Mbps, 30-day traffic (RX+TX volume), Ping ms, Uptime days |
| **Local host** | Dashboard server metrics via `psutil` — no SSH needed |
| **SSH modes** | **Normal** (new connection each cycle) or **Persistent** (connection pool with keepalive & auto-reconnect) |
| **Telegram bot** | Down / CPU / Ping / Disk / RX / TX threshold alerts with configurable delay, recovery notifications, HTML-formatted messages |
| **Auth** | PBKDF2-SHA256 (600 k iter), IP/CIDR whitelist, IP-bound sessions (30-day expiry), brute-force protection (5 attempts → 30-min block), login history with geo-lookup |
| **Security** | CSRF Origin check, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`; X-Forwarded-For explicitly ignored |
| **Bootstrap** | Auto-create hardened `monitor` user via root SSH: `/bin/sh` shell, locked password, no sudo/wheel, `authorized_keys` with `no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty` |
| **SSH keys** | Generate ed25519 keys from UI, strict `known_hosts` verification, key-only auth, auto-cleanup on server delete |
| **CSV logging** | Daily per-server files, 30-day auto-rotation, download via UI, Unicode-safe filenames (RFC 5987) |
| **UI** | Dark / Light theme, 6 colour presets, RU / EN languages, sortable table, inline rename, responsive layout |

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/Nelson053-n/servers-info-dash.git
cd servers-info-dash
python -m venv .venv
```

Activate the virtual environment:

| OS | Command |
|---|---|
| Windows PowerShell | `.\.venv\Scripts\Activate.ps1` |
| Linux / macOS | `source .venv/bin/activate` |

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/servers.example.yaml config/servers.yaml
```

Edit `config/servers.yaml`:

```yaml
refresh_interval_sec: 10       # 1 – 300
persistent_ssh: false           # true = keep connections alive

ssh:
  known_hosts: ~/.ssh/known_hosts
  client_keys:
    - ~/.ssh/id_ed25519

servers:
  - name: my-server
    host: 10.0.0.1
    port: 22
    user: monitor
    interface: eth0             # optional, auto-detected if null

bot:                            # optional
  enabled: true
  token: "BOT_TOKEN"
  chat_id: "CHAT_ID"
  notify_down: true
  notify_cpu_threshold: 90
  notify_ping_threshold: null   # ms, off by default
  notify_disk_threshold: 95     # %
  notify_rx_threshold: null     # Mbps
  notify_tx_threshold: null     # Mbps
  notify_delay: 3               # consecutive cycles before alert
```

### 3. Run

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000**

---

## Adding a Server (Bootstrap)

Servers can be added directly from the UI. With **bootstrap** enabled:

1. Enter root (or sudo-capable) credentials — used once, never stored.
2. The app will:
   - Scan and save the host key to `known_hosts`
   - Create a `monitor` user with `/bin/sh`, locked password, no sudo/wheel
   - Generate an ed25519 key pair (or use existing)
   - Install the public key with SSH restrictions:  
     `no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty`
   - Remove any old unrestricted copy of the same key

After bootstrap all connections use **key-only auth**. The `monitor` user can only run non-interactive commands — tunnelling, forwarding, and PTY are blocked at the SSH level.

---

## Authentication

Set a password on the first visit via the **Security** panel (🔒 button).

| Feature | Details |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 600 000 iterations, 16-byte salt |
| Minimum length | 8 characters |
| Brute-force protection | 5 failed attempts → 30-minute IP block |
| Session | HttpOnly cookie, SameSite=Lax, bound to client IP, 30-day max age |
| IP whitelist | Optional CIDR / IP list (e.g. `192.168.1.0/24, 10.0.0.5`) |
| CSRF | Origin header validated for POST / PUT / PATCH / DELETE |
| Login history | Last 20 logins — IP, country (ip-api.com), User-Agent |
| Password change | Requires current password |
| Password reset | Delete `password_hash` from `config/auth.yaml` |

---

## How Metrics Work

All remote metrics are collected in a **single SSH command** per server per cycle.

| Metric | Remote source | Local source |
|---|---|---|
| CPU % | Delta of `/proc/stat` | `psutil.cpu_percent()` |
| RAM | `/proc/meminfo` (MemTotal − MemAvailable) | `psutil.virtual_memory()` |
| Disk | `df -B1 /` | `psutil.disk_usage("/")` |
| RX / TX | Delta of `/proc/net/dev` | `psutil.net_io_counters()` |
| Uptime | `/proc/uptime` | `psutil.boot_time()` |
| Ping | ICMP → TCP fallback | — |

> First cycle shows CPU / RX / TX as "—" (two data points needed for deltas).

**Error tolerance:** up to 5 consecutive SSH failures are absorbed using cached data before marking a server as DOWN.

**Network interface:** auto-detected (highest-traffic non-loopback) or user-specified.

### 30-day traffic column

- Source: per-server CSV logs in `logs/`, only files from last 30 days are included.
- Formula per log row: `((rx_mbps + tx_mbps) * interval_sec) / 8 / 1000` → GB.
- Final value: sum of all included rows for the server.
- Refresh: recalculated with a 5-minute backend cache.
- Display units in UI:
  - `< 1 GB` → `MB`
  - `1..1024 GB` → `GB`
  - `> 1024 GB` → `TB`

---

## SSH Modes

| Mode | Behaviour | Best for |
|---|---|---|
| **Normal** | New connection opened and closed each cycle | Long intervals (30 s+), many servers |
| **Persistent** | Pooled connections with `keepalive_interval=30`, auto-reconnect on failure | Short intervals (1–10 s), few servers |

Toggle via the **SSH** button in the toolbar. Both modes use public-key auth and strict `known_hosts`.

---

## Telegram Notifications

| Alert | Trigger | Recovery |
|---|---|---|
| Server DOWN | Status = down | "Server back UP" |
| CPU | ≥ threshold % | "CPU OK (current %)" |
| Ping | ≥ threshold ms | "Ping OK (current ms)" |
| Disk | ≥ threshold % used | "Disk OK (current %)" |
| RX | ≥ threshold Mbps | "RX OK (current Mbps)" |
| TX | ≥ threshold Mbps | "TX OK (current Mbps)" |

`notify_delay` prevents transient-spike alerts — the condition must persist for N consecutive cycles before firing.

---

## API Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Serve SPA |
| `GET` | `/api/metrics` | Cached server metrics |
| `GET` | `/api/logs/{name}` | Download CSV log |
| `POST` | `/api/servers` | Add server (+ optional bootstrap) |
| `DELETE` | `/api/servers/{name}` | Delete server (+ key cleanup) |
| `PATCH` | `/api/servers/{name}` | Rename server |
| `PUT` | `/api/interval` | Set refresh interval (1–300 s) |
| `PUT` | `/api/ssh_mode` | Toggle persistent / normal SSH |
| `GET` | `/api/bot` | Get bot config (token masked) |
| `PUT` | `/api/bot` | Update bot config |
| `GET` | `/api/auth/status` | Auth status |
| `POST` | `/api/auth/login` | Login |
| `POST` | `/api/auth/logout` | Logout |
| `GET` | `/api/auth/settings` | Auth settings + login history |
| `PUT` | `/api/auth/settings` | Update password / allowed networks |

---

## Project Structure

```
├── app/
│   ├── main.py               # FastAPI backend
│   └── static/
│       └── index.html         # Single-page frontend (vanilla JS, no build step)
├── config/
│   ├── servers.example.yaml   # Example config (safe to commit)
│   ├── key-info.template.yaml
│   ├── servers.yaml           # Your config (gitignored)
│   └── auth.yaml              # Auth state (gitignored)
├── logs/                      # CSV logs (gitignored, 30-day rotation)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Tech Stack

- **Backend:** Python 3.12+, FastAPI, uvicorn, asyncssh, psutil, PyYAML, pydantic v2
- **Frontend:** Vanilla HTML / CSS / JS — single file, no dependencies
- **Notifications:** Telegram Bot API

---

## License

MIT
