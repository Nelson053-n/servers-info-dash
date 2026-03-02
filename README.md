# Servers Info Dashboard

<p align="center">
  <img src="https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=white" alt="Python 3.12+"/>
  <img src="https://img.shields.io/badge/FastAPI-0.116+-009688?logo=fastapi&logoColor=white" alt="FastAPI"/>
  <img src="https://img.shields.io/badge/license-MIT-green" alt="MIT"/>
</p>

Real-time single-page dashboard for monitoring multiple Linux servers via SSH.  
No agents needed on remote hosts — only an SSH user with read access to `/proc`.

---

## Features

| Category | Details |
|---|---|
| **Metrics** | CPU %, RAM (used / total GB), Disk (used / total GB + progress bar), Network RX/TX Mbps, Ping ms, Uptime (days) |
| **Local host** | Dashboard server metrics via `psutil` — no SSH needed |
| **Telegram bot** | Alerts for: server down, CPU / ping / disk / RX / TX thresholds with configurable delay and recovery notifications |
| **Auth system** | Password login (PBKDF2-SHA256, 600k iterations), IP/subnet whitelist, session binding to IP, brute-force protection (5 attempts → 30 min block), login history with geo-lookup |
| **Security headers** | `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, CSRF Origin check, `Referrer-Policy`, `Permissions-Policy` |
| **CSV logging** | Daily per-server CSV files, auto-rotation (30 days), download via UI |
| **Server management** | Add / rename / delete servers from UI, auto-bootstrap `monitor` user via SSH (key generation + `authorized_keys` setup) |
| **SSH keys** | Generate ed25519 keys from UI, `known_hosts` strict verification, key-only auth (passwords disabled) |
| **UI** | Dark / Light theme, 6 color presets, RU / EN languages, sortable table, inline rename, responsive layout |

## Screenshots

> Add your screenshots here.

---

## Quick Start

### 1. Clone & install

```bash
git clone https://github.com/Nelson053-n/servers-info-dash.git
cd servers-info-dash
python -m venv .venv
```

Activate the virtual environment:

- **Windows PowerShell:** `.\.venv\Scripts\Activate.ps1`
- **Linux / macOS:** `source .venv/bin/activate`

```bash
pip install -r requirements.txt
```

### 2. Configure

```bash
cp config/servers.example.yaml config/servers.yaml
```

Edit `config/servers.yaml`:

```yaml
ssh:
  known_hosts: ~/.ssh/known_hosts
  client_keys:
    - ~/.ssh/id_ed25519

servers:
  - name: my-server
    host: 10.0.0.1
    port: 22
    user: monitor
    interface: eth0        # optional, auto-detected if null

bot:                        # optional
  enabled: true
  token: "BOT_TOKEN"
  chat_id: "CHAT_ID"
  notify_down: true
  notify_cpu_threshold: 90
  notify_delay: 3           # checks before alert
```

### 3. Run

```bash
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open **http://localhost:8000**

---

## Adding a Server (Bootstrap)

You can add servers directly from the UI. With **bootstrap** enabled:

1. Enter root/admin credentials (used once, not stored)
2. The app will:
   - Create a `monitor` user (locked, no sudo)
   - Generate an ed25519 SSH key pair (or use existing)
   - Install the public key into `~monitor/.ssh/authorized_keys`
   - Add the host to `known_hosts`

After bootstrap, all connections use **key-only authentication**.

---

## Authentication

Set a password on the first visit via the **Security** panel.

| Feature | Details |
|---|---|
| Password hashing | PBKDF2-HMAC-SHA256, 600 000 iterations |
| Brute-force protection | 5 failed attempts → 30-minute IP block |
| Session | Cookie (`HttpOnly`, `SameSite=Lax`), bound to client IP, 30-day expiry |
| IP whitelist | Optional CIDR/IP filtering (e.g. `192.168.1.0/24, 10.0.0.5`) |
| Login history | Last 20 logins with IP, country (via ip-api.com), User-Agent |
| Password reset | Delete `password_hash` in `config/auth.yaml` |

---

## How Metrics Work

| Metric | Source (remote) | Source (local) |
|---|---|---|
| CPU % | Delta of `/proc/stat` between polls | `psutil.cpu_percent()` |
| RAM | `/proc/meminfo` (MemTotal − MemAvailable) | `psutil.virtual_memory()` |
| Disk | `df -B1 /` | `psutil.disk_usage("/")` |
| RX / TX | Delta of `/proc/net/dev` between polls | `psutil.net_io_counters()` |
| Uptime | `/proc/uptime` | `psutil.boot_time()` |
| Ping | ICMP ping (fallback: TCP handshake) | — |

> First cycle after start shows CPU / RX / TX as "—" (two data points needed for delta calculation).

**Error tolerance:** Up to 5 consecutive SSH failures are absorbed using cached data before marking a server as "down".

---

## Project Structure

```
├── app/
│   ├── main.py              # FastAPI backend (metrics, auth, API, notifications)
│   └── static/
│       └── index.html        # Single-page frontend (vanilla JS)
├── config/
│   ├── servers.example.yaml  # Example config (safe to commit)
│   ├── key-info.template.yaml
│   ├── servers.yaml          # Your config (gitignored)
│   └── auth.yaml             # Auth state (gitignored)
├── logs/                     # CSV metrics logs (gitignored)
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Tech Stack

- **Backend:** Python 3.12+, FastAPI, uvicorn, asyncssh, psutil, PyYAML, pydantic v2
- **Frontend:** Vanilla HTML/CSS/JS (no build step)
- **Notifications:** Telegram Bot API

---

## License

MIT
