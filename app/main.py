import asyncio
import csv
import datetime as dt
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import platform
import re
import secrets
import shlex
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from threading import Lock
from typing import Any

import asyncssh
import psutil
import yaml
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import (
    FileResponse,
    JSONResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

logger = logging.getLogger("serverinfo")


class SSHSettings(BaseModel):
    known_hosts: str = "~/.ssh/known_hosts"
    client_keys: list[str] | None = None
    connect_timeout: float = 5.0
    command_timeout: float = 6.0

    @model_validator(mode="after")
    def validate_known_hosts(self) -> "SSHSettings":
        if not self.known_hosts:
            raise ValueError(
                "ssh.known_hosts must be set for strict host verification"
            )
        return self


class ServerConfig(BaseModel):
    name: str
    host: str
    port: int = 22
    user: str
    interface: str | None = None
    client_key: str | None = None
    country: str | None = None


class BotConfig(BaseModel):
    enabled: bool = False
    token: str = ""
    chat_id: str = ""
    notify_down: bool = True
    notify_cpu_threshold: float | None = 90.0
    notify_ping_threshold: float | None = None
    notify_disk_threshold: float | None = 95.0
    notify_rx_threshold: float | None = None
    notify_tx_threshold: float | None = None
    notify_delay: int = 1


class AppConfig(BaseModel):
    refresh_interval_sec: int = Field(default=5, ge=1, le=300)
    persistent_ssh: bool = False
    ssh: SSHSettings = Field(default_factory=SSHSettings)
    servers: list[ServerConfig]
    bot: BotConfig = Field(default_factory=BotConfig)


class AddServerRequest(BaseModel):
    name: str = Field(max_length=100)
    host: str = Field(max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    user: str = Field(max_length=32)
    interface: str | None = Field(default=None, max_length=50)
    client_key: str | None = Field(default=None, max_length=500)
    country: str | None = Field(default=None, max_length=2)
    bootstrap_with_root: bool = False
    root_user: str | None = Field(default=None, max_length=32)
    root_password: str | None = Field(default=None, max_length=200)
    public_key: str | None = Field(default=None, max_length=2000)
    generate_key: bool = False


@dataclass
class PreviousSample:
    cpu_total: int
    cpu_idle: int
    rx_bytes: int
    tx_bytes: int
    at: float


class MetricsCollector:
    _PING_INTERVAL: float = 30.0  # seconds between ping measurements

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self._previous: dict[str, PreviousSample] = {}
        self._error_counts: dict[str, int] = {}
        self._last_good: dict[str, dict[str, Any]] = {}
        self._error_threshold: int = 5
        self._pool: dict[str, asyncssh.SSHClientConnection] = {}
        self._pool_lock = asyncio.Lock()
        self._ping_cache: dict[str, float] = {}
        self._ping_last_time: dict[str, float] = {}

    async def collect_all(self) -> dict[str, Any]:
        tasks = [self.collect_server(server) for server in self.cfg.servers]
        servers = await asyncio.gather(*tasks)
        local = await self._collect_local()
        servers.insert(0, local)
        return {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "refresh_interval_sec": self.cfg.refresh_interval_sec,
            "persistent_ssh": self.cfg.persistent_ssh,
            "servers": servers,
        }

    async def _get_ping(self, server: ServerConfig) -> float | None:
        """Return cached ping or measure a new one (at most once per _PING_INTERVAL)."""
        now = asyncio.get_running_loop().time()
        last = self._ping_last_time.get(server.name, 0.0)
        if now - last < self._PING_INTERVAL and server.name in self._ping_cache:
            return self._ping_cache[server.name]

        ping_ms = await self._ping(server.host)
        if ping_ms is None:
            ping_ms = await self._tcp_ping(server.host, server.port)

        if ping_ms is not None:
            self._ping_cache[server.name] = ping_ms
            self._ping_last_time[server.name] = now
        else:
            # keep previous value if available
            ping_ms = self._ping_cache.get(server.name)

        return ping_ms

    async def collect_server(self, server: ServerConfig) -> dict[str, Any]:
        ping_ms = await self._get_ping(server)

        base = {
            "name": server.name,
            "host": server.host,
            "country": server.country,
            "ping_ms": ping_ms,
            "cpu_percent": None,
            "ram_used_gb": None,
            "ram_total_gb": None,
            "uptime_days": None,
            "rx_mbps": None,
            "tx_mbps": None,
            "disk_free_gb": None,
            "disk_total_gb": None,
            "interface": server.interface,
            "status": "down",
            "error": None,
        }

        try:
            snapshot = await self._fetch_remote_snapshot(server)
            now = asyncio.get_running_loop().time()
            cpu_percent, rx_mbps, tx_mbps, iface = self._calculate_rates(
                server.name,
                snapshot,
                now,
            )
            base.update(
                {
                    "cpu_percent": cpu_percent,
                    "ram_used_gb": snapshot.get("ram_used_gb"),
                    "ram_total_gb": snapshot.get("ram_total_gb"),
                    "uptime_days": snapshot.get("uptime_days"),
                    "rx_mbps": rx_mbps,
                    "tx_mbps": tx_mbps,
                    "disk_free_gb": snapshot.get("disk_free_gb"),
                    "disk_total_gb": snapshot.get("disk_total_gb"),
                    "interface": iface,
                    "status": "up",
                }
            )
        except Exception as exc:  # noqa: BLE001
            self._error_counts[server.name] = (
                self._error_counts.get(server.name, 0) + 1
            )
            count = self._error_counts[server.name]
            if count < self._error_threshold:
                cached = self._last_good.get(server.name)
                if cached:
                    cached["ping_ms"] = ping_ms
                    return cached
            base["error"] = str(exc)
            return base

        self._error_counts[server.name] = 0
        self._last_good[server.name] = dict(base)
        return base

    async def _collect_local(self) -> dict[str, Any]:
        """Collect metrics from the local host (dashboard server)."""
        loop = asyncio.get_running_loop()
        try:
            cpu = await loop.run_in_executor(
                None, lambda: psutil.cpu_percent(interval=0.3),
            )
            disk = psutil.disk_usage("/")
            mem = psutil.virtual_memory()
            boot = psutil.boot_time()
            uptime_sec = (
                dt.datetime.now().timestamp() - boot
            )
            net = psutil.net_io_counters()
            now = loop.time()
            rx_bytes = net.bytes_recv
            tx_bytes = net.bytes_sent
            rx_mbps = None
            tx_mbps = None
            prev = self._previous.get("__local__")
            self._previous["__local__"] = PreviousSample(
                cpu_total=0,
                cpu_idle=0,
                rx_bytes=rx_bytes,
                tx_bytes=tx_bytes,
                at=now,
            )
            if prev is not None:
                dt_sec = max(now - prev.at, 1e-6)
                rx_d = max(rx_bytes - prev.rx_bytes, 0)
                tx_d = max(tx_bytes - prev.tx_bytes, 0)
                rx_mbps = round(rx_d * 8 / dt_sec / 1e6, 3)
                tx_mbps = round(tx_d * 8 / dt_sec / 1e6, 3)
            return {
                "name": "Server Info",
                "host": platform.node(),
                "country": None,
                "ping_ms": 0.0,
                "cpu_percent": round(cpu, 2),
                "ram_used_gb": round(
                    mem.used / 1_073_741_824, 1,
                ),
                "ram_total_gb": round(
                    mem.total / 1_073_741_824, 1,
                ),
                "uptime_days": round(
                    uptime_sec / 86400, 1,
                ),
                "rx_mbps": rx_mbps,
                "tx_mbps": tx_mbps,
                "disk_free_gb": round(
                    disk.free / 1_073_741_824, 1,
                ),
                "disk_total_gb": round(
                    disk.total / 1_073_741_824, 1,
                ),
                "interface": "local",
                "status": "up",
                "error": None,
                "is_local": True,
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "name": "Server Info",
                "host": platform.node(),
                "country": None,
                "ping_ms": None,
                "cpu_percent": None,
                "ram_used_gb": None,
                "ram_total_gb": None,
                "uptime_days": None,
                "rx_mbps": None,
                "tx_mbps": None,
                "disk_free_gb": None,
                "disk_total_gb": None,
                "interface": "local",
                "status": "down",
                "error": str(exc),
                "is_local": True,
            }

    async def _ping(self, host: str) -> float | None:
        if platform.system().lower().startswith("win"):
            command = ["ping", "-n", "1", "-w", "1200", host]
        else:
            command = ["ping", "-c", "1", "-W", "1", host]

        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        out = stdout.decode(errors="ignore")

        patterns = [
            r"time[=<]\s*([\d.]+)\s*ms",
            r"время[=<]\s*([\d.]+)\s*мс",
            r"Average\s*=\s*([\d.]+)ms",
            r"Среднее\s*=\s*([\d.]+)мс",
        ]
        for pattern in patterns:
            match = re.search(pattern, out, flags=re.IGNORECASE)
            if match:
                return float(match.group(1))

        return None

    async def _tcp_ping(self, host: str, port: int) -> float | None:
        loop = asyncio.get_running_loop()
        started = loop.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host=host, port=port),
                timeout=1.5,
            )
            _ = reader
            latency_ms = (loop.time() - started) * 1000
            writer.close()
            await writer.wait_closed()
            return round(latency_ms, 1)
        except Exception:  # noqa: BLE001
            return None

    async def _get_connection(
        self,
        server: ServerConfig,
    ) -> asyncssh.SSHClientConnection:
        """Get or create a persistent SSH connection."""
        key = f"{server.host}:{server.port}:{server.user}"
        async with self._pool_lock:
            conn = self._pool.get(key)
            if conn is not None:
                # Check if connection is still alive
                try:
                    # Run a trivial command to verify
                    await asyncio.wait_for(
                        conn.run("echo ok", check=True),
                        timeout=3.0,
                    )
                    return conn
                except Exception:  # noqa: BLE001
                    try:
                        conn.close()
                        await conn.wait_closed()
                    except Exception:  # noqa: BLE001
                        pass
                    self._pool.pop(key, None)

            known_hosts = str(
                Path(self.cfg.ssh.known_hosts).expanduser(),
            )
            client_keys = self._resolve_client_keys(server)
            conn = await asyncssh.connect(
                host=server.host,
                port=server.port,
                username=server.user,
                known_hosts=known_hosts,
                client_keys=client_keys,
                preferred_auth=["publickey"],
                password=None,
                connect_timeout=self.cfg.ssh.connect_timeout,
                keepalive_interval=30,
                keepalive_count_max=3,
            )
            self._pool[key] = conn
            return conn

    async def close_pool(self) -> None:
        """Close all persistent SSH connections."""
        async with self._pool_lock:
            for key, conn in list(self._pool.items()):
                try:
                    conn.close()
                    await conn.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            self._pool.clear()

    async def _run_ssh_command(
        self,
        server: ServerConfig,
        command: str,
    ) -> str:
        """Run command via persistent or one-shot SSH."""
        if self.cfg.persistent_ssh:
            conn = await self._get_connection(server)
            result = await asyncio.wait_for(
                conn.run(command, check=True),
                timeout=self.cfg.ssh.command_timeout,
            )
            return self._normalize_output(result.stdout)

        # One-shot connection (original behavior)
        known_hosts = str(
            Path(self.cfg.ssh.known_hosts).expanduser(),
        )
        client_keys = self._resolve_client_keys(server)
        async with asyncssh.connect(
            host=server.host,
            port=server.port,
            username=server.user,
            known_hosts=known_hosts,
            client_keys=client_keys,
            preferred_auth=["publickey"],
            password=None,
            connect_timeout=self.cfg.ssh.connect_timeout,
        ) as conn:
            result = await asyncio.wait_for(
                conn.run(command, check=True),
                timeout=self.cfg.ssh.command_timeout,
            )
            return self._normalize_output(result.stdout)

    async def _fetch_remote_snapshot(
        self,
        server: ServerConfig,
    ) -> dict[str, Any]:
        command = (
            "LANG=C head -n 1 /proc/stat; "
            "cat /proc/net/dev; "
            "echo '---DF---'; "
            "df -B1 --output=avail,size / 2>/dev/null "
            "|| df -k / 2>/dev/null; "
            "echo '---MEM---'; "
            "head -n 3 /proc/meminfo; "
            "echo '---UPTIME---'; "
            "cat /proc/uptime"
        )

        stdout = await self._run_ssh_command(server, command)
        cpu_total, cpu_idle = self._parse_cpu_line(stdout)
        iface, rx_bytes, tx_bytes = self._parse_net_dev(
            stdout,
            server.interface,
        )
        disk_free, disk_total = self._parse_df(stdout)
        ram_used, ram_total = self._parse_meminfo(stdout)
        uptime_days = self._parse_uptime(stdout)
        return {
            "cpu_total": cpu_total,
            "cpu_idle": cpu_idle,
            "iface": iface,
            "rx_bytes": rx_bytes,
            "tx_bytes": tx_bytes,
            "disk_free_gb": disk_free,
            "disk_total_gb": disk_total,
            "ram_used_gb": ram_used,
            "ram_total_gb": ram_total,
            "uptime_days": uptime_days,
        }

    def _resolve_client_keys(self, server: ServerConfig) -> list[str] | None:
        if server.client_key:
            if _is_key_fingerprint(server.client_key):
                raise RuntimeError(
                    "client_key must be key file path, not fingerprint"
                )
            return [str(Path(server.client_key).expanduser())]

        if not self.cfg.ssh.client_keys:
            return None

        return [
            str(Path(item).expanduser())
            for item in self.cfg.ssh.client_keys
        ]

    @staticmethod
    def _normalize_output(output: Any) -> str:
        if output is None:
            raise RuntimeError("Empty command output")
        if isinstance(output, str):
            return output
        if isinstance(output, (bytes, bytearray)):
            return output.decode(errors="ignore")
        return str(output)

    @staticmethod
    def _parse_cpu_line(output: str) -> tuple[int, int]:
        first_line = output.splitlines()[0].strip()
        parts = first_line.split()
        if len(parts) < 6 or parts[0] != "cpu":
            raise RuntimeError("Invalid /proc/stat format")

        values = [int(item) for item in parts[1:9]]
        cpu_total = sum(values)
        cpu_idle = values[3] + values[4]
        return cpu_total, cpu_idle

    @staticmethod
    def _parse_net_dev(
        output: str,
        preferred_iface: str | None,
    ) -> tuple[str, int, int]:
        lines = output.splitlines()
        candidates: list[tuple[str, int, int]] = []

        for line in lines:
            if ":" not in line:
                continue
            iface_raw, counters_raw = line.split(":", maxsplit=1)
            iface = iface_raw.strip()
            counters = counters_raw.split()
            if len(counters) < 16:
                continue
            rx_bytes = int(counters[0])
            tx_bytes = int(counters[8])
            candidates.append((iface, rx_bytes, tx_bytes))

        if not candidates:
            raise RuntimeError("No interfaces in /proc/net/dev")

        if preferred_iface:
            for iface, rx_bytes, tx_bytes in candidates:
                if iface == preferred_iface:
                    return iface, rx_bytes, tx_bytes
            raise RuntimeError(f"Interface '{preferred_iface}' not found")

        non_loopback = [item for item in candidates if item[0] != "lo"]
        if non_loopback:
            return max(non_loopback, key=lambda item: item[1] + item[2])

        return candidates[0]

    @staticmethod
    def _parse_df(
        output: str,
    ) -> tuple[float | None, float | None]:
        marker = "---DF---"
        if marker not in output:
            return None, None
        df_section = output.split(marker, 1)[1].strip()
        lines = df_section.splitlines()
        if len(lines) < 2:
            return None, None
        parts = lines[1].split()
        if len(parts) < 2:
            return None, None
        try:
            avail = int(parts[0])
            total = int(parts[1])
            if avail > 1_000_000:
                return (
                    round(avail / 1_073_741_824, 1),
                    round(total / 1_073_741_824, 1),
                )
            return (
                round(avail / 1_048_576, 1),
                round(total / 1_048_576, 1),
            )
        except (ValueError, ZeroDivisionError):
            return None, None

    @staticmethod
    def _parse_meminfo(
        output: str,
    ) -> tuple[float | None, float | None]:
        marker = "---MEM---"
        if marker not in output:
            return None, None
        section = output.split(marker, 1)[1]
        section = section.split("---", 1)[0]
        total_kb: int | None = None
        avail_kb: int | None = None
        for line in section.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                if parts[0] == "MemTotal:":
                    total_kb = int(parts[1])
                elif parts[0] == "MemAvailable:":
                    avail_kb = int(parts[1])
        if total_kb is None:
            return None, None
        total_gb = round(total_kb / 1_048_576, 1)
        if avail_kb is not None:
            used_gb = round(
                (total_kb - avail_kb) / 1_048_576, 1,
            )
        else:
            used_gb = None
        return used_gb, total_gb

    @staticmethod
    def _parse_uptime(
        output: str,
    ) -> float | None:
        marker = "---UPTIME---"
        if marker not in output:
            return None
        section = output.split(marker, 1)[1].strip()
        first = section.splitlines()[0].strip()
        try:
            secs = float(first.split()[0])
            return round(secs / 86400, 1)
        except (ValueError, IndexError):
            return None

    def _calculate_rates(
        self,
        server_name: str,
        sample: dict[str, Any],
        now: float,
    ) -> tuple[float | None, float | None, float | None, str]:
        prev = self._previous.get(server_name)
        self._previous[server_name] = PreviousSample(
            cpu_total=sample["cpu_total"],
            cpu_idle=sample["cpu_idle"],
            rx_bytes=sample["rx_bytes"],
            tx_bytes=sample["tx_bytes"],
            at=now,
        )

        if prev is None:
            return None, None, None, sample["iface"]

        dt_sec = max(now - prev.at, 1e-6)

        cpu_total_delta = sample["cpu_total"] - prev.cpu_total
        cpu_idle_delta = sample["cpu_idle"] - prev.cpu_idle
        cpu_percent = None
        if cpu_total_delta > 0:
            cpu_percent = round(
                (1 - (cpu_idle_delta / cpu_total_delta)) * 100,
                2,
            )

        rx_delta = max(sample["rx_bytes"] - prev.rx_bytes, 0)
        tx_delta = max(sample["tx_bytes"] - prev.tx_bytes, 0)

        rx_mbps = round((rx_delta * 8) / dt_sec / 1_000_000, 3)
        tx_mbps = round((tx_delta * 8) / dt_sec / 1_000_000, 3)

        return cpu_percent, rx_mbps, tx_mbps, sample["iface"]


CONFIG_PATH = Path("config/servers.yaml")
CONFIG_LOCK = Lock()


def load_config() -> AppConfig:
    if not CONFIG_PATH.exists():
        raise RuntimeError(
            "Missing config/servers.yaml. Copy "
            "config/servers.example.yaml and update servers list."
        )

    raw = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    config = AppConfig.model_validate(raw)
    # Allow overriding bot token via environment variable
    env_token = os.environ.get("BOT_TOKEN")
    if env_token:
        config.bot.token = env_token
    return config


def save_config(updated_cfg: AppConfig) -> None:
    raw = updated_cfg.model_dump(mode="python")
    dumped = yaml.safe_dump(
        raw,
        sort_keys=False,
        allow_unicode=True,
    )
    CONFIG_PATH.write_text(dumped, encoding="utf-8")


def _validate_unix_username(username: str, field_name: str) -> None:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name} format",
        )


def _is_key_fingerprint(value: str) -> bool:
    return value.startswith("SHA256:") or value.startswith("MD5:")


def _validate_client_key_path(client_key: str | None) -> None:
    if not client_key:
        return

    if _is_key_fingerprint(client_key):
        raise HTTPException(
            status_code=400,
            detail=(
                "client_key must be a private key file path, "
                "not SSH fingerprint"
            ),
        )

    key_path = Path(client_key).expanduser()
    if not key_path.exists():
        raise HTTPException(
            status_code=400,
            detail=f"client_key file not found: {client_key}",
        )


def _resolve_public_key(
    client_key: str | None,
) -> str:
    candidates: list[str] = []
    if client_key:
        candidates.append(client_key)
    if cfg.ssh.client_keys:
        candidates.extend(cfg.ssh.client_keys)

    for key_path in candidates:
        if _is_key_fingerprint(key_path):
            continue
        pub_path = Path(key_path).expanduser().with_suffix(".pub")
        if pub_path.exists():
            value = pub_path.read_text(encoding="utf-8").strip()
            if value:
                return value

    raise HTTPException(
        status_code=400,
        detail=(
            "Public key not found. Provide public_key or create "
            "a .pub file for selected client key"
        ),
    )


def _get_public_key_fingerprint(pub_path: Path) -> str | None:
    result = subprocess.run(
        ["ssh-keygen", "-lf", str(pub_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None

    match = re.search(r"(SHA256:[A-Za-z0-9+/=]+)", result.stdout)
    if not match:
        return None
    return match.group(1)


def _resolve_public_key_by_fingerprint(
    fingerprint: str,
    client_key: str | None,
) -> str:
    candidates: list[Path] = []

    if client_key and not _is_key_fingerprint(client_key):
        candidates.append(Path(client_key).expanduser().with_suffix(".pub"))

    if cfg.ssh.client_keys:
        for item in cfg.ssh.client_keys:
            if _is_key_fingerprint(item):
                continue
            candidates.append(Path(item).expanduser().with_suffix(".pub"))

    ssh_dir = Path("~/.ssh").expanduser()
    if ssh_dir.exists():
        candidates.extend(ssh_dir.glob("*.pub"))

    seen: set[Path] = set()
    for pub_path in candidates:
        if pub_path in seen or not pub_path.exists():
            continue
        seen.add(pub_path)
        value = pub_path.read_text(encoding="utf-8").strip()
        if not value:
            continue

        candidate_fp = _get_public_key_fingerprint(pub_path)
        if candidate_fp == fingerprint:
            return value

    raise HTTPException(
        status_code=400,
        detail=(
            "No local .pub key matches fingerprint. "
            "Paste full public key text or select correct key file"
        ),
    )


def _generate_ssh_key_pair(server_name: str) -> tuple[str, str]:
    """Generate ed25519 key pair. Returns (private_path, public_key_text)."""
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", server_name)
    ssh_dir = Path("~/.ssh").expanduser()
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    private_path = ssh_dir / f"id_ed25519_{safe_name}"
    if private_path.exists():
        pub_path = private_path.with_suffix(".pub")
        if pub_path.exists():
            return (
                str(private_path),
                pub_path.read_text(encoding="utf-8").strip(),
            )
        raise HTTPException(
            status_code=400,
            detail=(
                f"Key {private_path} already exists but "
                f".pub file is missing"
            ),
        )

    result = subprocess.run(
        [
            "ssh-keygen",
            "-t", "ed25519",
            "-f", str(private_path),
            "-N", "",
            "-C", f"monitor@{safe_name}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise HTTPException(
            status_code=500,
            detail=f"ssh-keygen failed: {result.stderr.strip()}",
        )

    pub_path = private_path.with_suffix(".pub")
    public_key_text = pub_path.read_text(encoding="utf-8").strip()

    return str(private_path), public_key_text


def _ensure_host_in_known_hosts(host: str, port: int) -> None:
    known_hosts_path = Path(cfg.ssh.known_hosts).expanduser()
    known_hosts_path.parent.mkdir(parents=True, exist_ok=True)
    if not known_hosts_path.exists():
        known_hosts_path.touch()

    lookup = subprocess.run(
        ["ssh-keygen", "-F", host, "-f", str(known_hosts_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if lookup.returncode == 0:
        return

    try:
        scan = subprocess.run(
            ["ssh-keyscan", "-p", str(port), "-H", host],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=10,
        )
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=500,
            detail="Bootstrap failed: timed out while fetching host key",
        ) from exc

    host_key = scan.stdout.strip()
    if scan.returncode != 0 or not host_key:
        raise HTTPException(
            status_code=500,
            detail="Bootstrap failed: unable to fetch host key",
        )

    with known_hosts_path.open("a", encoding="utf-8") as file:
        file.write(f"{host_key}\n")


async def _bootstrap_monitor_user(
    host: str,
    port: int,
    root_user: str,
    root_password: str,
    monitor_user: str,
    public_key: str,
) -> None:
    known_hosts = str(Path(cfg.ssh.known_hosts).expanduser())
    _ensure_host_in_known_hosts(host, port)
    monitor_q = shlex.quote(monitor_user)
    home_q = shlex.quote(f"/home/{monitor_user}")
    # Prefix key with SSH restrictions to block tunneling/forwarding
    restricted_key = (
        "no-port-forwarding,no-X11-forwarding,"
        "no-agent-forwarding,no-pty "
        + public_key
    )
    key_q = shlex.quote(restricted_key)
    # Also quote the raw key for grep to remove old unrestricted entry
    raw_key_q = shlex.quote(public_key)
    script = " ".join(
        [
            "set -e;",
            (
                f"id -u {monitor_q} >/dev/null 2>&1 || "
                f"useradd -m -s /bin/sh {monitor_q};"
            ),
            f"home_dir=$(getent passwd {monitor_q} | cut -d: -f6);",
            f"[ -n \"$home_dir\" ] || home_dir={home_q};",
            (
                f"install -d -m 700 -o {monitor_q} -g "
                f"{monitor_q} \"$home_dir/.ssh\";"
            ),
            "auth_file=\"$home_dir/.ssh/authorized_keys\";",
            "touch \"$auth_file\";",
            f"chown {monitor_q}:{monitor_q} \"$auth_file\";",
            "chmod 600 \"$auth_file\";",
            # Remove old unrestricted key if present
            (
                f"grep -vF {raw_key_q} \"$auth_file\" > \"$auth_file.tmp\" "
                f"|| true; mv \"$auth_file.tmp\" \"$auth_file\";"
            ),
            # Add restricted key if not already there
            (
                f"grep -qxF {key_q} \"$auth_file\" || "
                f"printf '%s\\n' {key_q} >> \"$auth_file\";"
            ),
            f"passwd -l {monitor_q} >/dev/null 2>&1 || true;",
            f"gpasswd -d {monitor_q} sudo >/dev/null 2>&1 || true;",
            f"gpasswd -d {monitor_q} wheel >/dev/null 2>&1 || true;",
        ]
    )
    command = script
    command_input: str | None = None
    if root_user != "root":
        command = f"sudo -S -p '' bash -lc {shlex.quote(script)}"
        command_input = f"{root_password}\n"

    try:
        async with asyncssh.connect(
            host=host,
            port=port,
            username=root_user,
            password=root_password,
            known_hosts=known_hosts,
            preferred_auth=["keyboard-interactive", "password"],
            client_keys=[],
            agent_path=None,
            password_auth=True,
            kbdint_auth=True,
            connect_timeout=cfg.ssh.connect_timeout,
        ) as conn:
            await asyncio.wait_for(
                conn.run(command, input=command_input, check=True),
                timeout=cfg.ssh.command_timeout * 2,
            )
    except asyncssh.PermissionDenied as exc:
        raise HTTPException(
            status_code=401,
            detail=(
                "Authentication failed. If root password login is disabled, "
                "use an admin user with sudo in 'root user' field. "
                "Also verify server doesn't block auth after key attempts"
            ),
        ) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=500,
            detail=f"Bootstrap failed: {exc}",
        ) from exc


cfg = load_config()
collector = MetricsCollector(cfg)
app = FastAPI(title="Server Info Dashboard")
app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static",
)


# ---- rate limiter ----
class _RateLimiter:
    """Simple in-memory per-IP rate limiter (sliding window)."""

    def __init__(
        self,
        max_requests: int = 30,
        window_sec: int = 60,
    ) -> None:
        self._max = max_requests
        self._window = window_sec
        self._hits: dict[str, list[float]] = {}

    def is_limited(self, ip: str) -> bool:
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        cutoff = now - self._window
        hits = self._hits.get(ip, [])
        hits = [t for t in hits if t > cutoff]
        if len(hits) >= self._max:
            self._hits[ip] = hits
            return True
        hits.append(now)
        self._hits[ip] = hits
        return False


_api_limiter = _RateLimiter(max_requests=30, window_sec=60)

_RATE_LIMITED_PREFIXES = (
    "/api/servers",
    "/api/bot",
    "/api/interval",
    "/api/ssh_mode",
    "/api/auth/settings",
)


# ---- auth system ----
_AUTH_PATH = Path("config/auth.yaml")
_AUTH_LOCK = Lock()
_MAX_LOGIN_ATTEMPTS = 5
_BLOCK_MINUTES = 30
_SESSION_COOKIE = "sid"
_MAX_HISTORY = 20
_SESSION_MAX_AGE_DAYS = 30
_PBKDF2_ITERATIONS = 600_000
_MIN_PASSWORD_LENGTH = 8


@dataclass
class _AuthState:
    password_hash: str = ""
    allowed_networks: list[str] = dc_field(
        default_factory=list,
    )
    sessions: dict[str, str] = dc_field(
        default_factory=dict,
    )  # token -> ip
    session_created: dict[str, str] = dc_field(
        default_factory=dict,
    )  # token -> iso-ts
    fail_counts: dict[str, int] = dc_field(
        default_factory=dict,
    )  # ip -> count
    blocked_until: dict[str, str] = dc_field(
        default_factory=dict,
    )  # ip -> iso-ts
    history: list[dict[str, str]] = dc_field(
        default_factory=list,
    )


def _load_auth() -> _AuthState:
    if not _AUTH_PATH.exists():
        return _AuthState()
    raw = yaml.safe_load(
        _AUTH_PATH.read_text(encoding="utf-8"),
    )
    if not raw or not isinstance(raw, dict):
        return _AuthState()
    return _AuthState(
        password_hash=raw.get("password_hash", ""),
        allowed_networks=raw.get(
            "allowed_networks", [],
        ),
        sessions=raw.get("sessions", {}),
        session_created=raw.get("session_created", {}),
        fail_counts=raw.get("fail_counts", {}),
        blocked_until=raw.get("blocked_until", {}),
        history=raw.get("history", []),
    )


def _save_auth(state: _AuthState) -> None:
    _AUTH_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "password_hash": state.password_hash,
        "allowed_networks": state.allowed_networks,
        "sessions": state.sessions,
        "session_created": state.session_created,
        "fail_counts": state.fail_counts,
        "blocked_until": state.blocked_until,
        "history": state.history[
            -_MAX_HISTORY:
        ],
    }
    _AUTH_PATH.write_text(
        yaml.safe_dump(
            data, sort_keys=False, allow_unicode=True,
        ),
        encoding="utf-8",
    )


def _hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        pw.encode("utf-8"),
        salt,
        _PBKDF2_ITERATIONS,
    )
    return f"pbkdf2${salt.hex()}${dk.hex()}"


def _verify_password(
    pw: str, stored: str,
) -> bool:
    if "$" not in stored:
        return False
    # PBKDF2 format: pbkdf2$salt_hex$hash_hex
    if stored.startswith("pbkdf2$"):
        parts = stored.split("$")
        if len(parts) != 3:
            return False
        _, salt_hex, hash_hex = parts
        try:
            salt = bytes.fromhex(salt_hex)
        except ValueError:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            pw.encode("utf-8"),
            salt,
            _PBKDF2_ITERATIONS,
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    # legacy SHA-256 fallback
    salt, h = stored.split("$", 1)
    return hmac.compare_digest(
        hashlib.sha256(
            (salt + pw).encode("utf-8"),
        ).hexdigest(),
        h,
    )


def _client_ip(request: Request) -> str:
    # Do NOT trust X-Forwarded-For — it can be spoofed
    # to bypass IP whitelist and session binding.
    if request.client:
        return request.client.host
    return "unknown"


def _ip_allowed(
    ip: str, networks: list[str],
) -> bool:
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net_str in networks:
        try:
            net = ipaddress.ip_network(
                net_str, strict=False,
            )
            if addr in net:
                return True
        except ValueError:
            if ip == net_str:
                return True
    return False


def _geo_lookup(ip: str) -> str:
    """Best-effort country lookup via ip-api."""
    try:
        url = (
            f"https://ip-api.com/json/{ip}"
            "?fields=country"
        )
        req = urllib.request.Request(
            url, method="GET",
        )
        with urllib.request.urlopen(
            req, timeout=3,
        ) as resp:
            data = json.loads(resp.read())
            return data.get("country", "")
    except Exception:  # noqa: BLE001
        return ""


_auth = _load_auth()

_PUBLIC_PATHS = {
    "/api/auth/login",
    "/api/auth/status",
}


def _session_expired(token: str) -> bool:
    """Check if session has exceeded max age."""
    created = _auth.session_created.get(token)
    if not created:
        return True  # no timestamp = legacy, treat as expired
    try:
        ts = dt.datetime.fromisoformat(created)
        age = dt.datetime.now(dt.timezone.utc) - ts
        return age.days > _SESSION_MAX_AGE_DAYS
    except ValueError:
        return True


def _check_csrf(request: Request) -> bool:
    """Validate Origin header for state-changing requests."""
    method = request.method.upper()
    if method in ("GET", "HEAD", "OPTIONS"):
        return True
    origin = request.headers.get("origin")
    if not origin:
        # no Origin header — allow (non-browser client)
        return True
    host = request.headers.get("host", "").split(":")[0]
    # extract host from origin (scheme://host[:port])
    try:
        origin_host = origin.split("://", 1)[1].split(":")[0]
    except IndexError:
        return False
    return origin_host == host


@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next: Any,
) -> Response:
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


@app.middleware("http")
async def auth_middleware(
    request: Request,
    call_next: Any,
) -> Response:
    """Protect all routes when password is set."""
    path = request.url.path
    # static assets always allowed
    if path.startswith("/static/"):
        return await call_next(request)
    # CSRF check for state-changing requests
    if not _check_csrf(request):
        return JSONResponse(
            {"detail": "CSRF check failed"}, status_code=403,
        )
    # rate limit state-changing API endpoints
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if any(path.startswith(p) for p in _RATE_LIMITED_PREFIXES):
            ip_rl = _client_ip(request)
            if _api_limiter.is_limited(ip_rl):
                return JSONResponse(
                    {"detail": "Too many requests"},
                    status_code=429,
                )
    # if no password set, everything open
    if not _auth.password_hash:
        return await call_next(request)
    # public auth endpoints
    if path in _PUBLIC_PATHS:
        return await call_next(request)
    # check IP whitelist
    ip = _client_ip(request)
    if (
        _auth.allowed_networks
        and not _ip_allowed(ip, _auth.allowed_networks)
    ):
        return JSONResponse(
            {"detail": "Forbidden"}, status_code=403,
        )
    # check session cookie
    sid = request.cookies.get(_SESSION_COOKIE)
    if not sid or sid not in _auth.sessions:
        # index page -> serve login page
        if path == "/":
            return FileResponse(
                "app/static/index.html",
            )
        return JSONResponse(
            {"detail": "Unauthorized"},
            status_code=401,
        )
    # verify IP hasn't changed
    if _auth.sessions.get(sid) != ip:
        with _AUTH_LOCK:
            _auth.sessions.pop(sid, None)
            _auth.session_created.pop(sid, None)
            _save_auth(_auth)
        return JSONResponse(
            {"detail": "Session expired (IP changed)"},
            status_code=401,
        )
    # verify session not expired
    if _session_expired(sid):
        with _AUTH_LOCK:
            _auth.sessions.pop(sid, None)
            _auth.session_created.pop(sid, None)
            _save_auth(_auth)
        return JSONResponse(
            {"detail": "Session expired"},
            status_code=401,
        )
    return await call_next(request)


# ---- server metrics log ----
_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
_LOG_RETENTION_DAYS = 30
_TRAFFIC_30D_CACHE_TTL_SEC = 300
_TRAFFIC_1D_CACHE_TTL_SEC = 60

_CSV_COLUMNS = [
    "timestamp", "name", "host", "status",
    "uptime_days", "ping_ms", "cpu_percent",
    "ram_used_gb", "ram_total_gb",
    "disk_free_gb", "disk_total_gb",
    "rx_mbps", "tx_mbps", "interface", "error",
]

_traffic_30d_cache: dict[str, Any] = {
    "expires_at": dt.datetime.fromtimestamp(
        0,
        tz=dt.timezone.utc,
    ),
    "values": {},
}

_traffic_1d_cache: dict[str, Any] = {
    "expires_at": dt.datetime.fromtimestamp(
        0,
        tz=dt.timezone.utc,
    ),
    "values": {},
}


def _safe_filename(name: str) -> str:
    """Sanitise server name for use as a filename."""
    return re.sub(r'[^\w\-. ]', '_', name)


def _log_server_metrics(
    servers: list[dict[str, Any]],
) -> None:
    """Append one CSV row per server to daily log files."""
    today = dt.date.today().isoformat()
    for srv in servers:
        safe = _safe_filename(srv.get("name", "unknown"))
        log_path = _LOGS_DIR / f"{safe}_{today}.csv"
        write_header = not log_path.exists()
        fieldnames = _CSV_COLUMNS
        if not write_header:
            try:
                with log_path.open(
                    encoding="utf-8",
                    newline="",
                ) as existing_file:
                    existing_reader = csv.reader(existing_file)
                    existing_header = next(existing_reader, None)
                    if existing_header:
                        fieldnames = [
                            str(col).strip()
                            for col in existing_header
                            if str(col).strip()
                        ]
            except Exception:  # noqa: BLE001
                fieldnames = _CSV_COLUMNS
        with log_path.open("a", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            if write_header:
                writer.writeheader()
            row = {
                "timestamp": dt.datetime.now(
                    dt.timezone.utc,
                ).strftime("%Y-%m-%d %H:%M"),
            }
            for col in fieldnames[1:]:
                row[col] = srv.get(col, "")
                if row[col] is None:
                    row[col] = ""
            writer.writerow(row)


def _rotate_logs() -> None:
    """Delete log files older than _LOG_RETENTION_DAYS."""
    cutoff = dt.date.today() - dt.timedelta(
        days=_LOG_RETENTION_DAYS,
    )
    for f in _LOGS_DIR.glob("*.csv"):
        # extract date from filename: name_YYYY-MM-DD.csv
        parts = f.stem.rsplit("_", 1)
        if len(parts) == 2:
            try:
                file_date = dt.date.fromisoformat(parts[1])
                if file_date < cutoff:
                    f.unlink(missing_ok=True)
            except ValueError:
                pass


def _calculate_traffic_30d_gb() -> dict[str, float]:
    """Calculate per-server RX+TX traffic for the last 30 days."""
    cutoff = dt.date.today() - dt.timedelta(days=30)
    totals_raw: dict[str, float] = {}

    for file_path in _LOGS_DIR.glob("*.csv"):
        parts = file_path.stem.rsplit("_", 1)
        if len(parts) != 2:
            continue
        safe_name, date_part = parts
        try:
            file_date = dt.date.fromisoformat(date_part)
        except ValueError:
            continue
        if file_date < cutoff:
            continue
        if file_path.stat().st_size <= 0:
            continue

        with file_path.open(encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            _ = next(reader, None)  # header
            for values in reader:
                # Handle mixed schemas in legacy files:
                # old: 12 columns, new: 15 columns.
                if len(values) >= 15:
                    row_name = values[1] if len(values) > 1 else ""
                    rx_raw = values[11] if len(values) > 11 else ""
                    tx_raw = values[12] if len(values) > 12 else ""
                elif len(values) >= 12:
                    row_name = values[1] if len(values) > 1 else ""
                    rx_raw = values[8] if len(values) > 8 else ""
                    tx_raw = values[9] if len(values) > 9 else ""
                else:
                    continue

                row_key = (
                    _safe_filename(row_name)
                    if row_name
                    else safe_name
                )
                try:
                    rx = float(rx_raw or 0.0)
                except (TypeError, ValueError):
                    rx = 0.0
                try:
                    tx = float(tx_raw or 0.0)
                except (TypeError, ValueError):
                    tx = 0.0
                if rx <= 0 and tx <= 0:
                    continue
                row_total = totals_raw.get(row_key, 0.0)
                period_megabits = (
                    (rx + tx) * cfg.refresh_interval_sec
                )
                period_megabytes = period_megabits / 8.0
                period_gigabytes = period_megabytes / 1000.0
                row_total += period_gigabytes
                totals_raw[row_key] = row_total

    return {
        key: round(value, 3)
        for key, value in totals_raw.items()
    }


def _calculate_traffic_1d_gb() -> dict[str, float]:
    """Calculate per-server RX+TX traffic for the last 1 day."""
    cutoff = dt.date.today() - dt.timedelta(days=1)
    totals_raw: dict[str, float] = {}

    for file_path in _LOGS_DIR.glob("*.csv"):
        parts = file_path.stem.rsplit("_", 1)
        if len(parts) != 2:
            continue
        safe_name, date_part = parts
        try:
            file_date = dt.date.fromisoformat(date_part)
        except ValueError:
            continue
        if file_date < cutoff:
            continue
        if file_path.stat().st_size <= 0:
            continue

        with file_path.open(encoding="utf-8", newline="") as fh:
            reader = csv.reader(fh)
            _ = next(reader, None)  # header
            for values in reader:
                if len(values) >= 15:
                    row_name = values[1] if len(values) > 1 else ""
                    rx_raw = values[11] if len(values) > 11 else ""
                    tx_raw = values[12] if len(values) > 12 else ""
                elif len(values) >= 12:
                    row_name = values[1] if len(values) > 1 else ""
                    rx_raw = values[8] if len(values) > 8 else ""
                    tx_raw = values[9] if len(values) > 9 else ""
                else:
                    continue

                row_key = (
                    _safe_filename(row_name)
                    if row_name
                    else safe_name
                )
                try:
                    rx = float(rx_raw or 0.0)
                except (TypeError, ValueError):
                    rx = 0.0
                try:
                    tx = float(tx_raw or 0.0)
                except (TypeError, ValueError):
                    tx = 0.0
                if rx <= 0 and tx <= 0:
                    continue
                row_total = totals_raw.get(row_key, 0.0)
                period_megabits = (
                    (rx + tx) * cfg.refresh_interval_sec
                )
                period_megabytes = period_megabits / 8.0
                period_gigabytes = period_megabytes / 1000.0
                row_total += period_gigabytes
                totals_raw[row_key] = row_total

    return {
        key: round(value, 3)
        for key, value in totals_raw.items()
    }


def _get_traffic_30d_gb_cached() -> dict[str, float]:
    """Return cached 30-day traffic map, recomputing every 5 minutes."""
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = _traffic_30d_cache.get("expires_at")
    if isinstance(expires_at, dt.datetime) and now < expires_at:
        values = _traffic_30d_cache.get("values")
        if isinstance(values, dict) and values:
            return values

    values = _calculate_traffic_30d_gb()
    _traffic_30d_cache["values"] = values
    _traffic_30d_cache["expires_at"] = now + dt.timedelta(
        seconds=_TRAFFIC_30D_CACHE_TTL_SEC,
    )
    return values


def _get_traffic_1d_gb_cached() -> dict[str, float]:
    """Return cached 1-day traffic map, recomputing every minute."""
    now = dt.datetime.now(dt.timezone.utc)
    expires_at = _traffic_1d_cache.get("expires_at")
    if isinstance(expires_at, dt.datetime) and now < expires_at:
        values = _traffic_1d_cache.get("values")
        if isinstance(values, dict) and values:
            return values

    values = _calculate_traffic_1d_gb()
    _traffic_1d_cache["values"] = values
    _traffic_1d_cache["expires_at"] = now + dt.timedelta(
        seconds=_TRAFFIC_1D_CACHE_TTL_SEC,
    )
    return values


def _attach_traffic_30d(
    servers: list[dict[str, Any]],
) -> None:
    traffic_map = _get_traffic_30d_gb_cached()
    for srv in servers:
        safe_name = _safe_filename(srv.get("name", ""))
        srv["traffic_30d_gb"] = traffic_map.get(safe_name, 0.0)


def _attach_traffic_1d(
    servers: list[dict[str, Any]],
) -> None:
    traffic_map = _get_traffic_1d_gb_cached()
    for srv in servers:
        safe_name = _safe_filename(srv.get("name", ""))
        srv["traffic_1d_gb"] = traffic_map.get(safe_name, 0.0)


_cached_metrics: dict[str, Any] = {
    "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    "refresh_interval_sec": cfg.refresh_interval_sec,
    "servers": [],
    "ready": False,
}
_metrics_lock = asyncio.Lock()

_notified_state: dict[str, set[str]] = {}
_trigger_counts: dict[str, dict[str, int]] = {}


def _send_telegram(token: str, chat_id: str, text: str) -> None:
    """Send a message via Telegram Bot API (sync)."""
    url = (
        f"https://api.telegram.org/bot{token}"
        f"/sendMessage"
    )
    payload = json.dumps(
        {"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
    ).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10):
            pass
    except Exception as exc:  # noqa: BLE001
        logger.warning("Telegram send failed: %s", exc)


async def _check_and_notify(
    servers: list[dict[str, Any]],
) -> None:
    """Check thresholds and send Telegram alerts."""
    bot = cfg.bot
    if not bot.enabled or not bot.token or not bot.chat_id:
        return

    delay = max(bot.notify_delay, 1)
    alerts: list[str] = []

    for srv in servers:
        name = srv.get("name", "?")
        counts = _trigger_counts.setdefault(name, {})
        triggered: set[str] = set()

        # --- check each metric ---
        if bot.notify_down and srv.get("status") == "down":
            counts["down"] = counts.get("down", 0) + 1
        else:
            counts["down"] = 0
        if counts.get("down", 0) >= delay:
            triggered.add("down")

        cpu = srv.get("cpu_percent")
        if (
            bot.notify_cpu_threshold is not None
            and cpu is not None
            and cpu >= bot.notify_cpu_threshold
        ):
            counts["cpu"] = counts.get("cpu", 0) + 1
        else:
            counts["cpu"] = 0
        if counts.get("cpu", 0) >= delay:
            triggered.add("cpu")

        ping = srv.get("ping_ms")
        if (
            bot.notify_ping_threshold is not None
            and ping is not None
            and ping >= bot.notify_ping_threshold
        ):
            counts["ping"] = counts.get("ping", 0) + 1
        else:
            counts["ping"] = 0
        if counts.get("ping", 0) >= delay:
            triggered.add("ping")

        if bot.notify_disk_threshold is not None:
            free = srv.get("disk_free_gb")
            total = srv.get("disk_total_gb")
            if free is not None and total and total > 0:
                used_pct = ((total - free) / total) * 100
                if used_pct >= bot.notify_disk_threshold:
                    counts["disk"] = counts.get("disk", 0) + 1
                else:
                    counts["disk"] = 0
            else:
                counts["disk"] = 0
        else:
            counts["disk"] = 0
        if counts.get("disk", 0) >= delay:
            triggered.add("disk")

        rx = srv.get("rx_mbps")
        if (
            bot.notify_rx_threshold is not None
            and rx is not None
            and rx >= bot.notify_rx_threshold
        ):
            counts["rx"] = counts.get("rx", 0) + 1
        else:
            counts["rx"] = 0
        if counts.get("rx", 0) >= delay:
            triggered.add("rx")

        tx = srv.get("tx_mbps")
        if (
            bot.notify_tx_threshold is not None
            and tx is not None
            and tx >= bot.notify_tx_threshold
        ):
            counts["tx"] = counts.get("tx", 0) + 1
        else:
            counts["tx"] = 0
        if counts.get("tx", 0) >= delay:
            triggered.add("tx")

        prev = _notified_state.get(name, set())
        new_alerts = triggered - prev
        recovered = prev - triggered
        _notified_state[name] = triggered

        for key in sorted(new_alerts):
            if key == "down":
                alerts.append(
                    f"\u26a0\ufe0f <b>{name}</b> is DOWN"
                )
            elif key == "cpu":
                alerts.append(
                    f"\U0001f525 <b>{name}</b> CPU {cpu:.1f}%"
                    f" \u2265 {bot.notify_cpu_threshold}%"
                )
            elif key == "ping":
                alerts.append(
                    f"\U0001f4e1 <b>{name}</b> Ping"
                    f" {ping:.0f} ms"
                    f" \u2265 {bot.notify_ping_threshold} ms"
                )
            elif key == "disk":
                d_total = srv.get("disk_total_gb") or 1
                d_free = srv.get("disk_free_gb") or 0
                alerts.append(
                    f"\U0001f4be <b>{name}</b> Disk"
                    f" {((d_total - d_free) / d_total * 100):.0f}%"
                    f" \u2265 {bot.notify_disk_threshold}%"
                )
            elif key == "rx":
                alerts.append(
                    f"\u2b07\ufe0f <b>{name}</b> RX"
                    f" {rx:.3f} Mbps"
                    f" \u2265 {bot.notify_rx_threshold}"
                )
            elif key == "tx":
                alerts.append(
                    f"\u2b06\ufe0f <b>{name}</b> TX"
                    f" {tx:.3f} Mbps"
                    f" \u2265 {bot.notify_tx_threshold}"
                )

        # --- recovery notifications ---
        for key in sorted(recovered):
            if key == "down":
                alerts.append(
                    f"\u2705 <b>{name}</b> is UP"
                )
            elif key == "cpu":
                val = f" ({cpu:.1f}%)" if cpu is not None else ""
                alerts.append(
                    f"\u2705 <b>{name}</b> CPU OK{val}"
                )
            elif key == "ping":
                val = (
                    f" ({ping:.0f} ms)"
                    if ping is not None
                    else ""
                )
                alerts.append(
                    f"\u2705 <b>{name}</b> Ping OK{val}"
                )
            elif key == "disk":
                alerts.append(
                    f"\u2705 <b>{name}</b> Disk OK"
                )
            elif key == "rx":
                val = (
                    f" ({rx:.3f} Mbps)"
                    if rx is not None
                    else ""
                )
                alerts.append(
                    f"\u2705 <b>{name}</b> RX OK{val}"
                )
            elif key == "tx":
                val = (
                    f" ({tx:.3f} Mbps)"
                    if tx is not None
                    else ""
                )
                alerts.append(
                    f"\u2705 <b>{name}</b> TX OK{val}"
                )

    if alerts:
        text = "\n".join(alerts)
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            _send_telegram,
            bot.token,
            bot.chat_id,
            text,
        )


async def _background_collector() -> None:
    global _cached_metrics
    _rotation_counter = 0
    while True:
        try:
            data = await collector.collect_all()
            _attach_traffic_30d(data["servers"])
            _attach_traffic_1d(data["servers"])
            data["ready"] = True
            async with _metrics_lock:
                _cached_metrics = data
            await _check_and_notify(data["servers"])
            # write metrics to CSV log files
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(
                None, _log_server_metrics, data["servers"],
            )
            # rotate old logs once every ~100 cycles
            _rotation_counter += 1
            if _rotation_counter >= 100:
                _rotation_counter = 0
                await loop.run_in_executor(
                    None, _rotate_logs,
                )
        except Exception:  # noqa: BLE001
            pass
        await asyncio.sleep(cfg.refresh_interval_sec)


@app.on_event("startup")
async def _start_background_tasks() -> None:
    asyncio.create_task(_background_collector())


# ---- auth endpoints ----

class _LoginRequest(BaseModel):
    password: str = Field(max_length=200)


class _SecuritySettingsRequest(BaseModel):
    current_password: str | None = None
    password: str | None = None
    allowed_networks: list[str] = []


@app.get("/api/auth/status")
async def auth_status(
    request: Request,
) -> dict[str, Any]:
    has_pw = bool(_auth.password_hash)
    ip = _client_ip(request)
    sid = request.cookies.get(_SESSION_COOKIE)
    logged = (
        has_pw
        and sid is not None
        and _auth.sessions.get(sid) == ip
    )
    return {
        "has_password": has_pw,
        "logged_in": logged,
    }


@app.post("/api/auth/login")
async def auth_login(
    payload: _LoginRequest,
    request: Request,
) -> JSONResponse:
    ip = _client_ip(request)
    now = dt.datetime.now(dt.timezone.utc)
    # check block
    blocked_ts = _auth.blocked_until.get(ip)
    if blocked_ts:
        try:
            until = dt.datetime.fromisoformat(blocked_ts)
            if now < until:
                diff = int((until - now).total_seconds())
                return JSONResponse(
                    {
                        "detail": (
                            f"Blocked for {diff}s"
                        ),
                    },
                    status_code=429,
                )
        except ValueError:
            pass
        with _AUTH_LOCK:
            _auth.blocked_until.pop(ip, None)
            _auth.fail_counts.pop(ip, None)
            _save_auth(_auth)

    if not _auth.password_hash:
        return JSONResponse(
            {"detail": "No password set"},
            status_code=400,
        )

    if not _verify_password(
        payload.password, _auth.password_hash,
    ):
        with _AUTH_LOCK:
            c = _auth.fail_counts.get(ip, 0) + 1
            _auth.fail_counts[ip] = c
            if c >= _MAX_LOGIN_ATTEMPTS:
                until = now + dt.timedelta(
                    minutes=_BLOCK_MINUTES,
                )
                _auth.blocked_until[ip] = (
                    until.isoformat()
                )
                _auth.fail_counts[ip] = 0
            _save_auth(_auth)
        remaining = _MAX_LOGIN_ATTEMPTS - c
        if remaining <= 0:
            return JSONResponse(
                {
                    "detail": (
                        "Blocked for "
                        f"{_BLOCK_MINUTES} min"
                    ),
                },
                status_code=429,
            )
        return JSONResponse(
            {
                "detail": "Wrong password",
                "remaining": remaining,
            },
            status_code=403,
        )

    # success
    token = secrets.token_urlsafe(32)
    ua = request.headers.get("user-agent", "")
    country = await asyncio.get_running_loop(
    ).run_in_executor(None, _geo_lookup, ip)
    with _AUTH_LOCK:
        _auth.sessions[token] = ip
        _auth.session_created[token] = (
            now.isoformat()
        )
        _auth.fail_counts.pop(ip, None)
        _auth.blocked_until.pop(ip, None)
        _auth.history.append(
            {
                "time": now.strftime(
                    "%Y-%m-%d %H:%M",
                ),
                "ip": ip,
                "country": country,
                "ua": ua[:200],
            },
        )
        if len(_auth.history) > _MAX_HISTORY:
            _auth.history = _auth.history[
                -_MAX_HISTORY:
            ]
        _save_auth(_auth)

    resp = JSONResponse({"status": "ok"})
    resp.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        samesite="lax",
        max_age=_SESSION_MAX_AGE_DAYS * 86400,
    )
    return resp


@app.post("/api/auth/logout")
async def auth_logout(
    request: Request,
) -> JSONResponse:
    sid = request.cookies.get(_SESSION_COOKIE)
    if sid:
        with _AUTH_LOCK:
            _auth.sessions.pop(sid, None)
            _auth.session_created.pop(sid, None)
            _save_auth(_auth)
    resp = JSONResponse({"status": "ok"})
    resp.delete_cookie(_SESSION_COOKIE)
    return resp


@app.get("/api/auth/settings")
async def get_auth_settings() -> dict[str, Any]:
    return {
        "has_password": bool(_auth.password_hash),
        "allowed_networks": _auth.allowed_networks,
        "history": _auth.history[-_MAX_HISTORY:],
    }


@app.put("/api/auth/settings")
async def update_auth_settings(
    payload: _SecuritySettingsRequest,
) -> dict[str, Any]:
    with _AUTH_LOCK:
        if payload.password:
            if len(payload.password) < _MIN_PASSWORD_LENGTH:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Password must be at least "
                        f"{_MIN_PASSWORD_LENGTH} characters"
                    ),
                )
            # require current password when changing
            if _auth.password_hash:
                if (
                    not payload.current_password
                    or not _verify_password(
                        payload.current_password,
                        _auth.password_hash,
                    )
                ):
                    raise HTTPException(
                        status_code=403,
                        detail="Current password is incorrect",
                    )
            _auth.password_hash = _hash_password(
                payload.password,
            )
        nets: list[str] = []
        for n in payload.allowed_networks:
            n = n.strip()
            if not n:
                continue
            try:
                ipaddress.ip_network(n, strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(n)
                except ValueError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"Invalid network or IP: {n}",
                    )
            nets.append(n)
        _auth.allowed_networks = nets
        _save_auth(_auth)
    return {
        "status": "ok",
        "has_password": bool(_auth.password_hash),
        "allowed_networks": _auth.allowed_networks,
    }


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    async with _metrics_lock:
        return _cached_metrics


@app.get("/api/logs/{server_name}")
async def download_logs(server_name: str) -> StreamingResponse:
    """Download combined CSV log for the given server."""
    safe = _safe_filename(server_name)
    files = sorted(_LOGS_DIR.glob(f"{safe}_*.csv"))
    if not files:
        raise HTTPException(
            status_code=404, detail="No logs found",
        )

    buf = io.StringIO()
    writer = csv.DictWriter(
        buf,
        fieldnames=_CSV_COLUMNS,
        extrasaction="ignore",
    )
    writer.writeheader()
    for fp in files:
        with fp.open(encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                filtered = {
                    k: row.get(k, "")
                    for k in _CSV_COLUMNS
                }
                writer.writerow(filtered)

    content = buf.getvalue().encode("utf-8")
    filename = f"{safe}_logs.csv"
    ascii_name = filename.encode("ascii", "replace").decode("ascii")
    utf8_name = urllib.parse.quote(filename)
    return StreamingResponse(
        io.BytesIO(content),
        media_type="text/csv",
        headers={
            "Content-Disposition": (
                f"attachment; filename=\"{ascii_name}\"; "
                f"filename*=UTF-8''{utf8_name}"
            ),
        },
    )


@app.post("/api/servers")
async def add_server(payload: AddServerRequest) -> dict[str, Any]:
    name = payload.name.strip()
    host = payload.host.strip()
    user = payload.user.strip()
    interface = payload.interface.strip() if payload.interface else None
    client_key = payload.client_key.strip() if payload.client_key else None
    root_user = payload.root_user.strip() if payload.root_user else None
    root_password = payload.root_password if payload.root_password else None
    public_key = payload.public_key.strip() if payload.public_key else None

    if not name or not host or not user:
        raise HTTPException(
            status_code=400,
            detail="name, host and user are required",
        )

    _validate_unix_username(user, "user")
    _validate_client_key_path(client_key)

    generated_private_key: str | None = None
    generated_public_key: str | None = None

    if payload.generate_key:
        generated_private_key, generated_public_key = (
            _generate_ssh_key_pair(name)
        )
        client_key = generated_private_key

    country = (
        payload.country.strip().lower()[:2]
        if payload.country
        else None
    )

    server = ServerConfig(
        name=name,
        host=host,
        port=payload.port,
        user=user,
        interface=interface,
        client_key=client_key,
        country=country,
    )

    if payload.bootstrap_with_root:
        if not root_user or not root_password:
            raise HTTPException(
                status_code=400,
                detail=(
                    "root_user and root_password are required "
                    "for bootstrap"
                ),
            )

        _validate_unix_username(root_user, "root_user")

        if generated_public_key:
            resolved_public_key = generated_public_key
        elif public_key and _is_key_fingerprint(public_key):
            resolved_public_key = _resolve_public_key_by_fingerprint(
                public_key,
                client_key,
            )
        else:
            resolved_public_key = (
                public_key or _resolve_public_key(client_key)
            )
        await _bootstrap_monitor_user(
            host=host,
            port=payload.port,
            root_user=root_user,
            root_password=root_password,
            monitor_user=user,
            public_key=resolved_public_key,
        )

    with CONFIG_LOCK:
        if any(item.name == server.name for item in cfg.servers):
            raise HTTPException(
                status_code=409,
                detail=f"Server '{server.name}' already exists",
            )

        if generated_private_key:
            if cfg.ssh.client_keys is None:
                cfg.ssh.client_keys = []
            if generated_private_key not in cfg.ssh.client_keys:
                cfg.ssh.client_keys.append(generated_private_key)

        cfg.servers.append(server)
        save_config(cfg)

    return {
        "status": "ok",
        "server": server.model_dump(mode="python"),
    }


@app.delete("/api/servers/{server_name}")
async def delete_server(server_name: str) -> dict[str, Any]:
    target_name = server_name.strip()
    if not target_name:
        raise HTTPException(status_code=400, detail="server name is required")

    with CONFIG_LOCK:
        index = next(
            (
                idx
                for idx, item in enumerate(cfg.servers)
                if item.name == target_name
            ),
            None,
        )

        if index is None:
            raise HTTPException(
                status_code=404,
                detail=f"Server '{target_name}' not found",
            )

        removed = cfg.servers.pop(index)
        collector._previous.pop(removed.name, None)

        if removed.client_key:
            _cleanup_server_key(
                removed.client_key,
                cfg,
            )

        save_config(cfg)

    return {"status": "ok", "deleted": removed.name}


def _cleanup_server_key(
    client_key: str,
    config: AppConfig,
) -> None:
    if _is_key_fingerprint(client_key):
        return
    key_path = Path(client_key).expanduser()
    pub_path = key_path.with_suffix(".pub")

    still_used = any(
        s.client_key and str(Path(s.client_key).expanduser()) == str(key_path)
        for s in config.servers
    )
    if still_used:
        return

    if config.ssh.client_keys:
        config.ssh.client_keys = [
            k for k in config.ssh.client_keys
            if str(Path(k).expanduser()) != str(key_path)
        ]

    for path in (key_path, pub_path):
        try:
            if path.exists():
                path.unlink()
        except OSError:
            pass


class RenameServerRequest(BaseModel):
    new_name: str = Field(max_length=100)


@app.patch("/api/servers/{server_name}")
async def rename_server(
    server_name: str,
    payload: RenameServerRequest,
) -> dict[str, Any]:
    old = server_name.strip()
    new = payload.new_name.strip()
    if not new:
        raise HTTPException(400, "new_name is required")

    with CONFIG_LOCK:
        srv = next(
            (s for s in cfg.servers if s.name == old),
            None,
        )
        if srv is None:
            raise HTTPException(
                404,
                f"Server '{old}' not found",
            )
        if any(s.name == new for s in cfg.servers):
            raise HTTPException(
                409,
                f"Server '{new}' already exists",
            )

        prev_sample = collector._previous.pop(old, None)
        srv.name = new
        if prev_sample is not None:
            collector._previous[new] = prev_sample
        save_config(cfg)

    return {"status": "ok", "old_name": old, "new_name": new}


class IntervalRequest(BaseModel):
    interval: int = Field(ge=1, le=300)


class BotConfigRequest(BaseModel):
    enabled: bool = False
    token: str = ""
    chat_id: str = ""
    notify_down: bool = True
    notify_cpu_threshold: float | None = 90.0
    notify_ping_threshold: float | None = None
    notify_disk_threshold: float | None = 95.0
    notify_rx_threshold: float | None = None
    notify_tx_threshold: float | None = None
    notify_delay: int = 1


@app.put("/api/interval")
async def update_interval(
    payload: IntervalRequest,
) -> dict[str, Any]:
    with CONFIG_LOCK:
        cfg.refresh_interval_sec = payload.interval
        save_config(cfg)
    return {
        "status": "ok",
        "refresh_interval_sec": cfg.refresh_interval_sec,
    }


class SshModeRequest(BaseModel):
    persistent: bool


@app.put("/api/ssh_mode")
async def update_ssh_mode(
    payload: SshModeRequest,
) -> dict[str, Any]:
    old = cfg.persistent_ssh
    with CONFIG_LOCK:
        cfg.persistent_ssh = payload.persistent
        save_config(cfg)
    # If switching OFF persistent, close all pooled connections
    if old and not payload.persistent:
        await collector.close_pool()
    return {
        "status": "ok",
        "persistent_ssh": cfg.persistent_ssh,
    }


@app.get("/api/bot")
async def get_bot() -> dict[str, Any]:
    d = cfg.bot.model_dump(mode="python")
    if d.get("token"):
        d["token"] = ""
        d["token_set"] = True
    else:
        d["token_set"] = False
    return d


@app.put("/api/bot")
async def update_bot(
    payload: BotConfigRequest,
) -> dict[str, Any]:
    with CONFIG_LOCK:
        token = payload.token
        if not token and cfg.bot.token:
            token = cfg.bot.token
        cfg.bot = BotConfig(
            enabled=payload.enabled,
            token=token,
            chat_id=payload.chat_id,
            notify_down=payload.notify_down,
            notify_cpu_threshold=payload.notify_cpu_threshold,
            notify_ping_threshold=payload.notify_ping_threshold,
            notify_disk_threshold=payload.notify_disk_threshold,
            notify_rx_threshold=payload.notify_rx_threshold,
            notify_tx_threshold=payload.notify_tx_threshold,
            notify_delay=payload.notify_delay,
        )
        save_config(cfg)
    # send startup notification when bot is enabled
    if (
        cfg.bot.enabled
        and cfg.bot.token
        and cfg.bot.chat_id
    ):
        msg = (
            "\u2705 <b>Server Info Bot</b> "
            "\u0437\u0430\u043f\u0443\u0449\u0435\u043d \u0438 "
            "\u043e\u0442\u043f\u0440\u0430\u0432\u043b\u044f\u0435\u0442 "
            "\u0443\u0432\u0435\u0434\u043e\u043c\u043b\u0435\u043d"
            "\u0438\u044f."
        )
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            _send_telegram,
            cfg.bot.token,
            cfg.bot.chat_id,
            msg,
        )
    d = cfg.bot.model_dump(mode="python")
    if d.get("token"):
        d["token"] = ""
        d["token_set"] = True
    else:
        d["token_set"] = False
    return {"status": "ok", "bot": d}
