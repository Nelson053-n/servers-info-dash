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
from pydantic import BaseModel, Field, field_validator, model_validator

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


_HOSTNAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252})")


def _validate_host(value: str) -> str:
    """Accept an IP address or a DNS name, nothing that looks like an option.

    The host goes straight into ping and ssh-keyscan argv; a value
    starting with '-' would be parsed as a flag there.
    """
    value = value.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(value):
        raise ValueError("host must be an IP address or a hostname")
    return value


class AddServerRequest(BaseModel):
    name: str = Field(max_length=100)
    host: str = Field(max_length=255)

    @field_validator("host")
    @classmethod
    def _check_host(cls, value: str) -> str:
        return _validate_host(value)
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


# Upper bound on one server's snapshot; the real one is ~2 KB.
_MAX_REMOTE_OUTPUT_CHARS = 64 * 1024
# Linux IFNAMSIZ is 16 including NUL; names like eth0, ens3, wg0,
# veth1@if5, eth0.100 all fit this.
_IFACE_RE = re.compile(r"[\w.@-]{1,15}")


class MetricsCollector:
    _PING_INTERVAL: float = 30.0  # seconds between ping measurements
    # ping's own -W bounds the reply wait but not name resolution
    _PING_TIMEOUT_SEC: float = 5.0

    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self._previous: dict[str, PreviousSample] = {}
        self._error_counts: dict[str, int] = {}
        self._last_good: dict[str, dict[str, Any]] = {}
        self._error_threshold: int = 5
        self._pool: dict[str, asyncssh.SSHClientConnection] = {}
        # One lock per pool key, not one for the pool: a single lock held
        # across asyncssh.connect() serialises every server and undoes
        # the asyncio.gather in collect_all.
        self._pool_locks: dict[str, asyncio.Lock] = {}
        self._pool_lock = asyncio.Lock()  # guards _pool_locks itself
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
                    # Copy, or callers that decorate the result (traffic
                    # totals, renames) write straight into the cache.
                    stale = dict(cached)
                    stale["ping_ms"] = ping_ms
                    # Rates were measured cycles ago; logging them again
                    # invents traffic that never crossed the wire.
                    stale["rx_mbps"] = None
                    stale["tx_mbps"] = None
                    stale["stale"] = True
                    stale["error"] = f"stale ({count}): {exc}"
                    return stale
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
        # ping's -W bounds the reply wait but not name resolution, so a
        # wedged resolver leaves this await pending forever. That hangs
        # the whole collector loop without raising, which its try/except
        # cannot catch.
        try:
            stdout, _ = await asyncio.wait_for(
                process.communicate(),
                timeout=self._PING_TIMEOUT_SEC,
            )
        except (TimeoutError, asyncio.TimeoutError):
            try:
                process.kill()
                await process.wait()
            except (ProcessLookupError, OSError):
                pass
            logger.warning("ping to %s timed out", host)
            return None
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
            lock = self._pool_locks.get(key)
            if lock is None:
                lock = asyncio.Lock()
                self._pool_locks[key] = lock
        # Held per server, so a slow connect blocks only that server.
        async with lock:
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

    def forget_server(self, server: ServerConfig) -> None:
        """Drop per-server state when a server is removed or renamed.

        Only _previous used to be cleared, so ping caches, error counts
        and last-good snapshots accumulated for servers that no longer
        exist, and a pooled connection stayed open — keepalives and all
        — to a host the operator had already removed.
        """
        self._previous.pop(server.name, None)
        self._ping_cache.pop(server.name, None)
        self._ping_last_time.pop(server.name, None)
        self._error_counts.pop(server.name, None)
        self._last_good.pop(server.name, None)

        key = f"{server.host}:{server.port}:{server.user}"
        conn = self._pool.pop(key, None)
        self._pool_locks.pop(key, None)
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass

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
            self._pool_locks.clear()

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
        if isinstance(output, (bytes, bytearray)):
            output = output.decode(errors="ignore")
        elif not isinstance(output, str):
            output = str(output)
        # The snapshot is a few KB. A compromised host could answer
        # with hundreds of MB inside command_timeout; the parsers run
        # on the event loop, so this bounds what they ever see.
        if len(output) > _MAX_REMOTE_OUTPUT_CHARS:
            raise RuntimeError(
                f"Command output too large ({len(output)} chars)",
            )
        return output

    @staticmethod
    def _parse_cpu_line(output: str) -> tuple[int, int]:
        first_line = output.splitlines()[0].strip()
        parts = first_line.split()
        if len(parts) < 6 or parts[0] != "cpu":
            raise RuntimeError("Invalid /proc/stat format")

        # A malformed line must fail as a parse error, not as a raw
        # ValueError/IndexError: callers distinguish "bad output" from
        # a crash, and an unexpected type serves cached data for five
        # cycles as if it were current.
        try:
            values = [int(item) for item in parts[1:9]]
            cpu_total = sum(values)
            cpu_idle = values[3] + values[4]
        except (ValueError, IndexError) as exc:
            raise RuntimeError(
                f"Invalid /proc/stat values: {exc}",
            ) from exc
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
            # The name is stored in CSV and shown in the UI verbatim;
            # anything the kernel would not accept is not an interface.
            if not _IFACE_RE.fullmatch(iface):
                continue
            counters = counters_raw.split()
            if len(counters) < 16:
                continue
            # Any line with a colon and enough tokens reaches here — a
            # motd or sudo warning in the stream would otherwise raise
            # and fail the whole server's collection.
            try:
                rx_bytes = int(counters[0])
                tx_bytes = int(counters[8])
            except ValueError:
                continue
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
                # Unknown memory is reported as unknown; raising here
                # would hide it behind five cycles of cached values.
                try:
                    if parts[0] == "MemTotal:":
                        total_kb = int(parts[1])
                    elif parts[0] == "MemAvailable:":
                        avail_kb = int(parts[1])
                except ValueError:
                    return None, None
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
    # The bot token lives in here: create at 0600 and rename into
    # place, the same way auth.yaml is written.
    tmp_path = CONFIG_PATH.with_name(f".{CONFIG_PATH.name}.tmp")
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(dumped)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, CONFIG_PATH)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    CONFIG_PATH.chmod(0o600)


def _validate_unix_username(username: str, field_name: str) -> None:
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", username):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {field_name} format",
        )


# Keys the app generates itself live here, and only these may be
# deleted when a server is removed — client_key is caller-controlled.
_MANAGED_KEY_DIR = Path("~/.ssh")


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


def _is_managed_key(key_path: Path) -> bool:
    """True if the app generated this key and may delete it.

    Living in the managed directory is not enough: the operator's own
    ~/.ssh/id_ed25519 and unrelated keys share it. Only the naming
    pattern from _generate_ssh_key_pair qualifies.
    """
    managed_dir = _MANAGED_KEY_DIR.expanduser()
    try:
        resolved = key_path.expanduser().resolve()
        if resolved.parent != managed_dir.resolve():
            return False
    except OSError:
        return False
    return bool(re.fullmatch(r"id_ed25519_[A-Za-z0-9_-]+", resolved.name))


def _generate_ssh_key_pair(server_name: str) -> tuple[str, str]:
    """Generate ed25519 key pair. Returns (private_path, public_key_text)."""
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", server_name)
    ssh_dir = _MANAGED_KEY_DIR.expanduser()
    ssh_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    # mode= applies only when mkdir creates the directory; a pre-existing
    # ~/.ssh at 0755 would leave the key listing readable to everyone.
    try:
        ssh_dir.chmod(0o700)
    except OSError:
        logger.warning("could not tighten permissions on %s", ssh_dir)

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
# Cap on per-IP entries kept in memory and in auth.yaml.
_MAX_TRACKED_IPS = 1000


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

    def _prune(self, now: float) -> None:
        """Forget keys with no hits left in the window.

        Entries are only ever added while checking, so without this the
        table grows for every source address ever seen — and the login
        limiter is reachable before authentication.
        """
        cutoff = now - self._window
        for key in list(self._hits):
            live = [t for t in self._hits[key] if t > cutoff]
            if live:
                self._hits[key] = live
            else:
                del self._hits[key]
        # A flood of fresh addresses within one window still grows the
        # table, so cap it; the oldest entries go first.
        excess = len(self._hits) - _MAX_TRACKED_IPS
        if excess > 0:
            for key in list(self._hits)[:excess]:
                del self._hits[key]

    def is_limited(self, ip: str) -> bool:
        now = dt.datetime.now(dt.timezone.utc).timestamp()
        cutoff = now - self._window
        hits = [t for t in self._hits.get(ip, []) if t > cutoff]
        if len(hits) >= self._max:
            self._hits[ip] = hits
            return True
        hits.append(now)
        self._hits[ip] = hits
        if len(self._hits) > _MAX_TRACKED_IPS:
            self._prune(now)
        return False


def _limiter_key(ip: str) -> str:
    """Group an address into one rate-limit bucket.

    A single IPv6 host is routinely handed a whole /64, so keying on the
    exact address lets one client cycle through billions of them. IPv4
    addresses are used as-is.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    # A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d, and
    # every one of those shares the ::/64 prefix — grouping them would
    # let one client's failures lock out everybody else.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


_api_limiter = _RateLimiter(max_requests=30, window_sec=60)

# Login is the one endpoint an unauthenticated caller may hammer, so it
# gets a tighter budget than the authenticated API.
_LOGIN_MAX_PER_WINDOW = 10
_LOGIN_WINDOW_SEC = 300
_login_limiter = _RateLimiter(
    max_requests=_LOGIN_MAX_PER_WINDOW,
    window_sec=_LOGIN_WINDOW_SEC,
)

# The per-IP limiter is trivially spread across many addresses, and a
# login costs a PBKDF2 round: one shared budget bounds the total CPU an
# unauthenticated crowd can burn.
_LOGIN_GLOBAL_MAX_PER_MINUTE = 60
_login_global_limiter = _RateLimiter(
    max_requests=_LOGIN_GLOBAL_MAX_PER_MINUTE,
    window_sec=60,
)
_GLOBAL_KEY = "*"

_RATE_LIMITED_PREFIXES = (
    "/api/servers",
    "/api/bot",
    "/api/interval",
    "/api/ssh_mode",
    "/api/auth/settings",
    "/api/auth/tokens",
)


# ---- auth system ----
_AUTH_PATH = Path("config/auth.yaml")
_AUTH_LOCK = Lock()
_MAX_LOGIN_ATTEMPTS = 5
_BLOCK_MINUTES = 30
_SESSION_COOKIE = "sid"
_MAX_HISTORY = 20
_SESSION_MAX_AGE_DAYS = 30
# A client that logs in on every poll without keeping its cookie would
# otherwise accumulate a session per request, forever.
_MAX_SESSIONS_PER_IP = 10
_PBKDF2_ITERATIONS = 600_000
_MIN_PASSWORD_LENGTH = 8
# Second factor: a one-time code sent to the configured Telegram chat.
_PENDING_COOKIE = "sid_pending"
_2FA_CODE_TTL_SEC = 300
_2FA_CODE_DIGITS = 6
# One-time token gating first-run setup; None once a password exists.
_setup_token: str | None = None


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
    two_factor: bool = False
    # name -> {"hash": sha256 hex, "created": iso}. Read-only bearer
    # tokens for scripts that poll /api/metrics and cannot answer a
    # Telegram code; the plaintext is shown once at creation.
    api_tokens: dict[str, dict[str, str]] = dc_field(
        default_factory=dict,
    )


_API_TOKEN_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,40}")
_MAX_API_TOKENS = 20


def _hash_api_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _bearer_token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def _match_api_token(token: str) -> str | None:
    """Return the token's name, or None. Constant-time per entry."""
    digest = _hash_api_token(token)
    for name, entry in _auth.api_tokens.items():
        if hmac.compare_digest(digest, entry.get("hash", "")):
            return name
    return None


def _session_age_ok(created: str | None) -> bool:
    if not created:
        return False  # no timestamp = legacy, treat as expired
    try:
        ts = dt.datetime.fromisoformat(created)
    except ValueError:
        return False
    age = dt.datetime.now(dt.timezone.utc) - ts
    return age.days <= _SESSION_MAX_AGE_DAYS


def _prune_sessions(state: _AuthState) -> None:
    """Drop expired sessions and cap how many one address may hold.

    Expiry used to be checked only when a token was presented, so a
    session that was never used again lived in auth.yaml indefinitely.
    Caller holds _AUTH_LOCK (or owns the state).
    """
    for tok in list(state.sessions):
        if not _session_age_ok(state.session_created.get(tok)):
            state.sessions.pop(tok, None)
            state.session_created.pop(tok, None)
    by_ip: dict[str, list[str]] = {}
    for tok, ip in state.sessions.items():
        by_ip.setdefault(ip, []).append(tok)
    for toks in by_ip.values():
        excess = len(toks) - _MAX_SESSIONS_PER_IP
        if excess <= 0:
            continue
        toks.sort(key=lambda t: state.session_created.get(t, ""))
        for tok in toks[:excess]:
            state.sessions.pop(tok, None)
            state.session_created.pop(tok, None)


def _load_auth() -> _AuthState:
    if not _AUTH_PATH.exists():
        return _AuthState()
    raw = yaml.safe_load(
        _AUTH_PATH.read_text(encoding="utf-8"),
    )
    # An absent or empty file is a first run. A file that exists with
    # content but no password_hash is damage — a kill mid-write leaves
    # valid YAML behind — and must not degrade into "no password set",
    # which would unlock every endpoint.
    if raw is None or raw == "":
        return _AuthState()
    if not isinstance(raw, dict) or "password_hash" not in raw:
        raise RuntimeError(
            f"{_AUTH_PATH} is corrupted: no password_hash. Refusing to "
            f"start unauthenticated. Restore it or delete it to start over."
        )
    state = _AuthState(
        password_hash=raw.get("password_hash", ""),
        allowed_networks=raw.get(
            "allowed_networks", [],
        ),
        sessions=raw.get("sessions", {}),
        session_created=raw.get("session_created", {}),
        fail_counts=raw.get("fail_counts", {}),
        blocked_until=raw.get("blocked_until", {}),
        history=raw.get("history", []),
        two_factor=bool(raw.get("two_factor", False)),
        api_tokens=raw.get("api_tokens", {}) or {},
    )
    _prune_sessions(state)
    return state


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
        "two_factor": state.two_factor,
        "api_tokens": state.api_tokens,
    }
    # Session tokens and the password hash are stored in the clear, so
    # the file must never be world-readable. Set the mode before writing
    # rather than after, or the contents sit at the umask default for
    # the duration of the write.
    # Write to a sibling and rename: a kill or a full disk partway
    # through would otherwise leave valid-but-truncated YAML, which
    # _load_auth reads as "no password set".
    tmp_path = _AUTH_PATH.with_name(f".{_AUTH_PATH.name}.tmp")
    fd = os.open(
        tmp_path,
        os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
        0o600,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            yaml.safe_dump(
                data, fh, sort_keys=False, allow_unicode=True,
            )
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, _AUTH_PATH)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise
    # O_CREAT only applies the mode to a new file; one deployed at 0644
    # keeps its old permissions without this.
    _AUTH_PATH.chmod(0o600)


def _prune_login_state() -> None:
    """Drop expired blocks and cap how much failure state is kept.

    fail_counts and blocked_until are persisted to auth.yaml on every
    failed login, so an unbounded dictionary is both a memory leak and a
    growing disk write on each attempt.
    """
    now = dt.datetime.now(dt.timezone.utc)
    for ip, until in list(_auth.blocked_until.items()):
        try:
            if dt.datetime.fromisoformat(until) <= now:
                _auth.blocked_until.pop(ip, None)
                _auth.fail_counts.pop(ip, None)
        except ValueError:
            _auth.blocked_until.pop(ip, None)

    # Still oversized after expiry: drop the oldest entries first, but
    # never evict an address that is currently blocked — that would hand
    # an attacker a way to clear their own block by flooding new IPs.
    excess = len(_auth.fail_counts) - _MAX_TRACKED_IPS
    if excess > 0:
        for ip in list(_auth.fail_counts):
            if excess <= 0:
                break
            if ip in _auth.blocked_until:
                continue
            _auth.fail_counts.pop(ip, None)
            excess -= 1
    excess = len(_auth.blocked_until) - _MAX_TRACKED_IPS
    if excess > 0:
        for ip in list(_auth.blocked_until)[:excess]:
            _auth.blocked_until.pop(ip, None)
            _auth.fail_counts.pop(ip, None)


def _record_login_failure(ip: str) -> int:
    """Count a failed attempt, blocking the address past the threshold.

    Keys on the limiter prefix rather than the exact address, so an
    IPv6 client cannot spread attempts across its own /64 and never
    reach the threshold. Returns attempts remaining before the block.
    """
    ip = _limiter_key(ip)
    with _AUTH_LOCK:
        count = _auth.fail_counts.get(ip, 0) + 1
        _auth.fail_counts[ip] = count
        if count >= _MAX_LOGIN_ATTEMPTS:
            until = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
                minutes=_BLOCK_MINUTES,
            )
            _auth.blocked_until[ip] = until.isoformat()
            _auth.fail_counts[ip] = 0
        # Prune after recording, so this address is not evicted by its
        # own insertion and the caps actually hold.
        _prune_login_state()
        _save_auth(_auth)
    return _MAX_LOGIN_ATTEMPTS - count


def _ensure_setup_token() -> str | None:
    """Mint a one-time token when no password is configured.

    Without this an unconfigured dashboard served every endpoint to
    anyone who could reach the port. The token is printed to the journal
    at startup and is the only way to set the first password.
    """
    global _setup_token
    if _auth.password_hash:
        _setup_token = None
        return None
    if _setup_token is None:
        _setup_token = secrets.token_urlsafe(32)
    return _setup_token


def _check_setup_token(provided: str | None) -> bool:
    """Constant-time check of the first-run setup token."""
    if not _setup_token or not provided:
        return False
    return secrets.compare_digest(provided, _setup_token)


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
    # A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d, which
    # never matches an IPv4 network — the operator's own whitelist would
    # lock them out.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    for net_str in networks:
        try:
            net = ipaddress.ip_network(
                net_str.strip(), strict=False,
            )
        except ValueError:
            # No string-equality fallback: "192.168.1.5 " and
            # "::ffff:192.168.1.5" are the same address written
            # differently, and comparing text gets both wrong.
            logger.warning(
                "ignoring malformed whitelist entry %r", net_str,
            )
            continue
        if addr in net:
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
    "/api/auth/verify",
    "/api/auth/status",
    "/api/health",
}

# Reachable before a password exists — just enough to complete setup.
_SETUP_PATHS = {
    "/",
    "/api/auth/status",
    "/api/auth/settings",
    "/api/health",
}


def _session_expired(token: str) -> bool:
    """Check if session has exceeded max age."""
    return not _session_age_ok(_auth.session_created.get(token))


def _cookie_secure(request: Request) -> bool:
    """Mark cookies Secure whenever the client actually used TLS.

    Behind nginx the scheme comes from X-Forwarded-Proto via uvicorn's
    proxy handling. HSTS does not help here: browsers ignore it for a
    bare IP address, and the dashboard is reached by one.
    """
    return request.url.scheme == "https"


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
    # No password configured: serve only what first-run setup needs.
    # Everything else stays shut, so an unconfigured dashboard is not a
    # a way in for anyone who can reach the port.
    if not _auth.password_hash:
        if path in _SETUP_PATHS:
            return await call_next(request)
        return JSONResponse(
            {
                "detail": (
                    "Dashboard is not configured. Set a password using "
                    "the setup token from the service log "
                    "(journalctl -u servers-info-dash)."
                ),
                "needs_setup": True,
            },
            status_code=403,
        )
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
    # API token: scripted read access, no cookie, no second factor.
    bearer = _bearer_token(request)
    if bearer is not None:
        if request.method not in ("GET", "HEAD"):
            return JSONResponse(
                {"detail": "API tokens are read-only"}, status_code=403,
            )
        if _match_api_token(bearer) is None:
            # 256-bit tokens are not guessable, but a stream of bad ones
            # should still cost the sender its login budget.
            _login_limiter.is_limited(_limiter_key(ip))
            return JSONResponse(
                {"detail": "Invalid API token"}, status_code=401,
            )
        return await call_next(request)
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


# The script lives in its own file so the policy can forbid inline
# script entirely; inline styles remain (style="" in generated rows).
_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'self'"
)


# Registered after auth_middleware, which makes it the outer layer:
# the login page and the 401/403/429 short-circuits above get the
# headers too, instead of only responses that reached a route.
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
    # The legacy auditor is removed from browsers and could be abused
    # for cross-site leaks; CSP is the replacement.
    response.headers["X-XSS-Protection"] = "0"
    response.headers["Content-Security-Policy"] = _CSP
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    return response


# ---- server metrics log ----
_LOGS_DIR = Path("logs")
_LOGS_DIR.mkdir(exist_ok=True)
_LOG_RETENTION_DAYS = 30
_TRAFFIC_30D_CACHE_TTL_SEC = 300
_TRAFFIC_1D_CACHE_TTL_SEC = 60
# how many refresh intervals may pass before /api/health reports 503
_HEALTH_MAX_AGE_CYCLES = 3
# a cycle is abandoned after this many refresh intervals
_CYCLE_TIMEOUT_CYCLES = 4
# gaps longer than this are treated as a collector outage, not traffic
_MAX_SAMPLE_GAP_SEC = 900

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
    # UTC, matching the timestamps written into the rows: a local date
    # would put rows from one UTC day into a file named for another.
    today = dt.datetime.now(dt.timezone.utc).date().isoformat()
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
        if not fieldnames:
            fieldnames = _CSV_COLUMNS
        with log_path.open("a", encoding="utf-8", newline="") as fh:
            # extrasaction="ignore": the header comes from the file, so a
            # legacy or hand-edited one naming its first column something
            # else would otherwise raise and kill logging for the day.
            writer = csv.DictWriter(
                fh, fieldnames=fieldnames, extrasaction="ignore",
            )
            if write_header:
                writer.writeheader()
            row = {
                fieldnames[0]: dt.datetime.now(
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
    cutoff = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(
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


def _read_traffic_rows(
    file_path: Path,
) -> list[tuple[str, str, str, str]]:
    """Read (name, rx, tx, timestamp) rows from one CSV log file.

    The timestamp is needed to turn instantaneous Mbit/s samples into a
    volume: the gap between consecutive rows is the period each sample
    stands for, and it is not necessarily today's refresh interval.

    Raises csv.Error on corrupted files (e.g. NUL bytes), letting
    callers skip that file instead of failing the whole calculation.
    """
    rows: list[tuple[str, str, str, str]] = []
    with file_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        _ = next(reader, None)  # header
        for values in reader:
            # csv.reader accepts NUL bytes and hands them back inside
            # the fields, so a log truncated by a crash would otherwise
            # feed \x00 into the traffic sums instead of being skipped.
            if any("\x00" in value for value in values):
                raise csv.Error(
                    f"NUL byte in {file_path.name}, file is corrupted",
                )
            # Handle mixed schemas in legacy files:
            # old: 12 columns, new: 15 columns.
            if len(values) >= 15:
                rows.append((
                    values[1] if len(values) > 1 else "",
                    values[11] if len(values) > 11 else "",
                    values[12] if len(values) > 12 else "",
                    values[0] if values else "",
                ))
            elif len(values) >= 12:
                rows.append((
                    values[1] if len(values) > 1 else "",
                    values[8] if len(values) > 8 else "",
                    values[9] if len(values) > 9 else "",
                    values[0] if values else "",
                ))
    return rows


def _sample_period_sec(
    timestamp: str,
    previous: dt.datetime | None,
) -> tuple[float | None, dt.datetime | None]:
    """Seconds a sample covers, from the gap to the previous row.

    Returns (period, parsed timestamp). The period is None for the first
    row of a series and for gaps too long to be one interval — a
    collector outage must not be billed as continuous traffic.
    """
    try:
        parsed = dt.datetime.strptime(timestamp.strip(), "%Y-%m-%d %H:%M")
    except (ValueError, AttributeError):
        return None, previous
    if previous is None:
        return None, parsed
    gap = (parsed - previous).total_seconds()
    if gap <= 0 or gap > _MAX_SAMPLE_GAP_SEC:
        return None, parsed
    return gap, parsed


def _calculate_traffic_30d_gb() -> dict[str, float]:
    """Calculate per-server RX+TX traffic for the last 30 days."""
    cutoff = dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=30)
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

        try:
            rows = _read_traffic_rows(file_path)
        except (OSError, csv.Error, UnicodeDecodeError):
            logger.exception(
                "skipping unreadable traffic log %s", file_path.name,
            )
            continue

        # Tracked per server: rows for different servers interleave
        # within one file, so a shared cursor would measure the wrong gap.
        last_seen: dict[str, dt.datetime | None] = {}
        for row_name, rx_raw, tx_raw, row_ts in rows:
            row_key = (
                _safe_filename(row_name)
                if row_name
                else safe_name
            )
            period_sec, parsed = _sample_period_sec(
                row_ts, last_seen.get(row_key),
            )
            last_seen[row_key] = parsed
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
            if period_sec is None:
                # First sample of a series, or a gap too long to trust.
                continue
            row_total = totals_raw.get(row_key, 0.0)
            period_megabits = (rx + tx) * period_sec
            period_megabytes = period_megabits / 8.0
            period_gigabytes = period_megabytes / 1000.0
            row_total += period_gigabytes
            totals_raw[row_key] = row_total

    return {
        key: round(value, 3)
        for key, value in totals_raw.items()
    }


def _calculate_traffic_1d_gb() -> dict[str, float]:
    """Calculate per-server RX+TX traffic for the last 24 hours."""
    # The filename only narrows which files to open; the window itself
    # is measured against the row timestamps, or "one day" would mean
    # today-plus-yesterday — up to 48 hours, halving at each midnight.
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    window_start = now - dt.timedelta(days=1)
    cutoff = window_start.date()
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

        try:
            rows = _read_traffic_rows(file_path)
        except (OSError, csv.Error, UnicodeDecodeError):
            logger.exception(
                "skipping unreadable traffic log %s", file_path.name,
            )
            continue

        # Tracked per server: rows for different servers interleave
        # within one file, so a shared cursor would measure the wrong gap.
        last_seen: dict[str, dt.datetime | None] = {}
        for row_name, rx_raw, tx_raw, row_ts in rows:
            row_key = (
                _safe_filename(row_name)
                if row_name
                else safe_name
            )
            period_sec, parsed = _sample_period_sec(
                row_ts, last_seen.get(row_key),
            )
            last_seen[row_key] = parsed
            if parsed is not None and parsed < window_start:
                # Outside the 24h window; still recorded above so the
                # first in-window sample measures its gap correctly.
                continue
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
            if period_sec is None:
                # First sample of a series, or a gap too long to trust.
                continue
            row_total = totals_raw.get(row_key, 0.0)
            period_megabits = (rx + tx) * period_sec
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


def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a message via Telegram Bot API (sync). True on success."""
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
        return False
    return True


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
        is_down = srv.get("status") == "down"

        # --- check each metric ---
        if bot.notify_down and is_down:
            counts["down"] = counts.get("down", 0) + 1
        else:
            counts["down"] = 0
        if counts.get("down", 0) >= delay:
            triggered.add("down")

        # Every metric reads None while the host is unreachable, and the
        # threshold checks below cannot tell that apart from "back under
        # the threshold": they would reset the counters and report a
        # recovery in the same message as the outage. Snapshot the
        # counters now and restore them afterwards, so a down host
        # freezes its metric alerts instead of clearing them.
        frozen = dict(counts) if is_down else None

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
        if frozen is not None:
            # Host is down: keep the metric counters and alerts exactly
            # as they were, so only the outage itself is reported.
            counts.clear()
            counts.update(frozen)
            counts["down"] = frozen.get("down", 0) + 1
            triggered = (triggered & {"down"}) | (prev - {"down"})
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


async def _run_collector_cycle(rotation_counter: int) -> int:
    """One collection pass. Returns the updated rotation counter."""
    global _cached_metrics
    data = await collector.collect_all()
    # traffic maps re-read every CSV log file, which takes
    # seconds once logs grow — keep it off the event loop
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None, _attach_traffic_30d, data["servers"],
    )
    await loop.run_in_executor(
        None, _attach_traffic_1d, data["servers"],
    )
    data["ready"] = True
    async with _metrics_lock:
        _cached_metrics = data
    await _check_and_notify(data["servers"])
    # write metrics to CSV log files
    await loop.run_in_executor(
        None, _log_server_metrics, data["servers"],
    )
    # rotate old logs once every ~100 cycles
    rotation_counter += 1
    if rotation_counter >= 100:
        rotation_counter = 0
        await loop.run_in_executor(
            None, _rotate_logs,
        )
    return rotation_counter


async def _background_collector() -> None:
    rotation_counter = 0
    while True:
        try:
            # A cycle that hangs — a wedged executor thread, a socket
            # that never answers — would otherwise stop collection for
            # good: try/except only catches raising, not waiting.
            rotation_counter = await asyncio.wait_for(
                _run_collector_cycle(rotation_counter),
                timeout=cfg.refresh_interval_sec * _CYCLE_TIMEOUT_CYCLES,
            )
        except (TimeoutError, asyncio.TimeoutError):
            logger.error(
                "collector cycle exceeded %ss, abandoning it",
                cfg.refresh_interval_sec * _CYCLE_TIMEOUT_CYCLES,
            )
        except Exception:  # noqa: BLE001
            logger.exception("background collector cycle failed")
        await asyncio.sleep(cfg.refresh_interval_sec)


@app.on_event("startup")
async def _start_background_tasks() -> None:
    token = _ensure_setup_token()
    if token:
        logger.warning(
            "No password configured. Open the dashboard and set one "
            "using this setup token: %s",
            token,
        )
    asyncio.create_task(_background_collector())


@app.on_event("shutdown")
async def _stop_background_tasks() -> None:
    # Without this the pooled SSH connections are torn down by process
    # exit rather than closed, leaving sessions on the monitored hosts
    # to time out on their own.
    try:
        await collector.close_pool()
    except Exception:  # noqa: BLE001
        logger.warning("failed to close SSH pool cleanly", exc_info=True)


# ---- auth endpoints ----

class _LoginRequest(BaseModel):
    password: str = Field(max_length=200)


class _VerifyRequest(BaseModel):
    code: str = Field(max_length=16)


class _SecuritySettingsRequest(BaseModel):
    current_password: str | None = None
    password: str | None = None
    allowed_networks: list[str] = []
    setup_token: str | None = None  # first run only
    two_factor: bool | None = None  # None = leave unchanged


# Half-open logins: password accepted, Telegram code not yet entered.
# In memory only — a restart simply asks for the password again.
_pending_2fa: dict[str, dict[str, Any]] = {}


def _bot_ready() -> bool:
    return bool(cfg.bot.token and cfg.bot.chat_id)


def _prune_pending(now_ts: float) -> None:
    for tok, entry in list(_pending_2fa.items()):
        if now_ts - entry["created"] > _2FA_CODE_TTL_SEC:
            _pending_2fa.pop(tok, None)


def _login_throttled(ip_key: str) -> JSONResponse | None:
    """Shared gate for both login steps: limiters, then the IP block."""
    if (
        _login_limiter.is_limited(ip_key)
        or _login_global_limiter.is_limited(_GLOBAL_KEY)
    ):
        return JSONResponse(
            {"detail": "Too many login attempts"},
            status_code=429,
        )
    blocked_ts = _auth.blocked_until.get(ip_key)
    if blocked_ts:
        now = dt.datetime.now(dt.timezone.utc)
        try:
            until = dt.datetime.fromisoformat(blocked_ts)
            if now < until:
                diff = int((until - now).total_seconds())
                return JSONResponse(
                    {"detail": f"Blocked for {diff}s"},
                    status_code=429,
                )
        except ValueError:
            pass
        with _AUTH_LOCK:
            _auth.blocked_until.pop(ip_key, None)
            _auth.fail_counts.pop(ip_key, None)
            _save_auth(_auth)
    return None


def _failure_response(ip_key: str, what: str) -> JSONResponse:
    remaining = _record_login_failure(ip_key)
    if remaining <= 0:
        return JSONResponse(
            {"detail": f"Blocked for {_BLOCK_MINUTES} min"},
            status_code=429,
        )
    return JSONResponse(
        {"detail": what, "remaining": remaining},
        status_code=403,
    )


async def _issue_session(
    request: Request, ip: str, ip_key: str,
) -> JSONResponse:
    """Both factors passed: record the login and set the cookie."""
    now = dt.datetime.now(dt.timezone.utc)
    token = secrets.token_urlsafe(32)
    ua = request.headers.get("user-agent", "")
    # Country is decoration for the login history; a third-party lookup
    # being down must not stop anyone signing in.
    try:
        country = await asyncio.get_running_loop(
        ).run_in_executor(None, _geo_lookup, ip)
    except Exception:  # noqa: BLE001
        logger.warning("geo lookup failed for %s", ip, exc_info=True)
        country = ""
    with _AUTH_LOCK:
        _prune_sessions(_auth)
        _auth.sessions[token] = ip
        _auth.session_created[token] = (
            now.isoformat()
        )
        # Keyed like the failure path, or a success would never clear
        # the block it was counted against.
        _auth.fail_counts.pop(ip_key, None)
        _auth.blocked_until.pop(ip_key, None)
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
        _prune_sessions(_auth)
        _save_auth(_auth)

    resp = JSONResponse({"status": "ok"})
    resp.set_cookie(
        _SESSION_COOKIE,
        token,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=_SESSION_MAX_AGE_DAYS * 86400,
    )
    resp.delete_cookie(_PENDING_COOKIE)
    return resp


async def _send_2fa_code(ip: str) -> str | None:
    """Mail a fresh code to Telegram; returns the code, or None if unsent."""
    code = str(
        secrets.randbelow(10 ** _2FA_CODE_DIGITS),
    ).zfill(_2FA_CODE_DIGITS)
    text = (
        "🔐 <b>Код входа в дашборд</b>\n"
        f"<code>{code}</code>\n"
        f"IP: {ip}\n"
        f"Действует {_2FA_CODE_TTL_SEC // 60} минут. "
        "Если это не вы — смените пароль."
    )
    sent = await asyncio.get_running_loop().run_in_executor(
        None, _send_telegram, cfg.bot.token, cfg.bot.chat_id, text,
    )
    return code if sent else None


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
    # Both the limiter and the failure counter key on the prefix, so an
    # IPv6 client cannot dodge either by walking its own /64.
    ip_key = _limiter_key(ip)
    # Rate limit before touching the password: the per-IP failure counter
    # below resets on block expiry, which on its own allows sustained
    # guessing.
    throttled = _login_throttled(ip_key)
    if throttled is not None:
        return throttled

    if not _auth.password_hash:
        return JSONResponse(
            {"detail": "No password set"},
            status_code=400,
        )

    # PBKDF2 takes a good fraction of a second; off the loop so a burst
    # of bad passwords does not stall the collector and everyone else.
    ok = await asyncio.get_running_loop().run_in_executor(
        None, _verify_password, payload.password, _auth.password_hash,
    )
    if not ok:
        return _failure_response(ip_key, "Wrong password")

    if not (_auth.two_factor and _bot_ready()):
        return await _issue_session(request, ip, ip_key)

    # Second factor: hand out a code and a short-lived pending cookie.
    now_ts = dt.datetime.now(dt.timezone.utc).timestamp()
    _prune_pending(now_ts)
    code = await _send_2fa_code(ip)
    if code is None:
        return JSONResponse(
            {"detail": "Could not send the code via Telegram"},
            status_code=503,
        )
    pending = secrets.token_urlsafe(32)
    _pending_2fa[pending] = {
        "code": code, "ip": ip, "created": now_ts,
    }
    resp = JSONResponse({"status": "2fa_required"})
    resp.set_cookie(
        _PENDING_COOKIE,
        pending,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=_2FA_CODE_TTL_SEC,
    )
    return resp


@app.post("/api/auth/verify")
async def auth_verify(
    payload: _VerifyRequest,
    request: Request,
) -> JSONResponse:
    ip = _client_ip(request)
    ip_key = _limiter_key(ip)
    throttled = _login_throttled(ip_key)
    if throttled is not None:
        return throttled

    now_ts = dt.datetime.now(dt.timezone.utc).timestamp()
    _prune_pending(now_ts)
    pending = request.cookies.get(_PENDING_COOKIE)
    entry = _pending_2fa.get(pending) if pending else None
    if entry is None or entry["ip"] != ip:
        resp = JSONResponse(
            {"detail": "Login expired, start again"},
            status_code=401,
        )
        resp.delete_cookie(_PENDING_COOKIE)
        return resp

    if not hmac.compare_digest(
        payload.code.strip(), entry["code"],
    ):
        # A wrong code counts like a wrong password: five of them block
        # the address, and the block ends this pending login too.
        resp = _failure_response(ip_key, "Wrong code")
        if resp.status_code == 429:
            _pending_2fa.pop(pending, None)
            resp.delete_cookie(_PENDING_COOKIE)
        return resp

    _pending_2fa.pop(pending, None)
    return await _issue_session(request, ip, ip_key)


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
    # Reachable unauthenticated before setup, where the whitelist and
    # login history would be free reconnaissance. Setup only needs to
    # know whether a password exists.
    if not _auth.password_hash:
        return {
            "has_password": False,
            "allowed_networks": [],
            "history": [],
            "two_factor": False,
            "bot_ready": False,
        }
    return {
        "has_password": True,
        "allowed_networks": _auth.allowed_networks,
        "history": _auth.history[-_MAX_HISTORY:],
        "two_factor": _auth.two_factor,
        "bot_ready": _bot_ready(),
        "api_tokens": [
            {"name": name, "created": entry.get("created", "")}
            for name, entry in _auth.api_tokens.items()
        ],
    }


class _CreateTokenRequest(BaseModel):
    name: str = Field(max_length=40)
    current_password: str = Field(max_length=200)


@app.post("/api/auth/tokens", status_code=201)
async def create_api_token(
    payload: _CreateTokenRequest,
) -> dict[str, str]:
    """Mint a read-only bearer token; the plaintext is returned once."""
    name = payload.name.strip()
    if not _API_TOKEN_NAME_RE.fullmatch(name):
        raise HTTPException(
            status_code=400,
            detail="Token name: letters, digits, . _ - (max 40)",
        )
    ok = await asyncio.get_running_loop().run_in_executor(
        None, _verify_password, payload.current_password, _auth.password_hash,
    )
    if not ok:
        raise HTTPException(
            status_code=403, detail="Current password is incorrect",
        )
    token = secrets.token_urlsafe(32)
    with _AUTH_LOCK:
        if name in _auth.api_tokens:
            raise HTTPException(
                status_code=409, detail="A token with this name exists",
            )
        if len(_auth.api_tokens) >= _MAX_API_TOKENS:
            raise HTTPException(
                status_code=400, detail="Too many tokens, revoke one first",
            )
        _auth.api_tokens[name] = {
            "hash": _hash_api_token(token),
            "created": dt.datetime.now(dt.timezone.utc).strftime(
                "%Y-%m-%d %H:%M",
            ),
        }
        _save_auth(_auth)
    return {"name": name, "token": token}


@app.delete("/api/auth/tokens/{name}")
async def revoke_api_token(name: str) -> dict[str, str]:
    with _AUTH_LOCK:
        if _auth.api_tokens.pop(name, None) is None:
            raise HTTPException(status_code=404, detail="No such token")
        _save_auth(_auth)
    return {"status": "ok"}


@app.put("/api/auth/settings")
async def update_auth_settings(
    payload: _SecuritySettingsRequest,
) -> dict[str, Any]:
    # Before a password exists the whole endpoint is reachable, so the
    # token gates every field — not just the password. Otherwise a
    # payload carrying only allowed_networks slips through and can pin
    # the whitelist to an attacker's address.
    if not _auth.password_hash and not _check_setup_token(
        payload.setup_token,
    ):
        raise HTTPException(
            status_code=403,
            detail=(
                "Invalid setup token. Find it in the service log: "
                "journalctl -u servers-info-dash"
            ),
        )
    if payload.password and len(payload.password) < _MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Password must be at least "
                f"{_MIN_PASSWORD_LENGTH} characters"
            ),
        )
    # Changing the password or the second factor re-proves the current
    # password. Verified before taking the lock: PBKDF2 runs in a
    # thread, and awaiting while holding _AUTH_LOCK would freeze the
    # loop for anyone else who needs it meanwhile.
    two_factor_change = (
        payload.two_factor is not None
        and payload.two_factor != _auth.two_factor
    )
    if _auth.password_hash and (payload.password or two_factor_change):
        current_ok = bool(payload.current_password) and (
            await asyncio.get_running_loop().run_in_executor(
                None,
                _verify_password,
                payload.current_password or "",
                _auth.password_hash,
            )
        )
        if not current_ok:
            raise HTTPException(
                status_code=403,
                detail="Current password is incorrect",
            )
    if two_factor_change and payload.two_factor:
        if not _bot_ready():
            raise HTTPException(
                status_code=400,
                detail="Configure the Telegram bot (token and chat) first",
            )
        # Prove the chat is reachable now, or the next login would be
        # the moment to find out that it is not.
        sent = await asyncio.get_running_loop().run_in_executor(
            None,
            _send_telegram,
            cfg.bot.token,
            cfg.bot.chat_id,
            "🔐 Двухфакторный вход в дашборд включён. "
            "Коды подтверждения будут приходить в этот чат.",
        )
        if not sent:
            raise HTTPException(
                status_code=502,
                detail="Telegram did not accept the test message",
            )
    with _AUTH_LOCK:
        if payload.password:
            # First run needs no current password: the setup token
            # checked above already stands in for it.
            _auth.password_hash = _hash_password(
                payload.password,
            )
            _ensure_setup_token()  # password now set -> token retired
        if two_factor_change and _auth.password_hash:
            _auth.two_factor = bool(payload.two_factor)
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
        "two_factor": _auth.two_factor,
    }


@app.get("/")
async def index() -> FileResponse:
    return FileResponse("app/static/index.html")


@app.get("/api/metrics")
async def metrics() -> dict[str, Any]:
    async with _metrics_lock:
        return _cached_metrics


@app.get("/api/health")
async def health(response: Response) -> dict[str, Any]:
    """Report collector liveness, not just that HTTP is up.

    Returns 503 while the collector has never completed a cycle or
    its last result is older than _HEALTH_MAX_AGE_CYCLES intervals,
    so deploys and external probes catch a dead collector.
    """
    async with _metrics_lock:
        ready = bool(_cached_metrics.get("ready"))
        generated_at = str(_cached_metrics.get("generated_at", ""))

    age_sec: float | None = None
    try:
        ts = dt.datetime.fromisoformat(generated_at)
    except ValueError:
        ts = None
    if ts is not None:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        now = dt.datetime.now(dt.timezone.utc)
        age_sec = round((now - ts).total_seconds(), 1)

    max_age = cfg.refresh_interval_sec * _HEALTH_MAX_AGE_CYCLES
    stale = age_sec is None or age_sec > max_age
    healthy = ready and not stale
    if not healthy:
        response.status_code = 503

    return {
        "status": "ok" if healthy else "degraded",
        "ready": ready,
        "generated_at": generated_at,
        "age_sec": age_sec,
        "max_age_sec": max_age,
    }


def _csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formulas in text cells.

    Text columns (name, interface, error) carry strings a monitored host
    can influence; a leading = + - @ or tab makes Excel/LibreOffice
    evaluate the cell. Numbers are left alone so they stay numbers.
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in "=+-@\t\r":
        try:
            float(value)
            return value
        except ValueError:
            return "'" + value
    return value


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
        try:
            with fp.open(encoding="utf-8", newline="") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    filtered = {
                        k: _csv_cell(row.get(k, ""))
                        for k in _CSV_COLUMNS
                    }
                    writer.writerow(filtered)
        except csv.Error:
            # One damaged day (a NUL from an unclean shutdown) should
            # not make every other day undownloadable.
            logger.warning("skipping unreadable log %s", fp, exc_info=True)
            continue

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
        collector.forget_server(removed)

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
    # A caller-supplied client_key may point anywhere; deleting it would
    # remove arbitrary files as the app user (root in production). Check
    # and delete the same resolved path, so a symlink cannot make the
    # two disagree about which file is meant.
    if not _is_managed_key(Path(client_key)):
        return
    key_path = Path(client_key).expanduser().resolve()
    # ".pub" must be appended, not substituted: with_suffix turns
    # "config.yaml" into "config.pub" — a file the caller never named.
    pub_path = Path(str(key_path) + ".pub")

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

        # Carry per-server state across the rename. Dropping it would
        # restart CPU/network deltas and, because _notified_state is
        # keyed by name, resend every alert already firing as if new.
        for store in (
            collector._previous,
            collector._ping_cache,
            collector._ping_last_time,
            collector._error_counts,
            collector._last_good,
            _notified_state,
            _trigger_counts,
        ):
            value = store.pop(old, None)
            if value is not None:
                store[new] = value
        srv.name = new
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
