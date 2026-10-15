"""Вкладка «Проекты»: доступность сайтов, сроки TLS и сводки приложений.

Конфиг — config/projects.yaml (в .gitignore: в нём токены сводок). Сборщик ходит
наружу по HTTPS и читает локальные файлы, которые пишут root-кроны
(deploy/collectors/), сам ни к чему не подключается по SSH.
"""

import asyncio
import datetime as dt
import json
import logging
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger("serverinfo.projects")

CONFIG_PATH = Path("config/projects.yaml")
_HTTP_TIMEOUT = 15
_SLOW_MS = 3000
_TLS_WARN_DAYS = 21
_TLS_BAD_DAYS = 7
_MAX_BODY = 256 * 1024


class SummarySource(BaseModel):
    kind: Literal["amnpanel", "file"]
    url: str | None = None
    token: str | None = None
    path: str | None = None
    # Файл сводки старше этого считается протухшим: крон пишет его раз в 10 мин.
    max_age_min: int = 30


class ProjectConfig(BaseModel):
    name: str
    stage: str = ""
    link: str | None = None
    check_url: str | None = None
    tls_host: str | None = None
    note: str = ""
    summary: SummarySource | None = None


class ProjectsConfig(BaseModel):
    refresh_sec: int = Field(default=300, ge=60, le=3600)
    projects: list[ProjectConfig] = []
    # Домены, у которых важен только срок сертификата (общий сертификат на хосте и т.п.)
    tls_hosts: list[str] = []


def load_projects_config(path: Path = CONFIG_PATH) -> ProjectsConfig:
    if not path.exists():
        return ProjectsConfig()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return ProjectsConfig.model_validate(data)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def probe_http(url: str) -> dict[str, Any]:
    started = time.monotonic()
    req = urllib.request.Request(url, headers={"User-Agent": "servers-info-dash/projects"})
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            code = resp.status
            resp.read(_MAX_BODY)
        error = None
    except urllib.error.HTTPError as exc:
        code, error = exc.code, None
    except Exception as exc:  # noqa: BLE001 — любой сбой сети = сайт недоступен
        code, error = None, f"{type(exc).__name__}: {exc}"[:200]
    return {"http": code, "ms": round((time.monotonic() - started) * 1000), "error": error}


def tls_expiry(host: str, port: int = 443) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=_HTTP_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        not_after = dt.datetime.fromtimestamp(
            ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc,
        )
        days = (not_after - _now()).total_seconds() / 86400
        return {"host": host, "expires": not_after.date().isoformat(), "days_left": int(days), "error": None}
    except Exception as exc:  # noqa: BLE001 — невалидный сертификат тоже показываем как ошибку
        return {"host": host, "expires": None, "days_left": None, "error": f"{type(exc).__name__}: {exc}"[:200]}


def fetch_summary(src: SummarySource) -> dict[str, Any]:
    if src.kind == "file":
        p = Path(src.path or "")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            age_min = (time.time() - p.stat().st_mtime) / 60
        except Exception as exc:  # noqa: BLE001
            return {"error": f"сводка не прочитана: {type(exc).__name__}"}
        data["stale"] = age_min > src.max_age_min
        data["age_min"] = round(age_min)
        return data
    req = urllib.request.Request(
        src.url or "",
        headers={"Authorization": f"Bearer {src.token or ''}", "User-Agent": "servers-info-dash/projects"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            return json.loads(resp.read(_MAX_BODY))
    except urllib.error.HTTPError as exc:
        return {"error": f"HTTP {exc.code}"}
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}"[:200]}


def _state_of(project: dict[str, Any]) -> tuple[str, list[str]]:
    """ok / warn / bad и причины — по тем же порогам, что видны в таблице."""
    bad: list[str] = []
    warn: list[str] = []
    chk = project.get("check")
    if chk:
        if chk["http"] is None or chk["http"] >= 500:
            bad.append("сайт не отвечает" if chk["http"] is None else f"сайт отвечает {chk['http']}")
        elif chk["http"] >= 400:
            warn.append(f"сайт отвечает {chk['http']}")
        elif chk["ms"] > _SLOW_MS:
            warn.append(f"медленный ответ {chk['ms']} мс")
    tls = project.get("tls")
    if tls:
        if tls["error"]:
            bad.append("сертификат не проверяется")
        elif tls["days_left"] < _TLS_BAD_DAYS:
            bad.append(f"сертификат истекает через {tls['days_left']} дн")
        elif tls["days_left"] < _TLS_WARN_DAYS:
            warn.append(f"сертификат истекает через {tls['days_left']} дн")
    s = project.get("summary") or {}
    if s.get("error"):
        warn.append(s["error"])
    if s.get("stale"):
        warn.append(f"сводка не обновлялась {s.get('age_min')} мин")
    for svc, st in (s.get("services") or {}).items():
        if st != "active":
            bad.append(f"{svc}: {st}")
    gen = s.get("generations_24h") or {}
    if gen.get("stuck"):
        warn.append(f"зависших генераций: {gen['stuck']}")
    if gen.get("failed_no_refund"):
        bad.append(f"ошибок без возврата: {gen['failed_no_refund']}")
    if gen.get("total") and gen.get("failed") is not None and gen["failed"] / gen["total"] > 0.2:
        warn.append(f"ошибок генерации {round(100 * gen['failed'] / gen['total'])} %")
    if s.get("ssh_alerts_open"):
        warn.append(f"открытых SSH-алертов: {s['ssh_alerts_open']}")
    for copy in s.get("rf") or []:
        if copy.get("error"):
            bad.append(f"{copy.get('label')}: нет данных о выходах")
        elif copy.get("exits_total") and copy.get("exits_alive", 0) < copy["exits_total"]:
            warn.append(f"{copy.get('label')}: живых выходов {copy.get('exits_alive')} из {copy['exits_total']}")
    offline = (s.get("servers") or {}).get("offline") or []
    if offline:
        warn.append("ноды offline: " + ", ".join(map(str, offline[:5])))
    backups = s.get("backups") or {}
    if backups.get("failed_24h"):
        warn.append(f"неудачных бэкапов за сутки: {backups['failed_24h']}")
    if bad:
        return "bad", bad + warn
    return ("warn" if warn else "ok"), warn


async def collect(cfg: ProjectsConfig) -> dict[str, Any]:
    async def one(p: ProjectConfig) -> dict[str, Any]:
        check, tls, summary = await asyncio.gather(
            asyncio.to_thread(probe_http, p.check_url) if p.check_url else _none(),
            asyncio.to_thread(tls_expiry, p.tls_host) if p.tls_host else _none(),
            asyncio.to_thread(fetch_summary, p.summary) if p.summary else _none(),
        )
        row = {"name": p.name, "stage": p.stage, "link": p.link, "note": p.note,
               "check": check, "tls": tls, "summary": summary}
        row["state"], row["reasons"] = _state_of(row)
        return row

    projects = await asyncio.gather(*(one(p) for p in cfg.projects))
    certs = await asyncio.gather(*(asyncio.to_thread(tls_expiry, h) for h in cfg.tls_hosts))
    return {
        "generated_at": _now().isoformat(timespec="seconds"),
        "refresh_sec": cfg.refresh_sec,
        "projects": list(projects),
        "tls": sorted(certs, key=lambda c: (c["days_left"] is not None, c["days_left"] or 0)),
    }


async def _none() -> None:
    return None


_cache: dict[str, Any] = {"generated_at": None, "projects": [], "tls": [], "ready": False}


def snapshot() -> dict[str, Any]:
    return _cache


async def run_forever() -> None:
    while True:
        try:
            cfg = load_projects_config()
            if cfg.projects or cfg.tls_hosts:
                result = await asyncio.wait_for(collect(cfg), timeout=120)
                result["ready"] = True
                _cache.clear()
                _cache.update(result)
            delay = cfg.refresh_sec
        except Exception:  # noqa: BLE001 — сборщик не должен умирать от одного сбоя
            logger.exception("projects collector cycle failed")
            delay = 300
        await asyncio.sleep(delay)
