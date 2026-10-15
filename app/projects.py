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
_MAX_DOC = 4 * 1024 * 1024


class SummarySource(BaseModel):
    # http — GET с Bearer-токеном (amnpanel /api/analytics), file — JSON root-сборщика.
    # amnpanel оставлен для старых конфигов: то же, что http.
    kind: Literal["http", "amnpanel", "file"]
    url: str | None = None
    token: str | None = None
    path: str | None = None
    # Файл сводки старше этого считается протухшим: крон пишет его раз в 10 мин.
    max_age_min: int = 30


class ProjectConfig(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9_-]{1,40}$")
    name: str
    stage: str = ""
    link: str | None = None
    check_url: str | None = None
    tls_host: str | None = None
    note: str = ""
    analytics: SummarySource | None = None


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


def _doc_age_min(doc: dict[str, Any], fallback_mtime: float | None = None) -> float | None:
    try:
        ts = dt.datetime.fromisoformat(str(doc.get("generated_at")).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        return (_now() - ts).total_seconds() / 60
    except ValueError:
        return None if fallback_mtime is None else (time.time() - fallback_mtime) / 60


def fetch_analytics(src: SummarySource) -> dict[str, Any]:
    """Документ аналитики (docs/analytics-schema.md) или {"error": ...}."""
    mtime = None
    if src.kind == "file":
        p = Path(src.path or "")
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            mtime = p.stat().st_mtime
        except Exception as exc:  # noqa: BLE001
            return {"error": f"данные не прочитаны: {type(exc).__name__}"}
    else:
        req = urllib.request.Request(
            src.url or "",
            headers={"Authorization": f"Bearer {src.token or ''}", "User-Agent": "servers-info-dash/projects"},
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = json.loads(resp.read(_MAX_DOC))
        except urllib.error.HTTPError as exc:
            return {"error": f"источник ответил HTTP {exc.code}"}
        except Exception as exc:  # noqa: BLE001
            return {"error": f"источник недоступен: {type(exc).__name__}"[:200]}
    if not isinstance(data, dict):
        return {"error": "источник вернул не документ"}
    age = _doc_age_min(data, mtime)
    data["age_min"] = None if age is None else round(age)
    data["stale"] = age is not None and age > src.max_age_min
    return data


def _state_of(project: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """ok / warn / bad и замечания [{severity, text}]: сайт, сертификат и alerts самого проекта."""
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
    doc = project.get("analytics") or {}
    if doc.get("error"):
        warn.append(doc["error"])
    if doc.get("stale"):
        warn.append(f"аналитика не обновлялась {doc.get('age_min')} мин")
    for a in doc.get("alerts") or []:
        text = str(a.get("text", ""))[:200]
        (bad if a.get("severity") == "bad" else warn).append(text)
    issues = [{"severity": "bad", "text": t} for t in bad] + [{"severity": "warn", "text": t} for t in warn]
    return ("bad" if bad else "warn" if warn else "ok"), issues


async def collect(cfg: ProjectsConfig) -> dict[str, Any]:
    async def one(p: ProjectConfig) -> dict[str, Any]:
        check, tls, doc = await asyncio.gather(
            asyncio.to_thread(probe_http, p.check_url) if p.check_url else _none(),
            asyncio.to_thread(tls_expiry, p.tls_host) if p.tls_host else _none(),
            asyncio.to_thread(fetch_analytics, p.analytics) if p.analytics else _none(),
        )
        row = {"id": p.id, "name": p.name, "stage": p.stage, "link": p.link, "note": p.note,
               "check": check, "tls": tls, "analytics": doc}
        row["state"], row["issues"] = _state_of(row)
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


def _card(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """Для обзора — первые 4 плитки и первый график; полный документ — в detail()."""
    if not doc:
        return None
    charts = doc.get("charts") or []
    return {
        "error": doc.get("error"),
        "stale": doc.get("stale"),
        "age_min": doc.get("age_min"),
        "kpis": (doc.get("kpis") or [])[:4],
        "spark": charts[0] if charts else None,
    }


def snapshot() -> dict[str, Any]:
    out = dict(_cache)
    out["projects"] = [{**p, "analytics": _card(p.get("analytics"))} for p in _cache.get("projects", [])]
    return out


def detail(project_id: str) -> dict[str, Any] | None:
    for p in _cache.get("projects", []):
        if p["id"] == project_id:
            return p
    return None


async def run_forever() -> None:
    while True:
        try:
            cfg = load_projects_config()
            if cfg.projects or cfg.tls_hosts:
                result = await asyncio.wait_for(collect(cfg), timeout=180)
                result["ready"] = True
                _cache.clear()
                _cache.update(result)
            delay = cfg.refresh_sec
        except Exception:  # noqa: BLE001 — сборщик не должен умирать от одного сбоя
            logger.exception("projects collector cycle failed")
            delay = 300
        await asyncio.sleep(delay)
