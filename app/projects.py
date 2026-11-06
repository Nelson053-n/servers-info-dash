"""Вкладка «Проекты»: доступность сайтов, сроки TLS и сводки приложений.

Конфиг — config/projects.yaml (в .gitignore: в нём токены сводок). Сборщик ходит
наружу по HTTPS и читает локальные файлы, которые пишут root-кроны
(deploy/collectors/), сам ни к чему не подключается по SSH.
"""

import asyncio
import copy
import datetime as dt
import hashlib
import json
import logging
import os
import re
import shlex
import socket
import ssl
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Literal

import asyncssh
import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger("serverinfo.projects")

CONFIG_PATH = Path("config/projects.yaml")
SERVERS_PATH = Path("config/servers.yaml")
_HTTP_TIMEOUT = 15
_SLOW_MS = 3000
_TLS_WARN_DAYS = 21
_TLS_BAD_DAYS = 7
_MAX_BODY = 256 * 1024
_MAX_DOC = 4 * 1024 * 1024


class SummarySource(BaseModel):
    # http — GET с Bearer-токеном (amnpanel /api/analytics), file — JSON root-сборщика.
    # amnpanel оставлен для старых конфигов: то же, что http.
    kind: Literal["http", "amnpanel", "file", "kuma-json"]
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
    check_kind: Literal["http", "kuma-entry-page"] = "http"
    # Имя сервера из servers.yaml: проверка сайта выполняется curl'ом на нём, а не с хоста панели
    # (сайт, который пускает только отдельные страны/сети, иначе отвечает панели 403).
    check_via: str | None = None
    tls_host: str | None = None
    note: str = ""
    analytics: SummarySource | None = None
    # Алерты из документа аналитики, содержащие любую из подстрок (без учёта регистра), не показываются:
    # то, на что мы не влияем (например, блокировки провайдером у vpn).
    mute_alerts: list[str] = []


class ServerGroup(BaseModel):
    title: str
    # Имена серверов ровно как в servers.yaml; не попавшие ни в одну группу идут в «Прочие»
    servers: list[str] = []


class ProjectsConfig(BaseModel):
    refresh_sec: int = Field(default=300, ge=60, le=3600)
    projects: list[ProjectConfig] = []
    server_groups: list[ServerGroup] = []
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



def probe_kuma_entry_page(url: str) -> dict[str, Any]:
    """Check the public dynamic API; this does not check individual monitors."""
    started = time.monotonic()
    code = None
    error = None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "servers-info-dash/projects"})
        with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT) as resp:
            code = resp.status
            if code != 200 or resp.geturl() != url:
                raise ValueError("expected HTTP 200 without redirect")
            if resp.headers.get_content_type() != "application/json":
                raise ValueError("expected JSON content type")
            body = resp.read(_MAX_BODY + 1)
            if len(body) > _MAX_BODY:
                raise ValueError("response too large")
            doc = json.loads(body)
            if not isinstance(doc, dict):
                raise ValueError("expected object")
            key = {"entryPage": "entryPage", "statusPageMatchedDomain": "statusPageSlug"}.get(doc.get("type"))
            if not key or not isinstance(doc.get(key), str) or not doc[key].strip():
                raise ValueError("unexpected entry-page schema")
    except urllib.error.HTTPError as exc:
        code, error = exc.code, "Kuma API HTTP error"
    except Exception as exc:
        error = "Kuma API validation failed: " + type(exc).__name__
    return {"http": code, "ms": round((time.monotonic() - started) * 1000),
            "error": error, "valid": error is None, "scope": "kuma-entry-page"}


async def probe_via_server(url: str, server_name: str, servers_path: Path = SERVERS_PATH) -> dict[str, Any]:
    """Как probe_http, но curl запускается по ssh на сервере server_name из servers.yaml."""
    started = time.monotonic()
    try:
        servers = yaml.safe_load(servers_path.read_text(encoding="utf-8")) or {}
        srv = next(x for x in servers["servers"] if x["name"] == server_name)
        known_hosts = str(Path(servers["ssh"]["known_hosts"]).expanduser())
        cmd = "curl -sS -o /dev/null -m 15 -w '%{http_code} %{time_total}' " + shlex.quote(url)
        async with asyncssh.connect(
            srv["host"], port=srv.get("port", 22), username=srv["user"],
            client_keys=[srv["client_key"]], known_hosts=known_hosts, connect_timeout=10,
        ) as conn:
            res = await asyncio.wait_for(conn.run(cmd, check=False), timeout=30)
        result = _http_probe_result(res.stdout, time.monotonic() - started)
        code = result["http"]
        error = None if code else (str(res.stderr).strip() or "curl: нет ответа")[:200]
        return {**result, "error": error}
    except Exception as exc:  # noqa: BLE001 — любой сбой = проверка не удалась
        code, error = None, f"{type(exc).__name__}: {exc}"[:200]
    return {"http": code, "ms": round((time.monotonic() - started) * 1000), "error": error}


def _http_probe_result(stdout: str | bytes, elapsed: float) -> dict[str, Any]:
    status, duration = (stdout.decode() if isinstance(stdout, bytes) else stdout).strip().split()
    return {"http": int(status) or None, "ms": round(float(duration) * 1000),
            "probe_ms": round(elapsed * 1000)}


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
        ts = dt.datetime.fromisoformat(str(doc.get("last_success") or doc.get("generated_at")).replace("Z", "+00:00"))
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=dt.timezone.utc)
        return (_now() - ts).total_seconds() / 60
    except ValueError:
        return None if fallback_mtime is None else (time.time() - fallback_mtime) / 60


def fetch_analytics(src: SummarySource) -> dict[str, Any]:
    """Keep the last successful aggregate when a source is temporarily unavailable."""
    identity = f"{src.kind}:{src.url or src.path}"
    cache = Path("logs/project-analytics") / (hashlib.sha256(identity.encode()).hexdigest()[:20] + ".json")
    data = _read_analytics(src)
    if data.get("error") and not data.get("kpis"):
        try:
            previous = json.loads(cache.read_text())
        except (OSError, ValueError):
            previous = {}
        if previous:
            previous.update(error=data["error"], status="stale", stale=True)
            for metric in previous.get("kpis", []):
                metric.update(status="stale" if metric.get("value") is not None else "unknown", error=data["error"])
            age = _doc_age_min(previous)
            previous["age_min"] = None if age is None else round(age)
            return previous
        return {**data, "status": "unknown", "last_success": None, "kpis": [], "charts": [], "tables": []}
    data = copy.deepcopy(data)
    data.setdefault("last_success", data.get("generated_at"))
    data.setdefault("status", "stale" if data.get("stale") else "ok")
    for metric in data.get("kpis", []):
        metric.setdefault("metric", metric.get("id"))
        metric.setdefault("unit", "")
        metric.setdefault("period", data.get("period", "период не указан"))
        metric.setdefault("source", data.get("source", src.url or src.path))
        metric.setdefault("generated_at", data.get("generated_at"))
        metric.setdefault("last_success", data.get("last_success") if metric.get("value") is not None else None)
        metric.setdefault("error", None)
        metric.setdefault("status", "unknown" if metric.get("value") is None else data["status"])
        if metric["status"] == "unknown":
            metric["value"] = None
            metric["last_success"] = None
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        temporary = cache.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, ensure_ascii=False))
        temporary.chmod(0o600)
        os.replace(temporary, cache)
    except OSError:
        logger.warning("Could not persist last successful project aggregate")
    return data



def _read_kuma_analytics(src: SummarySource) -> dict[str, Any]:
    # No credentials, redirects or caller-selected destinations.
    endpoint = "https://kuma.bondai.ru/info-analytics.json"
    if src.url != endpoint or src.token:
        return {"error": "Kuma analytics configuration rejected"}
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    try:
        req = urllib.request.Request(endpoint, headers={"User-Agent": "Info-Kuma-analytics"})
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=10) as resp:
            if resp.status != 200 or resp.geturl() != endpoint or resp.headers.get_content_type() != "application/json":
                raise ValueError("response rejected")
            raw = resp.read(262145)
            if len(raw) > 262144:
                raise ValueError("response too large")
            data = json.loads(raw)
        if (not isinstance(data, dict) or data.get("source") != "Kuma · read-only SQLite"
                or not isinstance(data.get("kpis"), list) or not isinstance(data.get("tables"), list)
                or not isinstance(data.get("charts"), list) or not data.get("generated_at")):
            raise ValueError("schema rejected")
        age = _doc_age_min(data)
        if age is None or age < -5:
            raise ValueError("timestamp rejected")
        data["age_min"] = round(age)
        data["stale"] = bool(data.get("stale") or data.get("error") or age > src.max_age_min)
        data["stale_reason"] = ("age" if age > src.max_age_min else "source") if data["stale"] else None
        if data["stale"]:
            data["status"] = "stale"
            for metric in data["kpis"]:
                metric["status"] = "stale" if metric.get("value") is not None else "unknown"
        _kuma_alerts(data)
        return data
    except Exception:
        return {"error": "Kuma statistics unavailable or invalid"}


def _kuma_alerts(data: dict[str, Any]) -> None:
    """Экспорт Kuma кладёт в alerts пояснения к методике подсчёта — это не замечания.
    Пояснения уходят в limitations (раздел «Ограничения данных»), а замечанием становится
    то, что действительно требует внимания: мониторы в состоянии DOWN."""
    notes, real = [], []
    for a in data.get("alerts") or []:
        text = str(a.get("text", ""))
        if a.get("severity") != "bad" and re.match(r"(Экспорт обновляется отдельно|Доступность = up/)", text):
            notes.append(text)
        else:
            real.append(a)
    limits = [x for x in data.get("limitations") or [] if isinstance(x, dict)]
    titles = ["Как читать состояния и задержки", "Как считается доступность"]
    for i, text in enumerate(notes):
        limits.append({"id": f"kuma_method_{i}", "title": titles[i] if i < len(titles) else "Методика Kuma",
                       "impact": text, "action": "Ничего — это описание методики, а не ошибка.", "source_message": text})
    rows = next((t.get("rows") or [] for t in data.get("tables") or [] if t.get("id") == "kuma_monitors"), [])
    down = [str(r.get("monitor")) for r in rows
            if str(r.get("state") or "").upper() == "DOWN" and r.get("monitor")]
    if not down:
        n = next((k.get("value") for k in data.get("kpis") or [] if k.get("id") == "down"), 0)
        down = [f"{n} шт."] if isinstance(n, int) and n > 0 else []
    if down:
        real.append({"severity": "warn", "text": f"Kuma: мониторы DOWN — {', '.join(down[:6])}"
                     + (f" и ещё {len(down) - 6}" if len(down) > 6 else "")})
        for k in data.get("kpis") or []:
            if k.get("id") == "down":
                k["state"] = "warn"
    data["alerts"] = real
    data["limitations"] = limits


def _read_analytics(src: SummarySource) -> dict[str, Any]:
    """Документ аналитики (docs/analytics-schema.md) или {"error": ...}."""
    if src.kind == "kuma-json":
        return _read_kuma_analytics(src)
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
    # Устаревание — только про свежесть данных. Поле error у документа сборщика часто содержит
    # пояснение о неполноте («прибыль не reconciled»), его разбирает _separate_coverage_limits;
    # раньше оно делало свежий документ «устаревшим» и давало ложное «не обновлялась 4 мин».
    # Сборщик, у которого упал источник, сам ставит status=stale и сохраняет прошлые значения.
    if src.kind == "file":
        if data.get("stale") is True or data.get("status") == "stale":
            reason = "source"   # сборщик не достучался до источника и отдал прошлые значения
        elif age is None:
            reason = "no_timestamp"
        elif age > src.max_age_min:
            reason = "age"
        else:
            reason = None
    else:
        reason = "age" if age is not None and age > src.max_age_min else None
    data["stale"] = reason is not None
    data["stale_reason"] = reason
    return data


def _last_success_age_min(doc: dict[str, Any]) -> float | None:
    raw = doc.get("last_success")
    if not raw:
        return None
    try:
        t = dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return (_now() - t).total_seconds() / 60


def _fmt_age(minutes: int) -> str:
    """Минуты → «45 мин» / «5 ч 10 мин» / «2 дн 20 ч»."""
    d, rem = divmod(int(minutes), 1440)
    h, m = divmod(rem, 60)
    if d:
        return f"{d} дн {h} ч" if h else f"{d} дн"
    if h:
        return f"{h} ч {m} мин" if m else f"{h} ч"
    return f"{m} мин"


def _drop_muted(doc: dict[str, Any] | None, patterns: list[str]) -> None:
    if not isinstance(doc, dict) or not patterns or not doc.get("alerts"):
        return
    low = [x.lower() for x in patterns]
    doc["alerts"] = [a for a in doc["alerts"] if not any(x in str(a.get("text", "")).lower() for x in low)]


def _separate_coverage_limits(doc: dict[str, Any] | None) -> None:
    if not isinstance(doc, dict):
        return
    descriptions = {
        "Monthly native ledger/cost coverage unavailable; not zero": (
            "monthly_finances", "Неполная история выплат и расходов",
            "Месячные поступления в FLUX и прибыль не подтверждены. Это не ошибка работы нод.",
            "Подключить полный журнал выплат и учёт расходов за месяц."),
        "Расходы/комиссии/возвраты не reconciled; прибыль неизвестна, не0": (
            "monthly_finances", "Прибыль пока не подтверждена",
            "Для расчёта прибыли не хватает сверенных расходов, комиссий и возвратов.",
            "Сверить поступления и расходы за один период."),
        "Некоммерческий HR сервис; денежный KPI неприменим, не0; Нет BobSSH/SQL/OPS capability; не проверено, не0/неbad": (
            "server_checks", "Часть серверных проверок недоступна",
            "Info не проверяет бэкапы, диск, контейнеры и CI. Данные отпусков доступны через HTTP API.",
            "Восстановить доступ мониторинга к серверным проверкам."),
        "Не проверены: серверные бэкапы, CI runner, диск и контейнеры (прежний SSH-маршрут недоступен). OPS-метрики требуют отдельного доступа.": (
            "server_checks", "Часть серверных проверок недоступна",
            "Info не проверяет бэкапы, диск, контейнеры и CI. Данные отпусков доступны через HTTP API.",
            "Восстановить доступ мониторинга к серверным проверкам."),
        "Агрегатный SQL-источник Bob недоступен.; Нужен SSH-доступ к Bob для серверных проверок.": (
            "hr_sql", "SQL-сводка и серверные проверки недоступны",
            "Info получает данные через HTTP-туннель, но полная SQL-сводка недоступна.",
            "Восстановить доступ к агрегатному SQL-источнику Bob и серверным проверкам."),
        "Для проверки бэкапов, CI runner, диска и контейнеров нужен SSH-доступ к Bob. Текущий сборщик использует HTTP-туннель приложения через RU3.": (
            "server_checks", "Часть серверных проверок недоступна",
            "Info не проверяет бэкапы, диск, контейнеры и CI. Данные отпусков доступны через HTTP API.",
            "Восстановить доступ мониторинга к серверным проверкам."),
        "Служебные показатели приложения недоступны: у учётной записи сборщика нет права ops.view (HTTP 403). Нужен доступ сборщика к OPS.": (
            "ops_access", "Нет доступа к служебным показателям OPS",
            "Учётной записи Info недоступна служебная статистика приложения.",
            "Согласовать предоставление учётной записи сборщика права ops.view."),
    }
    limits = list(doc.get("limitations") or [])

    def separate(text: Any) -> bool:
        if not isinstance(text, str) or text not in descriptions:
            return False
        key, title, impact, action = descriptions[text]
        if not any(x.get("id") == key for x in limits):
            limits.append({"id": key, "title": title, "impact": impact, "action": action, "source_message": text})
        return True

    if separate(doc.get("error")):
        doc["error"] = None
    doc["alerts"] = [a for a in doc.get("alerts") or []
                     if a.get("severity") == "bad" or not separate(a.get("text"))]
    doc["limitations"] = limits


def _state_of(project: dict[str, Any]) -> tuple[str, list[dict[str, str]]]:
    """ok / warn / bad и замечания [{severity, text}]: сайт, сертификат и alerts самого проекта."""
    bad: list[str] = []
    warn: list[str] = []
    chk = project.get("check")
    if chk:
        if chk.get("valid") is False:
            bad.append("Kuma API: HTTP/JSON check failed")
        elif chk["http"] is None or chk["http"] >= 500:
            bad.append("сайт не отвечает" if chk["http"] is None else f"сайт отвечает {chk['http']}")
        elif chk["http"] >= 400:
            warn.append(f"сайт отвечает {chk['http']}")
        elif chk["ms"] > _SLOW_MS and chk.get("slow_streak", _SLOW_STREAK) >= _SLOW_STREAK:
            # один медленный замер — шум сети/нагрузки; замечание — только если медленно N циклов подряд
            warn.append(f"медленный ответ {chk['ms']} мс ({chk.get('slow_streak', _SLOW_STREAK)} проверки подряд)")
    tls = project.get("tls")
    if tls:
        if tls["error"]:
            # один неудачный TLS-handshake — обычно сетевой сбой; «срочно» — только если повторился
            if tls.get("fail_streak", 2) >= 2:
                bad.append("сертификат не проверяется")
            else:
                warn.append("сертификат не проверился (разовый сбой — повтор в следующем цикле)")
        elif tls["days_left"] < _TLS_BAD_DAYS:
            bad.append(f"сертификат истекает через {tls['days_left']} дн")
        elif tls["days_left"] < _TLS_WARN_DAYS:
            warn.append(f"сертификат истекает через {tls['days_left']} дн")
    doc = project.get("analytics") or {}
    if doc.get("error"):
        warn.append(doc["error"])
    if doc.get("stale"):
        reason = doc.get("stale_reason")
        if reason == "source":
            ok_age = _last_success_age_min(doc)
            warn.append("источник данных недоступен — показаны прошлые значения"
                        + (f" (последний успех {_fmt_age(max(0, ok_age))} назад)" if ok_age is not None else ""))
        elif reason == "no_timestamp":
            warn.append("у сводки нет времени формирования — свежесть не проверить")
        else:
            warn.append(f"сводка не обновлялась {_fmt_age(doc.get('age_min') or 0)}")
    for a in doc.get("alerts") or []:
        text = str(a.get("text", ""))[:200]
        (bad if a.get("severity") == "bad" else warn).append(text)
    issues = [{"severity": "bad", "text": t} for t in bad] + [{"severity": "warn", "text": t} for t in warn]
    return ("bad" if bad else "warn" if warn else "ok"), issues


_tls_fail_streak: dict[str, int] = {}
_slow_streak: dict[str, int] = {}
_SLOW_STREAK = 3


async def collect(cfg: ProjectsConfig) -> dict[str, Any]:
    async def one(p: ProjectConfig) -> dict[str, Any]:
        check, tls, doc = await asyncio.gather(
            (asyncio.to_thread(probe_kuma_entry_page, p.check_url) if p.check_kind == "kuma-entry-page" else
             probe_via_server(p.check_url, p.check_via) if p.check_via else asyncio.to_thread(probe_http, p.check_url))
            if p.check_url else _none(),
            asyncio.to_thread(tls_expiry, p.tls_host) if p.tls_host else _none(),
            asyncio.to_thread(fetch_analytics, p.analytics) if p.analytics else _none(),
        )
        if tls:
            streak = _tls_fail_streak.get(p.tls_host, 0) + 1 if tls.get("error") else 0
            _tls_fail_streak[p.tls_host] = streak
            tls = {**tls, "fail_streak": streak}
        if check and check.get("ms") is not None and check.get("http") is not None:
            slow = _slow_streak.get(p.id, 0) + 1 if check["ms"] > _SLOW_MS else 0
            _slow_streak[p.id] = slow
            check = {**check, "slow_streak": slow}
        _drop_muted(doc, p.mute_alerts)
        _separate_coverage_limits(doc)
        row = {"id": p.id, "name": p.name, "stage": p.stage, "link": p.link, "note": p.note,
               "check": check, "tls": tls, "analytics": doc}
        row["state"], row["issues"] = _state_of(row)
        return row

    projects = await asyncio.gather(*(one(p) for p in cfg.projects))
    certs = await asyncio.gather(*(asyncio.to_thread(tls_expiry, h) for h in cfg.tls_hosts))
    return {
        "generated_at": _now().isoformat(timespec="seconds"),
        "refresh_sec": cfg.refresh_sec,
        "server_groups": [g.model_dump() for g in cfg.server_groups],
        "projects": list(projects),
        "tls": sorted(certs, key=lambda c: (c["days_left"] is not None, c["days_left"] or 0)),
    }


async def _none() -> None:
    return None


_cache: dict[str, Any] = {"generated_at": None, "projects": [], "tls": [], "ready": False}


def _card(doc: dict[str, Any] | None) -> dict[str, Any] | None:
    """Для обзора — первые 4 плитки и первый график; полный документ — в detail().
    Флаг has_revenue_month — по нему обзор решает, грузить ли полный документ для карточки «доход»:
    сама плитка может стоять дальше четвёртой и в сводку не попасть."""
    if not doc:
        return None
    charts = doc.get("charts") or []
    kpis = [k for k in doc.get("kpis") or [] if k.get("status") != "not_applicable"]
    known = [k for k in kpis if k.get("value") is not None]
    return {
        "error": doc.get("error"),
        "stale": doc.get("stale"),
        "stale_reason": doc.get("stale_reason"),
        "age_min": doc.get("age_min"),
        "generated_at": doc.get("generated_at"),
        "last_success": doc.get("last_success"),
        "status": doc.get("status"),
        "has_details": bool(doc.get("kpis") or doc.get("tables") or doc.get("charts")),
        # в карточку — только показатели со значением; пустые считаются отдельно,
        # иначе сетка карточки заполняется плитками «нет данных»
        "kpis": known[:4],
        "kpi_total": len(kpis),
        "kpi_missing": len(kpis) - len(known),
        "has_revenue_month": any(k.get("id") == "revenue_month" for k in doc.get("kpis") or []),
        "spark": charts[0] if charts else None,
        # для сводки «выручка всех проектов» на обзоре — по договорённому id
        "revenue_30d": next((k.get("value") for k in doc.get("kpis") or []
                             if k.get("id") == "revenue_30d" and isinstance(k.get("value"), (int, float))), None),
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
                for row in result["projects"]:
                    if (row.get("check") or {}).get("scope") == "kuma-entry-page":
                        logging.getLogger("uvicorn.error").info("Kuma availability refreshed: id=%s state=%s http=%s valid=%s generated_at=%s",
                                    row["id"], row["state"], row["check"]["http"], row["check"]["valid"], result["generated_at"])
            delay = cfg.refresh_sec
        except Exception:  # noqa: BLE001 — сборщик не должен умирать от одного сбоя
            logger.exception("projects collector cycle failed")
            delay = 300
        await asyncio.sleep(delay)
