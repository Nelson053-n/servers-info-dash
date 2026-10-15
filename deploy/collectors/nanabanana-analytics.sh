#!/bin/bash
# Аналитика прода nanabanana для вкладки «Проекты» (формат — docs/analytics-schema.md).
# Запускается root-кроном на хосте nanabanana: дашборд работает от infodash и к docker
# доступа не имеет, поэтому числа снимает root, а дашборд только читает готовый файл.
# Только чтение: SELECT, redis-cli llen/zcard, systemctl is-active, curl к localhost.
# Пороги alerts — из nanabanana/.claude/skills/prod-health/SKILL.md.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
mkdir -p "$OUT_DIR"
exec python3 - "$OUT_DIR" <<'PY'
import datetime as dt, json, os, re, subprocess, sys

OUT_DIR = sys.argv[1]
OUT = os.path.join(OUT_DIR, "nanabanana.json")
DAYS = 30
VLAT = dt.timezone(dt.timedelta(hours=10))
# createdAt — naive UTC; день по Владивостоку только двойной конвертацией (см. SKILL.md)
DAY = "date((\"createdAt\" AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Vladivostok')"


def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def q(sql):
    out = run(["docker", "exec", "nb-postgres", "psql", "-U", "nanabanana", "-d", "nanabanana",
               "-tA", "-F", "\t", "-c", sql])
    return [line.split("\t") for line in out.splitlines() if line]


def num(v):
    try:
        f = float(v)
        return int(f) if f == int(f) else round(f, 2)
    except (TypeError, ValueError):
        return None


def one(sql, n=1):
    rows = q(sql)
    vals = [num(x) for x in rows[0]] if rows else []
    vals += [None] * (n - len(vals))
    return vals if n > 1 else vals[0]


now = dt.datetime.now(dt.timezone.utc)
today = now.astimezone(VLAT).date()
days = [(today - dt.timedelta(days=i)).isoformat() for i in range(DAYS - 1, -1, -1)]
# Начало окна графиков: полночь VLAT первого дня, в naive UTC для сравнения с createdAt
start_utc = (dt.datetime.combine(today - dt.timedelta(days=DAYS - 1), dt.time(), VLAT)
             .astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
WIN = f"\"createdAt\" >= '{start_utc}'"


def daily(sql_rows, col=1):
    m = {r[0]: num(r[col]) or 0 for r in sql_rows}
    return [[d, m.get(d, 0)] for d in days]


# ── Сервисы ────────────────────────────────────────────────────────────────
s_bot = run(["systemctl", "is-active", "nb-bot"]) or "unknown"
s_web = run(["systemctl", "is-active", "nb-web"]) or "unknown"
health = num(run(["curl", "-s", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}",
                  "http://127.0.0.1:3000/api/health"]))

# ── Генерации ──────────────────────────────────────────────────────────────
g_total, g_done, g_failed = one(
    "SELECT count(*), count(*) FILTER (WHERE status='DONE'), count(*) FILTER (WHERE status='FAILED') "
    "FROM \"Generation\" WHERE \"createdAt\" > now() - interval '24 hours'", 3)
g_stuck = one("SELECT count(*) FROM \"Generation\" WHERE status::text IN ('PENDING','PROCESSING') "
              "AND \"createdAt\" < now() - interval '15 minutes'")
g_norefund = one("SELECT count(*) FROM \"Generation\" WHERE status='FAILED' AND \"isRefunded\"=false "
                 "AND \"createdAt\" > now() - interval '24 hours'")
err_pct = round(100 * g_failed / g_total, 1) if g_total else 0

# ── Деньги и пользователи (окна скользящие: последние 24 ч / 30 сут) ──────
PAID = "type='PURCHASE' AND status='COMPLETED' AND \"amountRub\" > 0"
rub_24h, rub_30d, rub_prev = one(
    f"SELECT COALESCE(sum(\"amountRub\") FILTER (WHERE \"createdAt\" > now()-interval '24 hours'),0), "
    f"COALESCE(sum(\"amountRub\") FILTER (WHERE \"createdAt\" > now()-interval '30 days'),0), "
    f"COALESCE(sum(\"amountRub\") FILTER (WHERE \"createdAt\" <= now()-interval '30 days'),0) "
    f"FROM \"Transaction\" WHERE {PAID} AND \"createdAt\" > now()-interval '60 days'", 3)
# ── Выручка календарными месяцами (по Владивостоку): с 1-го числа против тех же дней прошлого месяца ──
LOC = "((\"createdAt\" AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Vladivostok')"
NOWL = "(now() AT TIME ZONE 'Asia/Vladivostok')"
rub_mtd, rub_prev_same, rub_prev_month = one(
    f"SELECT COALESCE(sum(\"amountRub\") FILTER (WHERE {LOC} >= date_trunc('month', {NOWL})),0), "
    f"COALESCE(sum(\"amountRub\") FILTER (WHERE {LOC} >= date_trunc('month', {NOWL} - interval '1 month') "
    f"AND {LOC} < {NOWL} - interval '1 month'),0), "
    f"COALESCE(sum(\"amountRub\") FILTER (WHERE {LOC} >= date_trunc('month', {NOWL} - interval '1 month') "
    f"AND {LOC} < date_trunc('month', {NOWL})),0) "
    f"FROM \"Transaction\" WHERE {PAID} AND \"createdAt\" > now() - interval '70 days'", 3)
month_rows = q(f"SELECT to_char(date_trunc('month', {LOC}), 'YYYY-MM'), sum(\"amountRub\") FROM \"Transaction\" "
               f"WHERE {PAID} AND {LOC} >= date_trunc('month', {NOWL} - interval '11 months') GROUP BY 1")
_first = today.replace(day=1)
months = []
for i in range(11, -1, -1):
    y, m = divmod(_first.year * 12 + _first.month - 1 - i, 12)
    months.append(f"{y:04d}-{m + 1:02d}")
_mrev = {r[0]: num(r[1]) or 0 for r in month_rows}
MONTHS_GEN = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
MONTHS_ACC = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"]
_pm = (_first - dt.timedelta(days=1))
_same_day = min(today.day, _pm.day)
pend_old = one("SELECT count(*) FROM \"Transaction\" WHERE type='PURCHASE' AND status='PENDING' "
               "AND \"paymentMethod\"='YUKASSA' AND \"createdAt\" < now()-interval '24 hours' "
               "AND \"createdAt\" > now()-interval '7 days'")
u_24h, u_30d, u_prev = one(
    "SELECT count(*) FILTER (WHERE \"createdAt\" > now()-interval '24 hours'), "
    "count(*) FILTER (WHERE \"createdAt\" > now()-interval '30 days'), "
    "count(*) FILTER (WHERE \"createdAt\" <= now()-interval '30 days') "
    "FROM \"User\" WHERE \"createdAt\" > now()-interval '60 days'", 3)
a_24h, a_crit = one("SELECT count(*), count(*) FILTER (WHERE level='critical') FROM \"ApiAlert\" "
                    "WHERE \"createdAt\" > now() - interval '24 hours'", 2)


def delta(cur, prev):
    if cur is None or not prev:
        return None
    return round(100 * (cur - prev) / prev, 1)


# ── Графики ────────────────────────────────────────────────────────────────
gen_rows = q(f"SELECT {DAY}, count(*) FILTER (WHERE status='DONE'), count(*) FILTER (WHERE status='FAILED') "
             f"FROM \"Generation\" WHERE {WIN} GROUP BY 1")
prov_rows = q(f"SELECT {DAY}, \"apiProvider\"::text, count(*) FROM \"Generation\" WHERE {WIN} GROUP BY 1,2")
rev_rows = q(f"SELECT {DAY}, sum(\"amountRub\") FROM \"Transaction\" WHERE {PAID} AND {WIN} GROUP BY 1")
usr_rows = q(f"SELECT {DAY}, count(*) FROM \"User\" WHERE {WIN} GROUP BY 1")

prov_tot = {}
for d, p, c in prov_rows:
    prov_tot[p] = prov_tot.get(p, 0) + (num(c) or 0)
prov_series = []
for p in sorted(prov_tot, key=prov_tot.get, reverse=True)[:4]:
    prov_series.append({"name": p, "points": daily([(d, c) for d, pp, c in prov_rows if pp == p])})

# ── Таблицы ────────────────────────────────────────────────────────────────
def scrub(s):
    # failReason пишет код провайдера, но в него может попасть кусок промпта/URL:
    # вырезаем то, что похоже на идентификаторы и контакты.
    s = re.sub(r"https?://\S+", "<url>", s)
    s = re.sub(r"\S+@\S+", "<email>", s)
    s = re.sub(r"[0-9a-f]{8}-[0-9a-f-]{27,}", "<id>", s, flags=re.I)
    s = re.sub(r"\+?\d[\d\s()-]{8,}\d", "<num>", s)
    return s


reasons = {}
for c, r in q("SELECT count(*), left(coalesce(\"failReason\",'(нет причины)'),80) FROM \"Generation\" "
              "WHERE status='FAILED' AND \"createdAt\" > now() - interval '7 days' "
              "GROUP BY 2 ORDER BY 1 DESC LIMIT 60"):
    k = scrub(r)
    reasons[k] = reasons.get(k, 0) + (num(c) or 0)
reason_rows = [{"reason": k, "count": v} for k, v in sorted(reasons.items(), key=lambda x: -x[1])][:15]

prov24 = []
for p, d, f in q("SELECT \"apiProvider\"::text, count(*) FILTER (WHERE status='DONE'), "
                 "count(*) FILTER (WHERE status='FAILED') FROM \"Generation\" "
                 "WHERE \"createdAt\" > now() - interval '24 hours' GROUP BY 1 ORDER BY 2 DESC"):
    d, f = num(d) or 0, num(f) or 0
    pct = round(100 * f / (d + f), 1) if d + f else 0
    prov24.append({"provider": p, "done": d, "failed": f, "err_pct": pct,
                   "state": "bad" if pct >= 50 and f >= 3 else "warn" if pct >= 20 and f >= 3 else "ok"})


def redis(*args):
    return num(run(["docker", "exec", "nb-redis", "redis-cli", *args], timeout=8))


bull = {"wait": redis("llen", "bull:generation:wait"), "active": redis("llen", "bull:generation:active"),
        "delayed": redis("zcard", "bull:generation:delayed"), "failed": redis("zcard", "bull:generation:failed")}
bull_dead = (bull["wait"] or 0) > 2 and bull["active"] == 0
queue_rows = [
    {"name": "wait", "value": bull["wait"], "state": "bad" if bull_dead else "warn" if (bull["wait"] or 0) > 2 else "ok"},
    {"name": "active", "value": bull["active"], "state": "warn" if (bull["active"] or 0) > 2 else "ok"},
    {"name": "delayed", "value": bull["delayed"], "state": "ok"},
    {"name": "failed (посл. 50)", "value": bull["failed"], "state": "ok"},
]

# ── Диск хоста (порог из SKILL.md: > 85 %) ───────────────────────────────
disk = num((run(["df", "--output=pcent", "/"]).splitlines() or [""])[-1].strip().rstrip("%"))

# ── Документ ───────────────────────────────────────────────────────────────
svc_ok = s_bot == "active" and s_web == "active" and health == 200
kpis = [
    {"id": "services", "label": "nb-bot / nb-web", "value": "работают" if svc_ok else f"{s_bot} / {s_web}, health {health}",
     "state": "ok" if svc_ok else "bad"},
    {"id": "revenue_month", "label": f"Выручка с 1 {MONTHS_GEN[today.month - 1]}", "value": rub_mtd, "unit": "₽",
     "delta": delta(rub_mtd, rub_prev_same), "delta_label": f"к 1–{_same_day} {MONTHS_GEN[_pm.month - 1]}",
     "hint": "PURCHASE COMPLETED, amountRub; месяц по Владивостоку"},
    {"id": "generations_24h", "label": "Генераций за сутки", "value": g_total, "unit": "шт",
     "hint": f"DONE {g_done}, FAILED {g_failed}"},
    {"id": "error_rate_24h", "label": "Ошибок за сутки", "value": err_pct, "unit": "%",
     "state": "bad" if err_pct >= 40 and g_total >= 10 else "warn" if err_pct >= 20 and g_total >= 10 else "ok"},
    {"id": "revenue_30d", "label": "Выручка за 30 дней", "value": rub_30d, "unit": "₽",
     "delta": delta(rub_30d, rub_prev), "delta_label": "к прошлым 30 дням",
     "hint": "PURCHASE COMPLETED, amountRub (Stars — в рублёвом эквиваленте)"},
    {"id": "revenue_24h", "label": "Выручка за сутки", "value": rub_24h, "unit": "₽"},
    {"id": "revenue_prev_month", "label": f"Выручка за {MONTHS_ACC[_pm.month - 1]}", "value": rub_prev_month, "unit": "₽"},
    {"id": "users_24h", "label": "Новых пользователей за сутки", "value": u_24h, "unit": "шт"},
    {"id": "users_30d", "label": "Новых пользователей за 30 дней", "value": u_30d, "unit": "шт",
     "delta": delta(u_30d, u_prev), "delta_label": "к прошлым 30 дням"},
    {"id": "stuck", "label": "Зависших генераций", "value": g_stuck, "unit": "шт",
     "state": "bad" if (g_stuck or 0) > 0 else "ok", "hint": "PENDING/PROCESSING старше 15 мин, норма 0"},
    {"id": "failed_no_refund", "label": "FAILED без возврата (24 ч)", "value": g_norefund, "unit": "шт",
     "state": "bad" if (g_norefund or 0) > 0 else "ok", "hint": "норма 0"},
    {"id": "api_alerts_24h", "label": "Алерты API за сутки", "value": a_24h, "unit": "шт",
     "state": "warn" if (a_24h or 0) > 0 else "ok"},
]
charts = [
    {"id": "revenue_monthly", "title": "Выручка по месяцам", "kind": "bar", "unit": "₽",
     "note": "покупки COMPLETED; текущий месяц неполный",
     "series": [{"name": "₽", "points": [[m, _mrev.get(m, 0)] for m in months]}]},
    {"id": "generations_daily", "title": "Генерации по дням", "kind": "bar", "unit": "шт",
     "note": "по дате создания, сутки по Владивостоку",
     "series": [{"name": "DONE", "points": daily(gen_rows, 1)}, {"name": "FAILED", "points": daily(gen_rows, 2)}]},
    {"id": "providers_daily", "title": "Генерации по провайдерам", "kind": "bar", "unit": "шт",
     "note": "все статусы, топ-4 провайдера за 30 дней", "series": prov_series},
    {"id": "revenue_daily", "title": "Выручка по дням", "kind": "bar", "unit": "₽",
     "note": "покупки COMPLETED, по дате создания", "series": [{"name": "₽", "points": daily(rev_rows)}]},
    {"id": "users_daily", "title": "Новые пользователи", "kind": "bar", "unit": "шт",
     "series": [{"name": "новые", "points": daily(usr_rows)}]},
]
tables = [
    {"id": "fail_reasons_7d", "title": "Причины ошибок за 7 дней",
     "columns": [{"key": "reason", "label": "Причина (усечено)"}, {"key": "count", "label": "Кол-во", "num": True}],
     "rows": reason_rows},
    {"id": "providers_24h", "title": "Провайдеры за сутки",
     "columns": [{"key": "provider", "label": "Провайдер"}, {"key": "done", "label": "DONE", "num": True},
                 {"key": "failed", "label": "FAILED", "num": True}, {"key": "err_pct", "label": "% ошибок", "num": True},
                 {"key": "state", "label": "Статус", "state": True}],
     "rows": prov24},
    {"id": "bull_queue", "title": "Очередь Bull (generation)",
     "columns": [{"key": "name", "label": "Список"}, {"key": "value", "label": "Задач", "num": True},
                 {"key": "state", "label": "Статус", "state": True}],
     "rows": queue_rows},
]

alerts = []
if not svc_ok:
    alerts.append({"severity": "bad", "text": f"Сервисы: nb-bot {s_bot}, nb-web {s_web}, health {health} — не рестартовать без решения"})
if (g_stuck or 0) > 0:
    alerts.append({"severity": "bad", "text": f"{g_stuck} генераций висят в PENDING/PROCESSING > 15 мин — cleanup-джоб не работает?"})
if (g_norefund or 0) > 0:
    alerts.append({"severity": "bad", "text": f"{g_norefund} FAILED без возврата за сутки — разбор по diagnose-gen"})
if bull_dead:
    alerts.append({"severity": "bad", "text": f"Очередь Bull: wait {bull['wait']} при active 0 — worker мёртв?"})
if err_pct >= 20 and (g_total or 0) >= 10:
    alerts.append({"severity": "warn", "text": f"Ошибок генерации {err_pct}% за сутки ({g_failed} из {g_total})"})
if (a_crit or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{a_crit} critical-алертов провайдеров за сутки"})
if (pend_old or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{pend_old} платежей ЮKassa в PENDING дольше суток"})
if disk is not None and disk > 85:
    alerts.append({"severity": "bad", "text": f"Диск / заполнен на {disk}% (порог 85%) — docker-кэш"})

# Балансы API — отдельный часовой крон (nanabanana-balances.sh): там нужен код бота
try:
    with open(os.path.join(OUT_DIR, "nanabanana-balances.json")) as fh:
        bal = json.load(fh)
    bal_age_h = (now - dt.datetime.fromisoformat(bal["generated_at"])).total_seconds() / 3600
except Exception:
    bal, bal_age_h = {}, None
if bal_age_h is not None and bal_age_h > 3:
    alerts.append({"severity": "warn", "text": f"Балансы API не обновлялись {round(bal_age_h)} ч"})
for key, label, floor in (("kie_usd", "Баланс kie.ai", 10), ("openrouter_usd", "Баланс OpenRouter", 5),
                          ("google_usd", "Баланс Google AI", 20)):
    v = bal.get(key)
    if v is None:
        continue
    low = v < floor
    kpis.insert(4, {"id": key, "label": label, "value": v, "unit": "$", "state": "warn" if low else "ok",
                    "hint": f"порог ${floor}" + (" · расчётный: старт минус расход" if key == "google_usd" else "")})
    if low:
        alerts.append({"severity": "warn", "text": f"{label}: ${v} — меньше ${floor}, пополнить"})

doc = {"generated_at": now.isoformat(timespec="seconds"), "kpis": kpis, "charts": charts,
       "tables": tables, "alerts": alerts}
tmp = OUT + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, OUT)
PY
