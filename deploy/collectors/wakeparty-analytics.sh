#!/bin/bash
# Аналитика прода wakeparty.ru для вкладки «Проекты» (формат — docs/analytics-schema.md).
# Запускается root-кроном на хосте wakeparty (контейнеры wakeparty-app :3200 и wakeparty-db):
# дашборд работает от infodash и к docker доступа не имеет, поэтому числа снимает root.
# Только чтение: SELECT, docker inspect/logs, curl к localhost, df.
# Логика «ждут решения», выручки и катеров повторяет src/app/api/admin/dashboard/route.ts
# и src/lib/constants.ts проекта wakeparty-booknow.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
mkdir -p "$OUT_DIR"
exec python3 - "$OUT_DIR" <<'PY'
import datetime as dt, json, os, re, subprocess, sys

OUT = os.path.join(sys.argv[1], "wakeparty.json")
DAYS = 30
VLAT = dt.timezone(dt.timedelta(hours=10))
DAY = "date((\"{c}\" AT TIME ZONE 'UTC') AT TIME ZONE 'Asia/Vladivostok')"  # колонки — naive UTC
BOATS = {"e4ebb948-a012-11ee-a5a5-723e79e9b5cb": "Красный", "e4edfbaa-a012-11ee-a5a5-723e79e9b5cb": "Серый"}
# slotId — текст (ISO со смещением); приводим к времени только то, что похоже на дату
SLOT_OK = "\"slotId\" ~ '^\\d{4}-\\d{2}-\\d{2}T'"


def run(cmd, timeout=15):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except Exception:
        return ""


def q(sql):
    out = run(["docker", "exec", "wakeparty-db", "psql", "-U", "wake", "-d", "wakeparty",
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


def delta(cur, prev):
    if cur is None or not prev:
        return None
    return round(100 * (cur - prev) / prev, 1)


now = dt.datetime.now(dt.timezone.utc)
today = now.astimezone(VLAT).date()
days = [(today - dt.timedelta(days=i)).isoformat() for i in range(DAYS - 1, -1, -1)]
start_utc = (dt.datetime.combine(today - dt.timedelta(days=DAYS - 1), dt.time(), VLAT)
             .astimezone(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))


def daily(rows, col=1):
    m = {r[0]: num(r[col]) or 0 for r in rows}
    return [[d, m.get(d, 0)] for d in days]


# Предоплата фиксированная: в БД сумм нет, берём PREPAY_AMOUNT контейнера (дефолт кода 2000)
prepay = num(run(["docker", "exec", "wakeparty-app", "printenv", "PREPAY_AMOUNT"])) or 2000
# Проданный сертификат = оплаченный и не возвращённый
GIFT_SOLD = "status::text IN ('ACTIVE','USED','EXPIRED')"
PREPAID = "status='PAID' AND method='PREPAY'"

# ── Инфраструктура ─────────────────────────────────────────────────────────
health = num(run(["curl", "-s", "-o", "/dev/null", "-m", "8", "-w", "%{http_code}", "http://127.0.0.1:3200/api/health"]))
containers = []
for name in ("wakeparty-app", "wakeparty-db"):
    st = run(["docker", "inspect", "-f", "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", name])
    status, _, hl = st.partition(" ")
    ok = status == "running" and hl in ("", "healthy")
    containers.append({"name": name, "status": status or "нет", "health": hl or "—", "state": "ok" if ok else "bad"})
disk = num((run(["df", "--output=pcent", "/"]).splitlines() or [""])[-1].strip().rstrip("%"))
# Ошибки оплат пишутся только в stdout контейнера (console.error), отдельной таблицы нет.
# docker logs видит вывод с последнего пересоздания контейнера.
try:  # console.error идёт в stderr контейнера — склеиваем оба потока
    logs = subprocess.run(["docker", "logs", "--since", "24h", "wakeparty-app"], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True, timeout=20).stdout
except Exception:
    logs = ""
webhook_err = len(re.findall(r"^\[webhook\]", logs, re.M))
create_err = len(re.findall(r"^\[payments/create\]", logs, re.M))
sync_err = len(re.findall(r"^\[bookings-sync\] BookNow недоступен", logs, re.M))

# ── Брони и деньги ─────────────────────────────────────────────────────────
b24, b30, b_prev = one(
    f"SELECT count(*) FILTER (WHERE \"createdAt\" > now()-interval '24 hours'), "
    f"count(*) FILTER (WHERE \"createdAt\" > now()-interval '30 days'), "
    f"count(*) FILTER (WHERE \"createdAt\" <= now()-interval '30 days') "
    f"FROM \"PendingBooking\" WHERE status='PAID' AND \"createdAt\" > now()-interval '60 days'", 3)
pp30, pp_prev = one(
    f"SELECT count(*) FILTER (WHERE \"createdAt\" > now()-interval '30 days'), "
    f"count(*) FILTER (WHERE \"createdAt\" <= now()-interval '30 days') "
    f"FROM \"PendingBooking\" WHERE {PREPAID} AND \"createdAt\" > now()-interval '60 days'", 2)
gs30, gs30_rub, gs_prev_rub = one(
    f"SELECT count(*) FILTER (WHERE \"createdAt\" > now()-interval '30 days'), "
    f"COALESCE(sum(\"faceValue\") FILTER (WHERE \"createdAt\" > now()-interval '30 days'),0), "
    f"COALESCE(sum(\"faceValue\") FILTER (WHERE \"createdAt\" <= now()-interval '30 days'),0) "
    f"FROM \"GiftCard\" WHERE {GIFT_SOLD} AND \"createdAt\" > now()-interval '60 days'", 3)
rev30 = (pp30 or 0) * prepay + (gs30_rub or 0)
rev_prev = (pp_prev or 0) * prepay + (gs_prev_rub or 0)
g_used30 = one("SELECT count(*) FROM \"GiftCard\" WHERE status='USED' AND \"usedAt\" > now()-interval '30 days'")
g_active = one("SELECT count(*) FROM \"GiftCard\" WHERE status='ACTIVE' AND \"expiresAt\" > now()")

# «Ждут решения» — как бейдж админки: PAID без completedAt, отменена в BookNow / возврат
# сорвался / отметка booking.stale от крона сверки
attention = one(
    "SELECT count(*) FROM \"PendingBooking\" b WHERE b.status='PAID' AND b.\"completedAt\" IS NULL AND "
    "(b.\"bnCanceledNotified\" OR b.\"refundFailed\" OR EXISTS (SELECT 1 FROM \"AuditLog\" a "
    "WHERE a.action='booking.stale' AND a.\"entityId\"=b.id))")
refund_failed = one("SELECT count(*) FROM \"PendingBooking\" WHERE \"refundFailed\" AND status='PAID'")
needs_attn = one("SELECT count(*) FROM \"PendingBooking\" WHERE \"needsAttention\" AND status::text NOT IN ('CANCELLED','FAILED')")
pending_review = one("SELECT count(*) FROM \"PendingBooking\" WHERE status='PENDING_REVIEW'")
# AWAITING_PAYMENT старше 1 ч крон сверки закрывает сам; старше 2 ч — крон не работает
stuck_pay = one("SELECT count(*) FROM \"PendingBooking\" WHERE status='AWAITING_PAYMENT' "
                "AND \"createdAt\" < now()-interval '2 hours'")
refunds30, cancels30 = one(
    "SELECT count(*) FILTER (WHERE refunded), count(*) FROM \"PendingBooking\" "
    "WHERE status='CANCELLED' AND \"canceledAt\" > now()-interval '30 days'", 2)
gift_refunds30 = one("SELECT count(*) FROM \"GiftCard\" WHERE status='REFUNDED' AND \"refundedAt\" > now()-interval '30 days'")
no_funds7 = one("SELECT count(*) FROM \"AuditLog\" WHERE action='refund.no_funds' AND \"createdAt\" > now()-interval '7 days'")
sync_broken = one("SELECT count(*) FROM \"Settings\" WHERE \"syncFailAlertAt\" IS NOT NULL")

# ── Графики ────────────────────────────────────────────────────────────────
WIN = f"\"createdAt\" >= '{start_utc}'"
bk_rows = q(f"SELECT {DAY.format(c='createdAt')}, count(*) FILTER (WHERE status::text NOT IN ('FAILED')), "
            f"count(*) FILTER (WHERE status='PAID'), count(*) FILTER (WHERE status='CANCELLED') "
            f"FROM \"PendingBooking\" WHERE {WIN} GROUP BY 1")
pp_rows = q(f"SELECT {DAY.format(c='createdAt')}, count(*) FROM \"PendingBooking\" WHERE {PREPAID} AND {WIN} GROUP BY 1")
gs_rows = q(f"SELECT {DAY.format(c='createdAt')}, sum(\"faceValue\") FROM \"GiftCard\" WHERE {GIFT_SOLD} AND {WIN} GROUP BY 1")
rev_prepay = [[d, v * prepay] for d, v in daily(pp_rows)]
rev_gift = daily(gs_rows)

# ── Ближайшие брони на 7 дней (без клиентских данных) ─────────────────────
upcoming = []
for slot, boat, status, method, attn in q(
        f"SELECT to_char(\"slotId\"::timestamptz AT TIME ZONE 'Asia/Vladivostok','YYYY-MM-DD HH24:MI'), "
        f"coalesce(\"stafferUuid\",''), status::text, method::text, "
        f"(\"bnCanceledNotified\" OR \"refundFailed\" OR \"needsAttention\")::text "
        f"FROM \"PendingBooking\" WHERE status::text IN ('PAID','PENDING_REVIEW') AND \"completedAt\" IS NULL "
        f"AND {SLOT_OK} AND \"slotId\"::timestamptz BETWEEN now() AND now()+interval '7 days' "
        f"ORDER BY \"slotId\"::timestamptz LIMIT 50"):
    day, _, tm = slot.partition(" ")
    upcoming.append({"date": day, "time": tm, "boat": BOATS.get(boat, "Любой/не указан"),
                     "pay": "предоплата" if method == "PREPAY" else "сертификат",
                     "status": "ждёт одобрения" if status == "PENDING_REVIEW" else "оплачена",
                     "state": "warn" if status == "PENDING_REVIEW" or attn == "true" else "ok"})

# ── Документ ───────────────────────────────────────────────────────────────
site_ok = health == 200 and all(c["state"] == "ok" for c in containers)
kpis = [
    {"id": "site", "label": "Сайт", "value": "работает" if site_ok else f"health {health}",
     "state": "ok" if site_ok else "bad", "hint": "curl :3200/api/health + статус контейнеров"},
    {"id": "revenue_30d", "label": "Выручка за 30 дней", "value": rev30, "unit": "₽",
     "delta": delta(rev30, rev_prev), "delta_label": "к прошлым 30 дням",
     "hint": f"предоплаты {pp30 or 0}×{prepay} ₽ (статус PAID) + сертификаты {gs30_rub or 0} ₽"},
    {"id": "bookings_30d", "label": "Оплаченных броней за 30 дней", "value": b30, "unit": "шт",
     "delta": delta(b30, b_prev), "delta_label": "к прошлым 30 дням", "hint": "предоплата и сертификаты"},
    {"id": "attention", "label": "Ждут решения", "value": attention, "unit": "шт",
     "state": "warn" if (attention or 0) > 0 else "ok", "hint": "как бейдж в админке"},
    {"id": "bookings_24h", "label": "Оплаченных броней за сутки", "value": b24, "unit": "шт"},
    {"id": "pending_review", "label": "Брони по сертификату на проверке", "value": pending_review, "unit": "шт",
     "state": "warn" if (pending_review or 0) > 0 else "ok"},
    {"id": "refunds_30d", "label": "Возвратов за 30 дней", "value": (refunds30 or 0) + (gift_refunds30 or 0), "unit": "шт",
     "hint": f"брони {refunds30 or 0} из {cancels30 or 0} отмен, сертификаты {gift_refunds30 or 0}"},
    {"id": "gifts_sold_30d", "label": "Сертификатов продано за 30 дней", "value": gs30, "unit": "шт"},
    {"id": "gifts_used_30d", "label": "Сертификатов погашено за 30 дней", "value": g_used30, "unit": "шт",
     "hint": f"активных сейчас {g_active}"},
    {"id": "disk", "label": "Диск /", "value": disk, "unit": "%",
     "state": "bad" if (disk or 0) > 85 else "warn" if (disk or 0) > 75 else "ok"},
]
charts = [
    {"id": "bookings_daily", "title": "Брони по дням", "kind": "bar", "unit": "шт",
     "note": "по дате создания; заявки — все, кроме брошенных неоплаченных (FAILED); статус текущий",
     "series": [{"name": "заявки", "points": daily(bk_rows, 1)}, {"name": "оплачены", "points": daily(bk_rows, 2)},
                {"name": "отменены", "points": daily(bk_rows, 3)}]},
    {"id": "revenue_daily", "title": "Выручка по дням", "kind": "bar", "unit": "₽",
     "note": f"предоплата {prepay} ₽ × оплаченные брони + номинал проданных сертификатов, по дате создания",
     "series": [{"name": "предоплаты", "points": rev_prepay}, {"name": "сертификаты", "points": rev_gift}]},
]
tables = [
    {"id": "upcoming_7d", "title": "Ближайшие брони на 7 дней",
     "columns": [{"key": "date", "label": "Дата"}, {"key": "time", "label": "Время"}, {"key": "boat", "label": "Катер"},
                 {"key": "pay", "label": "Оплата"}, {"key": "status", "label": "Статус"},
                 {"key": "state", "label": "", "state": True}],
     "rows": upcoming},
    {"id": "infra", "title": "Контейнеры",
     "columns": [{"key": "name", "label": "Контейнер"}, {"key": "status", "label": "Состояние"},
                 {"key": "health", "label": "Healthcheck"}, {"key": "state", "label": "", "state": True}],
     "rows": containers},
    {"id": "payment_errors_24h", "title": "Ошибки оплат и сверки за сутки (лог контейнера)",
     "columns": [{"key": "name", "label": "Источник"}, {"key": "count", "label": "Строк", "num": True},
                 {"key": "state", "label": "", "state": True}],
     "rows": [{"name": "вебхук ЮKassa [webhook]", "count": webhook_err, "state": "warn" if webhook_err else "ok"},
              {"name": "создание платежа [payments/create]", "count": create_err, "state": "warn" if create_err else "ok"},
              {"name": "сверка BookNow недоступна", "count": sync_err, "state": "warn" if sync_err else "ok"}]},
]
alerts = []
if not site_ok:
    alerts.append({"severity": "bad", "text": f"Сайт: health {health}, контейнеры: " +
                   ", ".join(f"{c['name']} {c['status']}/{c['health']}" for c in containers)})
if (disk or 0) > 85:
    alerts.append({"severity": "bad", "text": f"Диск / заполнен на {disk}% (порог 85%)"})
if (refund_failed or 0) > 0:
    alerts.append({"severity": "bad", "text": f"{refund_failed} возвратов не прошли — деньги клиента у нас, крон досылает"})
if sync_broken:
    alerts.append({"severity": "bad", "text": "Сверка с BookNow не работает: отмены и переносы не доезжают до сайта"})
if (attention or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{attention} броней ждут решения в админке (вернуть/удержать/закрыть)"})
if (needs_attn or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{needs_attn} броней с неопределённым исходом — ручной разбор"})
if (pending_review or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{pending_review} броней по сертификату ждут одобрения"})
if (stuck_pay or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{stuck_pay} броней в AWAITING_PAYMENT дольше 2 ч — крон сверки не закрывает?"})
if webhook_err or create_err:
    alerts.append({"severity": "warn", "text": f"Ошибки оплат за сутки: вебхук {webhook_err}, создание платежа {create_err} — см. docker logs wakeparty-app"})
if (no_funds7 or 0) > 0:
    alerts.append({"severity": "warn", "text": f"{no_funds7} отказов ЮKassa в возврате (нет средств) за 7 дней"})

doc = {"generated_at": now.isoformat(timespec="seconds"), "kpis": kpis, "charts": charts,
       "tables": tables, "alerts": alerts}
tmp = OUT + ".tmp"
with open(tmp, "w") as f:
    json.dump(doc, f, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, OUT)
PY
