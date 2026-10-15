#!/bin/bash
# Аналитика bondai.ru (портфель владельца + сам сервис) для вкладки «Проекты»
# (формат — docs/analytics-schema.md). Root-крон на хосте bondai (/etc/cron.d/infodash-projects).
# Только чтение: GET к API под JWT владельца (минтится manage.py, живёт только в памяти
# процесса и никуда не пишется) и SELECT к SQLite в режиме ro.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
APP=/opt/mvp-bonds
OWNER_ID=1

TOK=$(cd "$APP" && set -a && . ./.env && set +a && .venv/bin/python3 manage.py token "$OWNER_ID" 2>/dev/null | tail -1)
export TOK OWNER_ID
export SVC=$(systemctl is-active bondai 2>/dev/null)
export DEPLOY_LAST=$(tail -1 /var/log/bondai-autodeploy.log 2>/dev/null | cut -c1-160)
mkdir -p "$OUT_DIR"
cd "$APP" && .venv/bin/python3 - "$OUT_DIR/bonds.json" <<'PY'
import datetime as dt, json, os, sqlite3, sys, urllib.request
VL = dt.timezone(dt.timedelta(hours=10))
today = dt.datetime.now(VL).date()
days30 = [(today - dt.timedelta(days=29 - i)).isoformat() for i in range(30)]
ahead30 = [(today + dt.timedelta(days=i)).isoformat() for i in range(30)]
owner = int(os.environ["OWNER_ID"])

def api(path):
    req = urllib.request.Request("https://bondai.ru" + path, headers={"Authorization": "Bearer " + os.environ.get("TOK", "")})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=60).read())
    except Exception:
        return None

kpis, charts, tables, alerts = [], [], [], []
table = api("/portfolios/all/table")
extra = api("/portfolios/all/analytics-extra") or {}
items = (table or {}).get("items") or []
if table is None:
    alerts.append({"severity": "warn", "text": "API портфеля не ответило"})

value = sum(i.get("current_value") or 0 for i in items)
cash = extra.get("free_cash_rub") or 0
day = sum(i.get("day_profit") or 0 for i in items)
profit = sum(i.get("profit") or 0 for i in items)
w_cr = sum((i.get("coupon_rate") or 0) * (i.get("current_value") or 0) for i in items)
if items:
    kpis += [
        {"id": "value", "label": "Портфель с деньгами", "value": round(value + cash), "unit": "₽"},
        {"id": "day", "label": "Изменение за день", "value": round(day), "unit": "₽", "state": "ok" if day >= 0 else "warn"},
        {"id": "profit", "label": "Курсовая прибыль", "value": round(profit), "unit": "₽"},
        {"id": "coupons", "label": "Купонов получено", "value": round(extra.get("realized_coupons") or 0), "unit": "₽"},
        {"id": "cash", "label": "Свободные деньги", "value": round(cash), "unit": "₽"},
        {"id": "coupon_rate", "label": "Средний купон", "value": round(w_cr / value, 2) if value else None, "unit": "%",
         "hint": "купонная ставка, взвешенная по стоимости позиций"},
        {"id": "positions", "label": "Бумаг в портфеле", "value": len(items)},
    ]
if extra.get("key_rate") is not None:
    kpis.append({"id": "key_rate", "label": "Ключевая ставка ЦБ", "value": extra["key_rate"], "unit": "%"})

db = sqlite3.connect("file:data/portfolio.db?mode=ro", uri=True)
q = lambda sql, *a: db.execute(sql, a).fetchall()
pids = [r[0] for r in q("SELECT id FROM portfolios WHERE user_id = ?", owner)]
if pids:
    marks = ",".join("?" * len(pids))
    rows = dict(q(f"SELECT snapshot_date, SUM(total_value) FROM portfolio_snapshots WHERE portfolio_id IN ({marks})"
                  f" AND snapshot_date >= ? GROUP BY snapshot_date", *pids, days30[0]))
    pts, last = [], None
    for d in days30:  # выходные без снимка — переносим последнее значение, а не ноль
        last = rows.get(d, last)
        pts.append([d, round(last) if last is not None else 0])
    if any(p[1] for p in pts):
        first = next(p[1] for p in pts if p[1])
        charts.append({"id": "value_30d", "title": "Стоимость портфеля за 30 дней", "kind": "line", "unit": "₽",
                       "note": "ежедневные снимки панели", "series": [{"name": "₽", "points": pts}]})
        kpis.insert(1, {"id": "value_30d_delta", "label": "За 30 дней", "value": round(pts[-1][1] - first), "unit": "₽",
                        "delta": round(100 * (pts[-1][1] - first) / first, 1) if first else None, "delta_label": "к началу периода"})

events = extra.get("events") or []
flow = {d: 0.0 for d in ahead30}
for e in events:
    if e.get("date") in flow:
        flow[e["date"]] += e.get("amount") or 0
charts.append({"id": "cashflow_30d", "title": "Поступления на 30 дней вперёд", "kind": "bar", "unit": "₽",
               "note": "купоны, погашения и оферты по календарю", "series": [{"name": "₽", "points": [[d, round(v)] for d, v in flow.items()]}]})

new_users = dict(q("SELECT date(created_at), COUNT(*) FROM users WHERE created_at >= ? GROUP BY 1", days30[0]))
charts.append({"id": "users_30d", "title": "Новые пользователи сервиса", "kind": "bar", "unit": "шт",
               "series": [{"name": "пользователи", "points": [[d, new_users.get(d, 0)] for d in days30]}]})
users_total = q("SELECT COUNT(*) FROM users")[0][0]
pro_now = q("SELECT COUNT(*) FROM users WHERE is_pro = 1 AND (pro_until IS NULL OR pro_until >= ?)", today.isoformat())[0][0]
paid30 = q("SELECT COUNT(*), COALESCE(SUM(amount), 0) FROM pro_payments WHERE status = 'succeeded' AND created_at >= ?", days30[0])[0]
kpis += [
    {"id": "users", "label": "Пользователей сервиса", "value": users_total},
    {"id": "users_30d", "label": "Новых за 30 дней", "value": sum(new_users.values())},
    {"id": "pro", "label": "Pro-подписок", "value": pro_now},
    {"id": "pro_paid_30d", "label": "Оплат Pro за 30 дней", "value": round(paid30[1]), "unit": "₽"},
]

top = sorted(items, key=lambda i: -(i.get("current_value") or 0))[:50]
tables.append({"id": "positions", "title": "Позиции", "columns": [
    {"key": "name", "label": "Бумага"}, {"key": "value", "label": "Стоимость, ₽", "num": True},
    {"key": "weight", "label": "Доля, %", "num": True}, {"key": "coupon_rate", "label": "Купон, %", "num": True},
    {"key": "profit", "label": "Прибыль, ₽", "num": True}, {"key": "rating", "label": "Рейтинг"},
    {"key": "next_coupon", "label": "Купон"}, {"key": "maturity", "label": "Погашение"}],
    "rows": [{"name": i.get("name") or i.get("ticker"), "value": round(i.get("current_value") or 0),
              "weight": round(i.get("weight") or 0, 1), "coupon_rate": round(i.get("coupon_rate") or 0, 2),
              "profit": round(i.get("profit") or 0), "rating": i.get("company_rating") or "—",
              "next_coupon": i.get("next_coupon_date") or "—", "maturity": i.get("maturity_date") or "—"} for i in top]})
upcoming = sorted((e for e in events if e.get("date", "") >= today.isoformat()), key=lambda e: e["date"])[:20]
tables.append({"id": "events", "title": "Ближайшие выплаты", "columns": [
    {"key": "date", "label": "Дата"}, {"key": "type", "label": "Событие"}, {"key": "name", "label": "Бумага"},
    {"key": "amount", "label": "Сумма, ₽", "num": True}],
    "rows": [{"date": e["date"], "type": {"coupon": "Купон", "maturity": "Погашение", "offer": "Оферта",
                                             "amortization": "Амортизация"}.get(e.get("type"), e.get("type")), "name": e.get("name") or e.get("ticker"), "amount": round(e.get("amount") or 0)} for e in upcoming]})

# Смена рейтинга бумаг портфеля за 30 дней: последняя запись против предыдущей
tickers = {i.get("ticker") for i in items if i.get("ticker")}
changes = []
for t in tickers:
    hist = q("SELECT rating, recorded_at FROM rating_history WHERE ticker = ? ORDER BY recorded_at DESC LIMIT 2", t)
    if len(hist) == 2 and hist[0][0] != hist[1][0] and hist[0][1] >= days30[0]:
        changes.append({"ticker": t, "was": hist[1][0], "now": hist[0][0], "date": hist[0][1][:10]})
if changes:
    tables.append({"id": "ratings", "title": "Изменения рейтингов за 30 дней", "columns": [
        {"key": "ticker", "label": "Бумага"}, {"key": "was", "label": "Было"}, {"key": "now", "label": "Стало"}, {"key": "date", "label": "Дата"}],
        "rows": changes})
    alerts.append({"severity": "warn", "text": f"Сменился рейтинг у {len(changes)} бумаг портфеля"})
for a in extra.get("anomalies") or []:
    alerts.append({"severity": "warn", "text": str(a.get("text") or a.get("message") or a)[:160]})
if os.environ.get("SVC") != "active":
    alerts.append({"severity": "bad", "text": f"сервис bondai: {os.environ.get('SVC') or 'unknown'}"})
if "error" in (os.environ.get("DEPLOY_LAST") or "").lower() or "fail" in (os.environ.get("DEPLOY_LAST") or "").lower():
    alerts.append({"severity": "warn", "text": "Автодеплой: " + os.environ["DEPLOY_LAST"]})

doc = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
       "kpis": [k for k in kpis if k.get("value") is not None], "charts": charts, "tables": tables, "alerts": alerts}
for k in doc["kpis"]:
    if k.get("delta") is None:
        k.pop("delta", None); k.pop("delta_label", None)
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[1])
PY
