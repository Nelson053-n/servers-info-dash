#!/bin/bash
# Аналитика trade4 (стратегии st4–st9) для вкладки «Проекты» (формат — docs/analytics-schema.md).
# Root-крон на хосте trade4 (/etc/cron.d/infodash-projects). Только чтение: логин JSON-ом
# (креды из drop-in юнита читаются внутри процесса и никуда не выводятся) и GET-запросы.
# Порт 8004 — trade4; на 8001 чужой pairsignal с похожим API.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR/trade.json" <<'PY'
import datetime as dt, json, os, re, subprocess, sys, urllib.request
B = "http://127.0.0.1:8004"
MSK = dt.timezone(dt.timedelta(hours=3))
VL = dt.timezone(dt.timedelta(hours=10))
now_msk = dt.datetime.now(MSK)
today_vl = dt.datetime.now(VL).date()
days30 = [(today_vl - dt.timedelta(days=29 - i)).isoformat() for i in range(30)]
kpis, charts, tables, alerts = [], [], [], []

def forts_open(t):
    # Пн–пт 07:00–23:50, сб/вс 10:00–19:00 МСК (канон — app/st5/forts_schedule.py)
    m = t.hour * 60 + t.minute
    return 420 <= m < 1430 if t.weekday() < 5 else 600 <= m < 1140

def get(path, cookie):
    req = urllib.request.Request(B + path, headers={"Cookie": cookie} if cookie else {})
    try:
        return json.loads(urllib.request.urlopen(req, timeout=30).read())
    except Exception:
        return None

cookie = None
try:
    unit = subprocess.run(["systemctl", "cat", "trade4"], capture_output=True, text=True).stdout
    u = re.search(r"Environment=TRADE4_USER=(\S+)", unit).group(1)
    p = re.search(r"Environment=TRADE4_PASS=(\S+)", unit).group(1)
    r = urllib.request.urlopen(urllib.request.Request(B + "/login", data=json.dumps({"username": u, "password": p}).encode(),
                                                      headers={"Content-Type": "application/json"}), timeout=15)
    cookie = next(v.split(";")[0] for h, v in r.getheaders() if h.lower() == "set-cookie")
except Exception:
    alerts.append({"severity": "bad", "text": "Не удалось войти в trade4 — данные стратегий недоступны"})

health = get("/health", None)
if health is None:
    alerts.append({"severity": "bad", "text": "trade4 не отвечает на /health"})
st = {s: get(f"/{s}/state", cookie) or {} for s in ("st5", "st6", "st7", "st8", "st9")} if cookie else {}
pairs = [p["id"] for p in (health or {}).get("pairs", [])]
st4 = {p: get(f"/st4/state?pair={p}", cookie) or {} for p in pairs} if cookie else {}

# P&L закрытых сделок по дням (Владивосток) — из журналов движков
daily = {s: {d: 0.0 for d in days30} for s in ("st5", "st8", "st9")}
def add(s, ts_ms=None, date=None, pnl=0.0):
    d = date or dt.datetime.fromtimestamp(ts_ms / 1000, VL).date().isoformat()
    if d in daily[s]:
        daily[s][d] += pnl or 0
for t in st.get("st5", {}).get("trades") or []:
    if t.get("exit_ts"):
        add("st5", ts_ms=t["exit_ts"], pnl=t.get("net_pnl_rub") or t.get("pnl_rub") or 0)
for t in st.get("st8", {}).get("trades_tail") or []:
    if t.get("exit_date"):
        add("st8", date=t["exit_date"], pnl=t.get("net_pnl_rub") or 0)
for t in st.get("st9", {}).get("trades_tail") or []:
    if t.get("exit_ts"):
        add("st9", ts_ms=t["exit_ts"], pnl=t.get("net_pnl_rub") or 0)
series = [{"name": s, "points": [[d, round(v)] for d, v in daily[s].items()]} for s in daily]
charts.append({"id": "pnl_daily", "title": "P&L закрытых сделок по дням", "kind": "bar", "unit": "₽",
               "note": "по журналам движков st5/st8/st9; у st9 и st8 — последние 20 сделок",
               "series": series})
cum, acc = [], 0
for i, d in enumerate(days30):
    acc += sum(daily[s][d] for s in daily)
    cum.append([d, round(acc)])
charts.append({"id": "pnl_cum", "title": "Накопленный P&L за 30 дней", "kind": "line", "unit": "₽", "series": [{"name": "₽", "points": cum}]})

rows, live_n, total_n, open_pos, net_total, gap_total = [], 0, 0, 0, 0, 0
def positions_of(s, o):
    if s == "st9":
        return sum(1 for i in o.get("instruments") or [] if (i.get("position") or {}).get("lots"))
    v = o.get("open_positions")
    return len(v) if isinstance(v, list) else (v or len(o.get("positions") or []))
for s, o in [(f"st4 {p}", v) for p, v in st4.items()] + list(st.items()):
    if not o:
        continue
    total_n += 1
    live = bool(o.get("live"))
    live_n += live
    pos = positions_of(s, o) if not s.startswith("st4") else (0 if o.get("fsm_state") == "flat" else 1)
    open_pos += pos or 0
    net = o.get("net_pnl_rub") or 0
    net_total += net
    gap = o.get("execution_gap_rub")
    frozen = not live and not pos  # остановлен и flat: расхождение исторически замороженное, не тревога
    gap_total += 0 if frozen else abs(gap or 0)
    state = "ok"
    if o.get("halted"):
        state = "bad"
        alerts.append({"severity": "bad", "text": f"{s}: остановлен — {o.get('halt_reason') or 'без причины'}"})
    elif gap is not None and abs(gap) > 1000 and not frozen:
        state = "warn"
        alerts.append({"severity": "warn", "text": f"{s}: журнал расходится со счётом на {round(gap)} ₽"})
    elif o.get("trading_enabled") and not live and not o.get("paused_by_user") and forts_open(now_msk):
        state = "warn"
        alerts.append({"severity": "warn", "text": f"{s}: торговля включена, но движок не live во время торгов"})
    rows.append({"strategy": s, "live": "да" if live else "нет", "mode": o.get("mode") or o.get("connector_mode") or "—",
                 "positions": pos or 0, "net": round(net), "gap": round(gap) if gap is not None else None,
                 "capital": round(o["capital_rub"]) if o.get("capital_rub") else None, "state": state})
tables.append({"id": "strategies", "title": "Стратегии", "columns": [
    {"key": "strategy", "label": "Стратегия"}, {"key": "state", "label": "Статус", "state": True},
    {"key": "live", "label": "Live"}, {"key": "mode", "label": "Счёт"}, {"key": "positions", "label": "Позиций", "num": True},
    {"key": "net", "label": "P&L всего, ₽", "num": True}, {"key": "gap", "label": "Расхождение, ₽", "num": True},
    {"key": "capital", "label": "Капитал, ₽", "num": True}], "rows": rows})

# Реестр роботов: что за версия сейчас в коде и в каком статусе. Суть/вердикты — статичный текст
# (источник: память проекта и CLAUDE.md trade4), режим/live/параметры/дата кода — живые.
def code_date(n):
    try:
        out = subprocess.run(["git", "-C", "/opt/trade4", "log", "-1", "--format=%ad", "--date=short", "--", f"app/st{n}"],
                             capture_output=True, text=True, timeout=10).stdout.strip()
        return out or "—"
    except Exception:
        return "—"
def js(o, keys):
    return ", ".join(f"{k}={o[k]}" for k in keys if k in o)
s6c, s7c = (st.get(k, {}).get("strategy") or {} for k in ("st6", "st7"))
s8c = st.get("st8", {}).get("strategy_cfg") or {}
s9i = st.get("st9", {}).get("instruments") or []
st4a = next(iter(st4.values()), {})
s5on = [p.get("pair") for p in st.get("st5", {}).get("pairs") or [] if p.get("enabled")]
robots = [
    ("st4", "BB-спред обычка/преф (SBRF/SBPR…)", "остановлен",
     st4a.get("connector_mode"), f"Bollinger SMA{st4a.get('sma_period')}/{st4a.get('sigma_mult')}σ, пары: {', '.join(pairs) or '—'}",
     "не жизнеспособен (вердикт 07.07)"),
    ("st5", "statarb, Kalman-β/коинтеграция, портфель до 3 пар", "остановлен",
     st.get("st5", {}).get("connector_mode"), f"включены пары: {', '.join(s5on) or '—'}; P&L по фактическим ногам (с 02.07)",
     "не жизнеспособен; журнал завышал vs счёт (07.07)"),
    ("st6", "фандинг-арбитраж: шорт перпа + лонг квартальника", "остановлен",
     st.get("st6", {}).get("connector_mode") or st.get("st6", {}).get("mode"), js(s6c, ["edge_enter_pp", "edge_exit_pp", "units"]), "не жизнеспособен; закрытых сделок нет, но позиции на движке открыты с 01.07 и не ведутся"),
    ("st7", "фандинг-давление: полухедж-шорт перпа", "остановлен",
     st.get("st7", {}).get("connector_mode") or st.get("st7", {}).get("mode"), js(s7c, ["fund_enter_pp", "fund_exit_pp", "units", "stop_loss_pct"]), "не жизнеспособен; сделок не было"),
    ("st8", "дивидендный набег: лонг за ~10 дн до отсечки, хедж IMOEXF", "работает",
     st.get("st8", {}).get("mode"), js(s8c, ["entry_days_before", "exit_offset_days", "min_div_yield_pct", "stop_loss_pct", "entry_notional_rub"]),
     "лонг-нога t=2.32; шорт-нога — артефакт; сезонное межсезонье (авг. 1,2% отсечек, окт. 17,5%)"),
    ("st9", "трендовая корзина перпов, Donchian+ATR 60м", "работает",
     st.get("st9", {}).get("mode"),
     "; ".join(f"{i.get('secid')} Donchian {i.get('don')}, {round((i.get('notional_rub') or 0) / 1000)}к" + ("" if i.get("entries_enabled", True) else " (входы выкл)") for i in s9i)
     + f"; стоп просадки {st.get('st9', {}).get('capital_dd_stop_pct')}%",
     "edge по плацебо реален, в деньгах не доказан (аудит 18.08); потолок ~13%/год"),
]
tables.append({"id": "robots", "title": "Версии роботов", "columns": [
    {"key": "robot", "label": "Робот"}, {"key": "what", "label": "Суть"}, {"key": "status", "label": "Статус"},
    {"key": "mode", "label": "Счёт"}, {"key": "params", "label": "Параметры сейчас"},
    {"key": "code", "label": "Код изменён"}, {"key": "verdict", "label": "Вердикт"}],
    "rows": [{"robot": r, "what": w, "status": "работает" if st.get(r, {}).get("live") else "остановлен", "mode": m or "—", "params": p or "—",
              "code": code_date(r[2:]), "verdict": v} for r, w, _s, m, p, v in robots]})

pos_rows = []
for p in st.get("st6", {}).get("positions") or []:
    pos_rows.append({"strategy": "st6", "instrument": p.get("label") or p.get("pair"), "lots": p.get("perp_lots"),
                     "since": p.get("entry_date"), "pnl": p.get("unrealized_rub")})
for i in st.get("st9", {}).get("instruments") or []:
    pos = i.get("position") or {}
    if pos.get("lots"):
        pos_rows.append({"strategy": "st9", "instrument": f"{i.get('secid')} {pos.get('side', '')}".strip(),
                         "lots": pos.get("lots"), "since": "", "pnl": pos.get("unrealized_rub")})
for p in st.get("st5", {}).get("positions") or []:
    pos_rows.append({"strategy": "st5", "instrument": p.get("pair"), "lots": p.get("lots"), "since": "", "pnl": p.get("unrealized_rub")})
tables.append({"id": "positions", "title": "Открытые позиции", "columns": [
    {"key": "strategy", "label": "Стратегия"}, {"key": "instrument", "label": "Инструмент"}, {"key": "lots", "label": "Лотов", "num": True},
    {"key": "since", "label": "С"}, {"key": "pnl", "label": "Нереализ., ₽", "num": True}], "rows": pos_rows})

rec = get("/reconcile/daily", cookie) if cookie else None
if rec:
    rec_rows = [{"engine": e.get("engine"), "fact": e.get("account_fact"), "fee": round(e.get("journal_fee") or 0, 2)} for e in rec.get("engines") or []]
    tables.append({"id": "reconcile", "title": f"Сверка со счётом за {rec.get('day')}", "columns": [
        {"key": "engine", "label": "Движок"}, {"key": "fact", "label": "Счёт"}, {"key": "fee", "label": "Комиссии журнала, ₽", "num": True}],
        "rows": rec_rows})
    bad_rec = [r["engine"] for r in rec_rows if "⚠" in str(r["fact"])]
    if bad_rec:
        alerts.append({"severity": "warn", "text": "Сверка комиссий со счётом: расхождение у " + ", ".join(bad_rec)})

day_pnl = sum(daily[s][days30[-1]] for s in daily)  # закрытые сегодня (по Владивостоку) сделки
kpis += [
    {"id": "net_total", "label": "P&L всех стратегий", "value": round(net_total), "unit": "₽",
     "state": "ok" if net_total >= 0 else "warn", "hint": "net_pnl_rub за всё время, песочница T-Bank"},
    {"id": "pnl_30d", "label": "P&L за 30 дней", "value": cum[-1][1] if cum else 0, "unit": "₽"},
    {"id": "live", "label": "Стратегий в live", "value": f"{live_n} из {total_n}"},
    {"id": "market", "label": "Биржа FORTS", "value": "торги идут" if forts_open(now_msk) else "закрыта"},
    {"id": "positions", "label": "Открытых позиций", "value": open_pos},
    {"id": "pnl_today", "label": "P&L сегодня", "value": round(day_pnl), "unit": "₽"},
    {"id": "gap", "label": "Расхождение журнал/счёт", "value": round(gap_total), "unit": "₽",
     "state": "warn" if gap_total > 1000 else "ok", "hint": "сумма |execution_gap_rub| по движкам"},
]
modes = {r["mode"] for r in rows}
if any("real" in m for m in modes):
    kpis.append({"id": "real", "label": "Реальный счёт", "value": "есть движки на реальном счёте", "state": "warn"})

doc = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
       "kpis": kpis, "charts": charts, "tables": tables, "alerts": alerts}
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[1])
PY
