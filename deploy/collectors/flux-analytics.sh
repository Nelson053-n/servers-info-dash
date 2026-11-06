#!/bin/bash
# Аналитика FluxRadar для вкладки «Проекты» (формат — docs/analytics-schema.md).
# Запускается root-кроном на хосте flux (/etc/cron.d/infodash-projects). Только чтение:
# публичный API сайта и systemctl/docker статусы.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
API=https://fluxradar.ru/api/v1
WALLET=t1MRWH9Q9sWA1XvqmwGoWqynaFFquq8pb7K
STATE=${STATE:-/var/lib/infodash/flux-rewards.json}
export WALLET STATE

get() { curl -s -m 20 "$API/$1"; }
export J_PRICE=$(get network/price)
export J_HIST=$(get network/price/history)
export J_WALLET=$(get "wallet/$WALLET/summary")
export J_VIS=$(get stats/visitors)
export J_NODES=$(get network/nodes)
export J_WNODES=$(get "wallet/$WALLET/nodes")
export UNITS=$(systemctl list-units 'flux*' --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1"="$3}' | tr '\n' ' ')
export CONTAINERS=$(docker ps -a --filter name=flux --format '{{.Names}}={{.State}}' 2>/dev/null | tr '\n' ' ')

mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR/flux.json" <<'PY'
import datetime as dt, json, os, sys
VL = dt.timezone(dt.timedelta(hours=10))
MSK = dt.timezone(dt.timedelta(hours=3))

import urllib.request, xml.etree.ElementTree as ET
EXPLORER = "https://explorer.runonflux.io/api/txs?address=" + os.environ["WALLET"] + "&pageNum="
MONTHS_GEN = ["января", "февраля", "марта", "апреля", "мая", "июня", "июля", "августа", "сентября", "октября", "ноября", "декабря"]
MONTHS_ACC = ["январь", "февраль", "март", "апрель", "май", "июнь", "июль", "август", "сентябрь", "октябрь", "ноябрь", "декабрь"]

def fetch(url, timeout=30):
    try:
        # эксплорер отвечает 403 на User-Agent по умолчанию у urllib
        return urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "infodash-collector"}), timeout=timeout).read()
    except Exception:
        return None

def load_rewards(since_ts, max_pages=60):
    """Награды нод = coinbase-транзакции с выходом на наш адрес. Эксплорер отдаёт 10 транзакций на страницу
    от новых к старым; кэш в STATE растёт от свежих к старым, пока не дойдёт до since_ts (курс известен только с него).
    Возвращает (награды {txid: [время, FLUX]}, нужно ли докачивать историю)."""
    path = os.environ["STATE"]
    try:
        st = json.load(open(path))
    except (OSError, ValueError):
        st = {"txs": {}, "next_page": 0, "complete": False}
    txs = st["txs"]
    page = 0 if st["complete"] else st["next_page"]
    fetched = 0
    while fetched < max_pages:
        raw = fetch(EXPLORER + str(page))
        try:
            rows = json.loads(raw)["txs"] if raw else None
        except (ValueError, KeyError, TypeError):
            rows = None
        if rows is None:
            break
        fetched += 1
        new = 0
        for tx in rows:
            if not tx.get("confirmations") or "coinbase" not in (tx.get("vin") or [{}])[0]:
                continue
            val = sum(float(o["value"]) for o in tx.get("vout") or [] if os.environ["WALLET"] in ((o.get("scriptPubKey") or {}).get("addresses") or []))
            if val and tx["txid"] not in txs:
                txs[tx["txid"]] = [tx["time"], val]
                new += 1
        oldest = min((tx["time"] for tx in rows), default=0)
        if not rows or oldest < since_ts:
            st["complete"] = True
            break
        if st["complete"] and new == 0 and all(tx["txid"] in txs or "coinbase" not in (tx.get("vin") or [{}])[0] for tx in rows):
            break
        page += 1
        st["next_page"] = page
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(st, fh)
    os.replace(tmp, path)
    return txs, not st["complete"]

def cbr_usd_rub(d1, d2):
    """Курс ЦБ USD/RUB по датам; на выходные и праздники — последний известный."""
    raw = fetch("https://www.cbr.ru/scripts/XML_dynamic.asp?date_req1=%s&date_req2=%s&VAL_NM_RQ=R01235" % (d1.strftime("%d/%m/%Y"), d2.strftime("%d/%m/%Y")))
    out = {}
    if raw:
        try:
            for r in ET.fromstring(raw).findall("Record"):
                out[dt.datetime.strptime(r.get("Date"), "%d.%m.%Y").date()] = float(r.find("Value").text.replace(",", ".")) / int(r.find("Nominal").text)
        except (ET.ParseError, ValueError, AttributeError):
            return {}
    return out

def pa_accrual(native, timestamp):
    """Оценка gross PA, не claim. Точный час закрытия Ergo 21.09.2026 не опубликован.

    https://docs.runonflux.com/fluxnodes/claim-parallel-assets/
    На спорную календарную дату оставляем диапазон 9–10 PA, по 10% каждый.
    """
    day = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).date()
    if day < dt.date(2026, 9, 21):
        return native, native
    if day == dt.date(2026, 9, 21):
        return native * 0.9, native
    return native * 0.9, native * 0.9


def pa_totals(wallet):
    chains = (wallet or {}).get("pa_chains") or []
    if not chains or (wallet.get("totals") or {}).get("is_estimate", True):
        return None
    return {key: sum(c[key] for c in chains)
            if all(isinstance(c.get(key), (int, float)) for c in chains) else None
            for key in ("claimable", "claimed", "received", "fees")}


def monthly_income(rewards, price_points, rub_rates):
    # Месяц — Владивосток, котировка — UTC-дата выплаты. Native берём из транзакций,
    # а не из сегодняшнего прогноза. Отсутствие курса не обнуляет полученные монеты.
    prices = {dt.datetime.fromtimestamp(p["t"], dt.timezone.utc).date(): p["usd"]
              for p in price_points if isinstance(p.get("usd"), (int, float))}
    out = {}
    for timestamp, native in rewards.values():
        date = dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).date()
        month = dt.datetime.fromtimestamp(timestamp, VL).strftime("%Y-%m")
        row = out.setdefault(month, {"native": 0, "pa_min": 0, "pa_max": 0,
                                    "rub_min": 0, "rub_max": 0, "usd_min": 0, "usd_max": 0,
                                    "rewards": 0, "priced": 0, "usd_priced": 0})
        low, high = pa_accrual(native, timestamp)
        row["native"] += native
        row["pa_min"] += low
        row["pa_max"] += high
        row["rewards"] += 1
        usd = prices.get(date)
        rub = next((rub_rates[d] for d in sorted(rub_rates, reverse=True) if d <= date), None)
        if usd is None:
            continue
        row["usd_priced"] += 1
        row["usd_min"] += (native + low) * usd
        row["usd_max"] += (native + high) * usd
        if rub is None:
            continue
        row["priced"] += 1
        row["rub_min"] += (native + low) * usd * rub
        row["rub_max"] += (native + high) * usd * rub
    for row in out.values():
        row["total_min"] = row["native"] + row["pa_min"]
        row["total_max"] = row["native"] + row["pa_max"]
        if row["priced"] != row["rewards"]:
            row["rub_min"] = row["rub_max"] = None
        if row["usd_priced"] != row["rewards"]:
            row["usd_min"] = row["usd_max"] = None
    return out


def amount_range(low, high, digits=2):
    if low is None or high is None:
        return None
    if abs(high - low) < 1e-8:
        return round(low, digits)
    return f"{low:.{digits}f}–{high:.{digits}f}"


def j(name):
    try:
        return json.loads(os.environ.get(name) or "")
    except ValueError:
        return None

price, hist, wallet, vis, nodes, wnodes = j("J_PRICE"), j("J_HIST"), j("J_WALLET"), j("J_VIS"), j("J_NODES"), j("J_WNODES")
kpis, charts, tables, alerts = [], [], [], []

if price:
    ch = price.get("change_24h")
    kpis.append({"id": "price", "label": "Курс FLUX", "value": round(price.get("flux_usd", 0), 4), "unit": "$",
                 "delta": round(ch, 1) if isinstance(ch, (int, float)) else None, "delta_label": "за 24 ч"})
else:
    alerts.append({"severity": "warn", "text": "API курса не ответил"})
if wallet:
    bal = wallet.get("balance") or {}
    kpis.append({"id": "balance_usd", "label": "Кошелёк, $", "value": round(bal.get("usd", 0)), "unit": "$"})
    kpis.append({"id": "balance_flux", "label": "Кошелёк, FLUX", "value": round(bal.get("flux", 0)), "unit": "FLUX"})
    pa = pa_totals(wallet)
    if pa is not None:
        for key, label in (("claimable", "PA доступно к claim"), ("claimed", "PA claimed до комиссий"),
                           ("received", "PA получено после комиссий"), ("fees", "PA комиссии claim")):
            kpis.append({"id": "pa_" + key, "label": label,
                         "value": round(pa[key], 2) if pa[key] is not None else None, "unit": "FLUX-экв.",
                         "hint": "Накопительно по Fusion, включая исторические сети; не выплаты за месяц"})
    tables.append({"id": "pa", "title": "PA: накопительные итоги по сетям",
                   "columns": [{"key": "chain", "label": "Сеть"}, {"key": "claimable", "label": "Доступно к claim", "num": True},
                               {"key": "claimed", "label": "Claimed до комиссий", "num": True},
                               {"key": "received", "label": "Получено после комиссий", "num": True},
                               {"key": "fees", "label": "Комиссии", "num": True}],
                   "rows": [{**{k: (round(c[k], 2) if isinstance(c.get(k), (int, float)) else c.get(k))
                                  for k in ("chain", "claimable", "claimed", "received", "fees")},
                             "chain": c["chain"] + (" (закрыт, остаток)" if c["chain"] == "erg" else "")}
                            for c in wallet.get("pa_chains") or []]})
    fleet = (wnodes or {}).get("nodes")
    total = wallet.get("total_nodes")
    # «Активна» = статус CONFIRMED в сети; «прошла тест» = бенчмарк пройден (bench_passed в сводке кошелька)
    active = sum(1 for n in fleet if n.get("status") == "CONFIRMED") if fleet is not None else None
    passed = wallet.get("bench_passed")
    if total is not None:
        t = wallet.get("tiers") or {}
        kpis.append({"id": "my_nodes", "label": "Наши ноды", "value": total, "unit": "шт",
                     "hint": f"Cumulus {t.get('cumulus', 0)}, Nimbus {t.get('nimbus', 0)}, Stratus {t.get('stratus', 0)}"})
        if active is not None:
            kpis.append({"id": "my_active", "label": "Активно (CONFIRMED)", "value": active, "unit": f"из {total}",
                         "state": "ok" if active == total else "bad"})
            if active < total:
                alerts.append({"severity": "bad", "text": f"Активны {active} нод из {total}"})
        if passed is not None:
            kpis.append({"id": "my_bench", "label": "Прошли тест", "value": passed, "unit": f"из {total}",
                         "state": "ok" if passed == total else "warn"})
            if passed < total:
                alerts.append({"severity": "warn", "text": f"Тест бенчмарка прошли {passed} нод из {total}"})
    if wallet.get("fleet_uptime_pct") is not None:
        kpis.append({"id": "fleet_uptime", "label": "Аптайм парка", "value": round(wallet["fleet_uptime_pct"], 1), "unit": "%"})
    ern = wallet.get("earnings") or {}
    if ern:
        kpis.append({"id": "earn_day", "label": "Прогноз начислений в сутки", "value": round((ern.get("daily") or {}).get("flux", 0), 1), "unit": "FLUX-экв.",
                     "hint": f"Native + PA до комиссий; прогноз на 30 дней. ≈ {round((ern.get('daily') or {}).get('usd', 0), 2)} $ в сутки, ≈ {round((ern.get('monthly') or {}).get('usd', 0))} $ в месяц"})
        kpis.append({"id": "apy", "label": "APY", "value": round(ern.get("apy_percent", 0), 1), "unit": "%"})
    tot = wallet.get("totals") or {}
    if tot.get("mined") and not tot.get("is_estimate", True):
        kpis.append({"id": "mined", "label": "PA начислено за всё время", "value": round(tot["mined"].get("flux", 0)), "unit": "FLUX",
                     "hint": "Накопительный gross PA из Fusion, отдельно от native и месячной оценки; это не сумма полученного"})
    if fleet:
        rows = []
        for n in sorted(fleet, key=lambda n: n.get("rank") or 0):
            ok = n.get("status") == "CONFIRMED"
            eta = n.get("payout_eta_secs")
            rows.append({"ip": n.get("ip"), "tier": (n.get("tier") or "").capitalize(), "city": (n.get("geo") or {}).get("city"),
                         "state": "ok" if ok else "bad", "status": n.get("status"), "rank": n.get("rank"),
                         "age": round((n.get("age_secs") or 0) / 86400, 1), "eta": None if eta is None else round(eta / 3600, 1),
                         "paid": dt.datetime.fromtimestamp(n["last_paid"], MSK).strftime("%d.%m %H:%M") if n.get("last_paid") else None,
                         "ver": n.get("flux_os_version")})
        tables.insert(0, {"id": "my_nodes", "title": "Наши ноды",
                          "columns": [{"key": "ip", "label": "Адрес"}, {"key": "tier", "label": "Тир"}, {"key": "city", "label": "Город"},
                                      {"key": "state", "label": "Статус", "state": True}, {"key": "status", "label": "Состояние"},
                                      {"key": "rank", "label": "Ранг", "num": True}, {"key": "age", "label": "В сети, дн", "num": True},
                                      {"key": "eta", "label": "До выплаты, ч", "num": True}, {"key": "paid", "label": "Посл. выплата, МСК"},
                                      {"key": "ver", "label": "FluxOS"}],
                          "rows": rows})
    elif fleet is None:
        alerts.append({"severity": "warn", "text": "API списка нод кошелька не ответил"})
else:
    alerts.append({"severity": "warn", "text": "API кошелька не ответил"})
if vis:
    kpis.append({"id": "visitors_today", "label": "Посетителей сегодня", "value": vis.get("today")})
    kpis.append({"id": "visitors_total", "label": "Посетителей всего", "value": vis.get("total")})
if nodes:
    kpis.append({"id": "network_nodes", "label": "Нод в сети Flux", "value": nodes.get("total")})

pts = (hist or {}).get("points") or []
if pts:
    by_day = {}
    for p in pts:
        d = dt.datetime.fromtimestamp(p["t"], VL).date().isoformat()
        by_day[d] = p["usd"]
    days = sorted(by_day)[-30:]
    charts.append({"id": "price_30d", "title": "Курс FLUX за 30 дней", "kind": "line", "unit": "$",
                   "series": [{"name": "$", "points": [[d, round(by_day[d], 4)] for d in days]}]})
    if wallet and (wallet.get("balance") or {}).get("flux"):
        f = wallet["balance"]["flux"]
        charts.append({"id": "wallet_usd_30d", "title": "Кошелёк в $ по курсу дня", "kind": "line", "unit": "$",
                       "note": "текущий баланс FLUX × курс каждого дня",
                       "series": [{"name": "$", "points": [[d, round(f * by_day[d])] for d in days]}]})

# ── Начисленный доход: полученный native + расчётные PA, до claim/комиссий ──
if pts:
    first_day = min(dt.datetime.fromtimestamp(p["t"], dt.timezone.utc).date() for p in pts)
    rewards, backfill = load_rewards(dt.datetime.combine(first_day, dt.time(), dt.timezone.utc).timestamp())
    rate = cbr_usd_rub(first_day, dt.datetime.now(dt.timezone.utc).date())
    income = monthly_income(rewards, pts, rate)
    now_l = dt.datetime.now(VL)
    months, y, mo = [], now_l.year, now_l.month
    for _ in range(12):
        months.append("%04d-%02d" % (y, mo))
        mo -= 1
        if not mo:
            y, mo = y - 1, 12
    months.reverse()
    cur, prev = months[-1], months[-2]
    for month, key, label in ((cur, "revenue_month", f"Начислено с 1 {MONTHS_GEN[now_l.month - 1]}"),
                              (prev, "revenue_prev_month", f"Начислено за {MONTHS_ACC[int(prev[5:]) - 1]}")):
        row = income.get(month)
        if row and row["rub_min"] is not None:
            kpis.append({"id": key, "label": label, "value": round(row["rub_min"]), "unit": "₽",
                         "hint": f"Получено {row['native']:.2f} native FLUX + PA (оценка) "
                                 f"{amount_range(row['pa_min'], row['pa_max'])}; до комиссий claim. "
                                 f"Оценка ₽: {amount_range(row['rub_min'], row['rub_max'], 0)}; "
                                 "при диапазоне показана нижняя граница. Курс FLUX/ЦБ по дате выплаты"})
    current = income.get(cur)
    if current:
        for key, label, val in (("native_month", "Native получено за месяц", current["native"]),
                                ("pa_accrued_month", "PA за месяц (расчёт gross)", amount_range(current["pa_min"], current["pa_max"])),
                                ("accrued_month", "Всего начислено за месяц", amount_range(current["total_min"], current["total_max"]))):
            kpis.append({"id": key, "label": label, "value": round(val, 2) if isinstance(val, (int, float)) else val,
                         "unit": "FLUX" if key == "native_month" else "FLUX-экв.",
                         "hint": "Native — coinbase на наш адрес; PA — начисления по правилам сети, не месячные claim/received"})
    note = ("Полученный native + PA (расчёт gross), до комиссий. PA: 10% на активную сеть; "
            "после закрытия Ergo — 9 сетей. За 21.09.2026 точный час неизвестен: "
            "в таблице диапазон, график показывает нижнюю границу. Месяцы — Владивосток; "
            "USD — дневной CoinGecko по UTC-дате, ₽ — курс ЦБ; это оценки, не продажи. "
            "Датированной истории claim PA нет.")
    priced_months = [m for m in months if m in income and income[m]["rub_min"] is not None]
    charts.insert(0, {"id": "revenue_monthly", "title": "Начислено native + PA по месяцам", "kind": "bar", "unit": "₽",
                      "note": note, "series": [{"name": "Начислено (нижняя оценка)",
                      "points": [[m, round(income[m]["rub_min"])] for m in priced_months]}]})
    charts.insert(1, {"id": "income_flux_monthly", "title": "Native и начисленные PA", "kind": "bar", "unit": "FLUX-экв.",
                      "note": note, "series": [{"name": "Получено native", "points": [[m, round(income[m]["native"], 2)] for m in months if m in income]},
                                               {"name": "PA (оценка, нижняя граница)", "points": [[m, round(income[m]["pa_min"], 2)] for m in months if m in income]}]})
    tables.append({"id": "income_months", "title": "Начислено: native + PA (оценка, до комиссий)",
                   "columns": [{"key": "month", "label": "Месяц"}, {"key": "native", "label": "Получено native FLUX", "num": True},
                               {"key": "rewards", "label": "Выплат", "num": True},
                               {"key": "pa", "label": "PA расчёт gross, FLUX-экв."},
                               {"key": "total", "label": "Всего начислено, FLUX-экв."},
                               {"key": "usd", "label": "$ по историческим курсам"}, {"key": "rub", "label": "₽ по историческим курсам"}],
                   "rows": [{"month": m, "native": round(income[m]["native"], 2), "rewards": income[m]["rewards"],
                             "pa": amount_range(income[m]["pa_min"], income[m]["pa_max"]),
                             "total": amount_range(income[m]["total_min"], income[m]["total_max"]),
                             "usd": amount_range(income[m]["usd_min"], income[m]["usd_max"]),
                             "rub": amount_range(income[m]["rub_min"], income[m]["rub_max"], 0)}
                            for m in reversed(months) if m in income]})
    if backfill:
        alerts.append({"severity": "warn", "text": "История native догружается: старые месяцы могут быть неполными"})
    if any(r["rub_min"] is None for m, r in income.items() if m in months):
        alerts.append({"severity": "warn", "text": "Для части выплат нет исторического курса: монеты учтены, денежная оценка месяца не показана"})
else:
    alerts.append({"severity": "warn", "text": "Исторические курсы FLUX недоступны: месячная оценка не рассчитана"})

svc_rows = []
for item in (os.environ.get("UNITS", "") + " " + os.environ.get("CONTAINERS", "")).split():
    name, _, state = item.partition("=")
    ok = state in ("active", "running")
    svc_rows.append({"name": name, "state": "ok" if ok else "bad", "status": state})
    if not ok and not name.endswith(".timer"):
        alerts.append({"severity": "bad", "text": f"{name}: {state}"})
if svc_rows:
    tables.append({"id": "services", "title": "Сервисы", "columns": [
        {"key": "name", "label": "Сервис"}, {"key": "state", "label": "Статус", "state": True}, {"key": "status", "label": "Состояние"}],
        "rows": svc_rows})

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
