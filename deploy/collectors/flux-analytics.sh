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
            if "coinbase" not in (tx.get("vin") or [{}])[0]:
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
    claim = sum(c.get("claimable", 0) for c in wallet.get("pa_chains") or [])
    kpis.append({"id": "pa_claimable", "label": "PA к получению", "value": round(claim, 1), "unit": "FLUX",
                 "hint": "Parallel Assets: сумма claimable по сетям"})
    tables.append({"id": "pa", "title": "Parallel Assets по сетям",
                   "columns": [{"key": "chain", "label": "Сеть"}, {"key": "claimable", "label": "К получению", "num": True},
                               {"key": "claimed", "label": "Получено", "num": True}, {"key": "fees", "label": "Комиссии", "num": True}],
                   "rows": [{k: (round(c[k], 2) if isinstance(c.get(k), float) else c.get(k)) for k in ("chain", "claimable", "claimed", "fees")}
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
        kpis.append({"id": "earn_day", "label": "Доход в сутки", "value": round((ern.get("daily") or {}).get("flux", 0), 1), "unit": "FLUX",
                     "hint": f"≈ {round((ern.get('daily') or {}).get('usd', 0), 2)} $ в сутки, ≈ {round((ern.get('monthly') or {}).get('usd', 0))} $ в месяц"})
        kpis.append({"id": "apy", "label": "APY", "value": round(ern.get("apy_percent", 0), 1), "unit": "%"})
    tot = wallet.get("totals") or {}
    if tot.get("mined"):
        kpis.append({"id": "mined", "label": "Намайнено всего", "value": round(tot["mined"].get("flux", 0)), "unit": "FLUX",
                     "hint": f"≈ {round(tot['mined'].get('usd', 0))} $; получено {round((tot.get('claimed') or {}).get('flux', 0))} FLUX"})
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

# ── Доход нод по месяцам: FLUX × курс FLUX на день выплаты × курс ЦБ на этот день ──
by_usd = {}
for p_ in pts:
    by_usd[dt.datetime.fromtimestamp(p_["t"], dt.timezone.utc).date()] = p_["usd"]
if by_usd:
    first_day = min(by_usd)
    rewards, backfill = load_rewards(dt.datetime.combine(first_day, dt.time(), dt.timezone.utc).timestamp())
    rate = cbr_usd_rub(first_day, dt.datetime.now(dt.timezone.utc).date())
    if rewards and rate:
        def rub_at(day):
            usd = by_usd.get(day) or by_usd[max(d for d in by_usd if d <= day)] if day >= first_day else None
            r = rate.get(day) or next((rate[d] for d in sorted(rate, reverse=True) if d <= day), None)
            return None if usd is None or r is None else usd * r
        # Parallel Assets: каждая из PA-сетей даёт +10 % к каждой награде (fusion: maxClaimablePerChain = 10 % от всех наград
        # на адрес); начисляется независимо от того, выведено или нет. Число сетей берём из сводки кошелька.
        pa_k = 0.1 * len((wallet or {}).get("pa_chains") or [])
        flux_m, pa_m, rub_m = {}, {}, {}
        for ts, val in rewards.values():
            day = dt.datetime.fromtimestamp(ts, dt.timezone.utc).date()
            rr = rub_at(day)
            if rr is None:
                continue
            m = dt.datetime.fromtimestamp(ts, VL).strftime("%Y-%m")
            flux_m[m] = flux_m.get(m, 0) + val
            pa_m[m] = pa_m.get(m, 0) + val * pa_k
            rub_m[m] = rub_m.get(m, 0) + val * (1 + pa_k) * rr
        now_l = dt.datetime.now(VL)
        months = []
        y, mo = now_l.year, now_l.month
        for _ in range(12):
            months.append("%04d-%02d" % (y, mo))
            mo -= 1
            if mo == 0:
                y, mo = y - 1, 12
        months.reverse()
        # месяц, в котором начинается история курса, неполный — его не показываем
        full_from = (dt.datetime.combine(first_day, dt.time(), dt.timezone.utc).astimezone(VL).date().replace(day=1) + dt.timedelta(days=32)).strftime("%Y-%m")
        months = [m for m in months if m >= full_from]
        cur, prev = now_l.strftime("%Y-%m"), (now_l.replace(day=1) - dt.timedelta(days=1)).strftime("%Y-%m")
        kpis.append({"id": "revenue_month", "label": f"Доход нод с 1 {MONTHS_GEN[now_l.month - 1]}", "value": round(rub_m.get(cur, 0)), "unit": "₽",
                     "hint": f"{round(flux_m.get(cur, 0))} FLUX + {round(pa_m.get(cur, 0))} PA по курсу FLUX и ЦБ на день получения; месяц по Владивостоку"})
        pm = int(prev[5:]) - 1
        if prev in flux_m or prev in months:
            kpis.append({"id": "revenue_prev_month", "label": f"Доход нод за {MONTHS_ACC[pm]}", "value": round(rub_m.get(prev, 0)), "unit": "₽"})
        charts.insert(0, {"id": "revenue_monthly", "title": "Доход нод по месяцам", "kind": "bar", "unit": "₽",
                          "note": "награды нод + Parallel Assets (начислено, без учёта вывода) в рублях по курсу на день получения; текущий месяц неполный",
                          "series": [{"name": "₽", "points": [[m, round(rub_m.get(m, 0))] for m in months]}]})
        charts.insert(1, {"id": "income_flux_monthly", "title": "Доход нод по месяцам, FLUX", "kind": "bar", "unit": "FLUX",
                          "note": "начислено: награды нод и Parallel Assets, без учёта вывода",
                          "series": [{"name": "награды", "points": [[m, round(flux_m.get(m, 0), 1)] for m in months]},
                                     {"name": "PA", "points": [[m, round(pa_m.get(m, 0), 1)] for m in months]}]})
        tables.append({"id": "income_months", "title": "Доход нод по месяцам",
                       "columns": [{"key": "month", "label": "Месяц"}, {"key": "flux", "label": "Награды, FLUX", "num": True},
                                   {"key": "pa", "label": "PA, FLUX", "num": True}, {"key": "total", "label": "Всего, FLUX", "num": True},
                                   {"key": "rub", "label": "₽", "num": True}, {"key": "avg", "label": "Средний курс, ₽/FLUX", "num": True}],
                       "rows": [{"month": m, "flux": round(flux_m.get(m, 0), 1), "pa": round(pa_m.get(m, 0), 1),
                                 "total": round(flux_m.get(m, 0) + pa_m.get(m, 0), 1), "rub": round(rub_m.get(m, 0)),
                                 "avg": round(rub_m[m] / (flux_m[m] + pa_m[m]), 2) if flux_m.get(m) else None} for m in reversed(months)]})
        if backfill:
            alerts.append({"severity": "warn", "text": "История наград догружается из эксплорера, цифры по старым месяцам неполные"})
    else:
        alerts.append({"severity": "warn", "text": "Доход по месяцам не посчитан: нет данных эксплорера или курса ЦБ"})

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
