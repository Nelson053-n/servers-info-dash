#!/bin/bash
# Аналитика FluxRadar для вкладки «Проекты» (формат — docs/analytics-schema.md).
# Запускается root-кроном на хосте flux (/etc/cron.d/infodash-projects). Только чтение:
# публичный API сайта и systemctl/docker статусы.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
API=https://fluxradar.ru/api/v1
WALLET=t1MRWH9Q9sWA1XvqmwGoWqynaFFquq8pb7K

get() { curl -s -m 20 "$API/$1"; }
export J_PRICE=$(get network/price)
export J_HIST=$(get network/price/history)
export J_WALLET=$(get "wallet/$WALLET/summary")
export J_VIS=$(get stats/visitors)
export J_NODES=$(get network/nodes)
export UNITS=$(systemctl list-units 'flux*' --type=service --all --no-legend --plain 2>/dev/null | awk '{print $1"="$3}' | tr '\n' ' ')
export CONTAINERS=$(docker ps -a --filter name=flux --format '{{.Names}}={{.State}}' 2>/dev/null | tr '\n' ' ')

mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR/flux.json" <<'PY'
import datetime as dt, json, os, sys
VL = dt.timezone(dt.timedelta(hours=10))

def j(name):
    try:
        return json.loads(os.environ.get(name) or "")
    except ValueError:
        return None

price, hist, wallet, vis, nodes = j("J_PRICE"), j("J_HIST"), j("J_WALLET"), j("J_VIS"), j("J_NODES")
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
