#!/bin/bash
# Аналитика cars.bondai.ru (калькулятор стоимости авто) для вкладки «Проекты»
# (формат — docs/analytics-schema.md). Своей БД у сайта нет — считаем посещаемость по
# отдельному журналу nginx (access_log в vhost добавлен 15.10.2026, история — с этого дня).
# Root-крон на хосте (/etc/cron.d/infodash-projects). Только чтение журналов и docker ps.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
export CONTAINER=$(docker ps -a --filter name=cars-app --format '{{.State}} {{.Status}}' | head -1)
export HEALTH=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1:3300/)
export CONTENT_MTIME=$(stat -c %Y /var/lib/docker/volumes/cars_cars-data/_data/site-content.json 2>/dev/null)
mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR/cars.json" <<'PY'
import datetime as dt, glob, gzip, json, os, re, sys
VL = dt.timezone(dt.timedelta(hours=10))
today = dt.datetime.now(VL).date()
days = [(today - dt.timedelta(days=29 - i)).isoformat() for i in range(30)]
# Свой IP — это проверки дашборда и curl с сервера, не посетители
OWN = {"212.8.228.248", "127.0.0.1"}
BOT = re.compile(r"bot|crawl|spider|slurp|curl|python|wget|httpx|go-http|headless|monitor|uptime|preview", re.I)
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"')
ASSET = re.compile(r"^/(_next|favicon|api/|.*\.(js|css|png|jpe?g|svg|ico|webp|woff2?|map|txt|xml)$)")
views = {d: 0 for d in days}
uniq = {d: set() for d in days}
calc = {d: 0 for d in days}
paths = {}
for f in sorted(glob.glob("/var/log/nginx/cars.access.log*")):
    op = gzip.open if f.endswith(".gz") else open
    with op(f, "rt", errors="replace") as fh:
        for line in fh:
            m = LINE.match(line)
            if not m:
                continue
            ip, ts, method, path, status, ua = m.groups()
            if ip in OWN or BOT.search(ua) or method != "GET":
                continue
            d = dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone(VL).date().isoformat()
            if d not in views:
                continue
            p = path.split("?")[0]
            if p.startswith("/api/cbr"):
                calc[d] += 1  # курс ЦБ запрашивается при расчёте стоимости
            if ASSET.match(p) or not status.startswith("2"):
                continue
            views[d] += 1
            uniq[d].add(ip)
            paths[p] = paths.get(p, 0) + 1

kpis, alerts = [], []
cont, health = os.environ.get("CONTAINER", ""), os.environ.get("HEALTH")
ok = cont.startswith("running") and health == "200"
kpis.append({"id": "site", "label": "Сайт", "value": "работает" if ok else "сбой", "state": "ok" if ok else "bad"})
if not ok:
    alerts.append({"severity": "bad", "text": f"cars-app: {cont or 'нет контейнера'}, ответ {health or 'нет'}"})
visitors30 = len(set().union(*uniq.values()))
kpis += [
    {"id": "visitors_today", "label": "Посетителей сегодня", "value": len(uniq[days[-1]])},
    {"id": "visitors_30d", "label": "Посетителей за 30 дней", "value": visitors30, "hint": "уникальные IP, без ботов"},
    {"id": "views_30d", "label": "Просмотров за 30 дней", "value": sum(views.values())},
    {"id": "calc_30d", "label": "Расчётов за 30 дней", "value": sum(calc.values()), "hint": "запросы курса ЦБ из калькулятора"},
]
mt = os.environ.get("CONTENT_MTIME")
if mt:
    kpis.append({"id": "content", "label": "Контент обновлён",
                 "value": dt.datetime.fromtimestamp(int(mt), VL).strftime("%d.%m.%Y")})
charts = [
    {"id": "visitors", "title": "Посетители по дням", "kind": "bar", "unit": "шт",
     "note": "уникальные IP без ботов; история с 15.10.2026",
     "series": [{"name": "посетители", "points": [[d, len(uniq[d])] for d in days]}]},
    {"id": "views", "title": "Просмотры и расчёты по дням", "kind": "bar", "unit": "шт",
     "series": [{"name": "просмотры", "points": [[d, views[d]] for d in days]},
                {"name": "расчёты", "points": [[d, calc[d]] for d in days]}]},
]
top = sorted(paths.items(), key=lambda x: -x[1])[:15]
tables = [{"id": "pages", "title": "Популярные страницы за 30 дней", "columns": [
    {"key": "path", "label": "Страница"}, {"key": "n", "label": "Просмотров", "num": True}],
    "rows": [{"path": p, "n": n} for p, n in top]}]
doc = {"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
       "kpis": kpis, "charts": charts, "tables": tables, "alerts": alerts}
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as fh:
    json.dump(doc, fh, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[1])
PY
