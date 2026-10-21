#!/bin/bash
# Аналитика тестового стенда «График отпусков» (bob, локальная сеть) для вкладки «Проекты»
# (формат — docs/analytics-schema.md). С Beget до bob не достать, поэтому сборщик идёт
# с vm-claude: собирает документ на bob (ssh bob, только чтение — SELECT, docker ps, df) и
# кладёт готовый файл на хост дашборда. Крон пользователя nel на vm-claude, раз в 10 мин.
set -u
DASH_HOST=${DASH_HOST:-root@212.8.228.248}
DEST=${DEST:-/var/lib/infodash/projects/otpuska.json}
TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT

ssh -o ConnectTimeout=15 -o BatchMode=yes bob 'bash -s' > "$TMP" <<'REMOTE' || exit 1
set -u
psqlq() { docker exec -i otpusk-stand-db-1 sh -c 'psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -tA -F"|"'; }
export SQL_OUT=$(psqlq <<'SQL'
SELECT 'campaign', year, status, collect_until, approve_until FROM campaign ORDER BY year;
SELECT 'plan', c.year, p.status, count(*) FROM plan_entry p JOIN campaign c ON c.id = p.campaign_id GROUP BY 2, 3;
SELECT 'req', status, count(*) FROM vacation_request GROUP BY 2;
SELECT 'task', status, count(*) FROM approval_task GROUP BY 2;
SELECT 'overdue', count(*) FROM approval_task WHERE status = 'pending' AND due_at < now();
SELECT 'notif', status, count(*) FROM notification WHERE created_at > now() - interval '30 days' GROUP BY 2;
SELECT 'actors7', count(DISTINCT actor_employee_id) FROM audit_log WHERE occurred_at > now() - interval '7 days';
SELECT 'audit_day', date(occurred_at AT TIME ZONE 'Asia/Vladivostok'), count(*) FROM audit_log
  WHERE occurred_at > now() - interval '31 days' GROUP BY 2;
SELECT 'req_day', date(created_at AT TIME ZONE 'Asia/Vladivostok'), count(*) FROM vacation_request
  WHERE created_at > now() - interval '31 days' GROUP BY 2;
SELECT 'notif_day', date(created_at AT TIME ZONE 'Asia/Vladivostok'), status, count(*) FROM notification
  WHERE created_at > now() - interval '31 days' GROUP BY 2, 3;
SELECT 'employees', count(*) FROM employee;
SQL
)
export HEALTH=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1:8080/healthz)
export CONTAINERS=$(docker ps -a --filter name=otpusk-stand --format '{{.Names}}={{.Status}}' | tr '\n' ';')
export DEPLOYED=$(head -c 120 /opt/otpuska/.deployed 2>/dev/null)
export BACKUPS=$(ls -1t ~/otpuska-backups 2>/dev/null | head -1)
export BACKUPS_N=$(ls -1 ~/otpuska-backups 2>/dev/null | wc -l)
export BACKUP_AGE_H=$(f=$(ls -1t ~/otpuska-backups/* 2>/dev/null | head -1); [ -n "$f" ] && echo $(( ($(date +%s) - $(stat -c %Y "$f")) / 3600 )))
export RUNNER=$(pgrep -f Runner.Listener >/dev/null && echo up || echo down)
export TUNNEL=$(systemctl is-active otpuska-tunnel 2>/dev/null)
export DISK=$(df --output=pcent / | tail -1 | tr -dc 0-9)
python3 - <<'PY'
import datetime as dt, json, os
VL = dt.timezone(dt.timedelta(hours=10))
today = dt.datetime.now(VL).date()
days = [(today - dt.timedelta(days=29 - i)).isoformat() for i in range(30)]
rows = [l.split("|") for l in os.environ["SQL_OUT"].splitlines() if l.strip()]
pick = lambda tag: [r[1:] for r in rows if r[0] == tag]
num = lambda v: int(float(v)) if v not in (None, "") else 0
kpis, charts, tables, alerts = [], [], [], []

health = os.environ.get("HEALTH")
cont = [c.split("=", 1) for c in os.environ.get("CONTAINERS", "").split(";") if "=" in c]
# init — одноразовый контейнер миграций: «Exited (0)» для него норма
unhealthy = [n for n, st in cont if not (st.startswith("Exited (0)") and n.endswith("init-1"))
             and ("healthy" not in st or "unhealthy" in st)]
kpis.append({"id": "stand", "label": "Стенд", "value": "работает" if health == "200" and not unhealthy else "сбой",
             "state": "ok" if health == "200" and not unhealthy else "bad"})
if health != "200":
    alerts.append({"severity": "bad", "text": f"/healthz стенда отвечает {health or 'нет ответа'}"})
if unhealthy:
    alerts.append({"severity": "bad", "text": "Контейнеры не healthy: " + ", ".join(unhealthy)})

camps = pick("campaign")
STATUS = {"collecting": "сбор пожеланий", "approval": "согласование", "hr_check": "проверка кадрами",
          "approved": "утверждён", "execution": "исполнение", "closed": "закрыт", "draft": "черновик"}
current = camps[-1] if camps else None
if current:
    kpis.append({"id": "campaign", "label": f"Кампания {current[0]}", "value": STATUS.get(current[1], current[1]),
                 "hint": f"сбор до {current[2]}, согласование до {current[3]}"})
tasks = {s: num(n) for s, n in pick("task")}
overdue = num((pick("overdue") or [["0"]])[0][0])
kpis.append({"id": "tasks_pending", "label": "Задач на согласовании", "value": tasks.get("pending", 0)})
# Просроченные согласования — рабочий процесс стенда, а не сбой: плитка без предупреждения и без алерта.
kpis.append({"id": "overdue", "label": "Просрочено задач", "value": overdue})
actors = num((pick("actors7") or [["0"]])[0][0])
kpis.append({"id": "actors7", "label": "Работников с действиями за 7 дней", "value": actors})
kpis.append({"id": "employees", "label": "Работников в базе", "value": num((pick("employees") or [["0"]])[0][0])})
dep = os.environ.get("DEPLOYED", "").split()
if len(dep) == 2:
    when = dt.datetime.fromisoformat(dep[0]).astimezone(VL).strftime("%d.%m %H:%M")
    kpis.append({"id": "deployed", "label": "Выкатан коммит", "value": dep[1][:7], "hint": f"выкатка {when} (Владивосток)"})
bn, bage = num(os.environ.get("BACKUPS_N")), os.environ.get("BACKUP_AGE_H")
kpis.append({"id": "backups", "label": "Бэкапов базы", "value": bn,
             "state": "warn" if not bn or (bage and int(bage) > 48) else "ok",
             "hint": f"последний {bage} ч назад" if bage else "нет"})
if not bn or (bage and int(bage) > 48):
    alerts.append({"severity": "warn", "text": f"Последний бэкап базы стенда {bage or '—'} ч назад"})
runner = os.environ.get("RUNNER")
kpis.append({"id": "runner", "label": "Раннер CI", "value": "работает" if runner == "up" else "остановлен",
             "state": "ok" if runner == "up" else "warn"})
if runner != "up":
    alerts.append({"severity": "warn", "text": "GitHub Actions runner на bob не запущен — автодеплой встанет"})
if os.environ.get("TUNNEL") != "active":
    alerts.append({"severity": "bad", "text": f"Туннель на ru3 (otpuska-tunnel): {os.environ.get('TUNNEL')} — стенд снаружи недоступен"})
disk = num(os.environ.get("DISK"))
kpis.append({"id": "disk", "label": "Диск bob", "value": disk, "unit": "%", "state": "warn" if disk >= 85 else "ok"})
if disk >= 85:
    alerts.append({"severity": "warn", "text": f"Диск bob заполнен на {disk} %"})
notif = {s: num(n) for s, n in pick("notif")}
if notif.get("failed"):
    alerts.append({"severity": "warn", "text": f"Уведомлений с ошибкой за 30 дней: {notif['failed']}"})

audit = {d: num(n) for d, n in pick("audit_day")}
reqd = {d: num(n) for d, n in pick("req_day")}
charts.append({"id": "activity", "title": "Действия пользователей по дням", "kind": "bar", "unit": "шт",
               "note": "записи журнала аудита: заявки, решения, правки графика",
               "series": [{"name": "действия", "points": [[d, audit.get(d, 0)] for d in days]}]})
charts.append({"id": "requests", "title": "Новые заявления по дням", "kind": "bar", "unit": "шт",
               "series": [{"name": "заявления", "points": [[d, reqd.get(d, 0)] for d in days]}]})
nd = {}
for d, st, n in pick("notif_day"):
    nd.setdefault(st, {})[d] = num(n)
if nd:
    charts.append({"id": "notifications", "title": "Уведомления по дням", "kind": "bar", "unit": "шт",
                   "series": [{"name": {"sent": "отправлены", "failed": "ошибки", "pending": "в очереди"}.get(st, st),
                               "points": [[d, v.get(d, 0)] for d in days]} for st, v in list(nd.items())[:4]]})

PLAN = {"draft": "черновик", "submitted": "отправлена", "approved": "согласована", "rejected": "отклонена"}
tables.append({"id": "plan", "title": "Строки графика по кампаниям", "columns": [
    {"key": "year", "label": "Год"}, {"key": "status", "label": "Статус"}, {"key": "n", "label": "Строк", "num": True}],
    "rows": [{"year": y, "status": PLAN.get(s, s), "n": num(n)} for y, s, n in sorted(pick("plan"))]})
REQ = {"submitted": "на согласовании", "approved": "согласовано", "executed": "исполнено", "rejected": "отклонено",
       "withdrawn": "отозвано", "cancelled": "отменено", "draft": "черновик"}
tables.append({"id": "requests", "title": "Заявления и задачи согласования", "columns": [
    {"key": "kind", "label": "Что"}, {"key": "status", "label": "Статус"}, {"key": "n", "label": "Кол-во", "num": True}],
    "rows": [{"kind": "Заявления", "status": REQ.get(s, s), "n": num(n)} for s, n in pick("req")] +
            [{"kind": "Задачи", "status": {"pending": "ждут решения", "approved": "одобрены", "rejected": "отклонены",
                                            "cancelled": "сняты"}.get(s, s), "n": num(n)} for s, n in pick("task")]})
tables.append({"id": "containers", "title": "Контейнеры стенда", "columns": [
    {"key": "name", "label": "Контейнер"}, {"key": "state", "label": "Статус", "state": True}, {"key": "status", "label": "Состояние"}],
    "rows": [{"name": n, "state": "bad" if n in unhealthy else "ok", "status": st} for n, st in cont]})

print(json.dumps({"generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                  "kpis": kpis, "charts": charts, "tables": tables, "alerts": alerts}, ensure_ascii=False))
PY
REMOTE

python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$TMP" || exit 1
if [ "${DRY_RUN:-0}" = 1 ]; then cat "$TMP"; exit 0; fi
ssh -o ConnectTimeout=15 -o BatchMode=yes "$DASH_HOST" "cat > $DEST.tmp && chmod 644 $DEST.tmp && mv $DEST.tmp $DEST" < "$TMP"
