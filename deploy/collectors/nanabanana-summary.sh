#!/bin/bash
# Сводка прода nanabanana для вкладки «Проекты». Запускается root-кроном на хосте nanabanana
# (/etc/cron.d/infodash-projects): дашборд работает от infodash и к docker доступа не имеет,
# поэтому числа снимает root, а дашборд только читает готовый файл.
# Только чтение: SELECT, systemctl is-active, curl к localhost.
set -u
OUT_DIR=/var/lib/infodash/projects
OUT=$OUT_DIR/nanabanana.json
PSQL="docker exec nb-postgres psql -U nanabanana -d nanabanana -tAc"

q() { timeout 20 $PSQL "$1" 2>/dev/null | head -1; }

export S_BOT=$(systemctl is-active nb-bot 2>/dev/null)
export S_WEB=$(systemctl is-active nb-web 2>/dev/null)
export H_WEB=$(curl -s -o /dev/null -m 10 -w '%{http_code}' http://127.0.0.1:3000/api/health)
export G_ROW=$(q "SELECT count(*), count(*) FILTER (WHERE status='DONE'), count(*) FILTER (WHERE status='FAILED')
                  FROM \"Generation\" WHERE \"createdAt\" > now() - interval '24 hours'")
export G_STUCK=$(q "SELECT count(*) FROM \"Generation\" WHERE status::text IN ('PENDING','PROCESSING')
                    AND \"createdAt\" < now() - interval '15 minutes'")
export G_NOREFUND=$(q "SELECT count(*) FROM \"Generation\" WHERE status='FAILED' AND \"isRefunded\"=false
                       AND \"createdAt\" > now() - interval '24 hours'")
export P_ROW=$(q "SELECT count(*), COALESCE(sum(\"amountRub\"),0) FROM \"Transaction\"
                  WHERE type='PURCHASE' AND status='COMPLETED' AND \"amountRub\" > 0
                    AND \"createdAt\" > now() - interval '24 hours'")
export A_CNT=$(q "SELECT count(*) FROM \"ApiAlert\" WHERE \"createdAt\" > now() - interval '24 hours'")

mkdir -p "$OUT_DIR"
python3 - "$OUT" <<'PY'
import json, os, sys, datetime
def ints(name, n):
    parts = (os.environ.get(name) or '').split('|')
    out = []
    for i in range(n):
        try: out.append(int(float(parts[i])))
        except (IndexError, ValueError): out.append(None)
    return out
total, done, failed = ints('G_ROW', 3)
paid, rub = ints('P_ROW', 2)
data = {
    "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "services": {"nb-bot": os.environ.get("S_BOT") or "unknown", "nb-web": os.environ.get("S_WEB") or "unknown"},
    "health_http": ints('H_WEB', 1)[0],
    "generations_24h": {"total": total, "done": done, "failed": failed,
                        "stuck": ints('G_STUCK', 1)[0], "failed_no_refund": ints('G_NOREFUND', 1)[0]},
    "purchases_24h": {"count": paid, "rub": rub},
    "api_alerts_24h": ints('A_CNT', 1)[0],
}
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as f:
    json.dump(data, f, ensure_ascii=False)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[1])
PY
