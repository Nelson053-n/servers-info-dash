#!/bin/bash
# Балансы API nanabanana (kie.ai, OpenRouter, Google AI) для вкладки «Проекты».
# Root-крон раз в час (/etc/cron.d/infodash-projects). Ключи лежат зашифрованными в БД бота
# (Setting['api_keys']), расшифровать их может только код бота — поэтому здесь запускается
# getRealApiKeys через tsx, а окружение Node читает из .env сам (--env-file): значения не
# проходят через shell и нигде не печатаются. В файл пишутся только суммы в долларах.
# Способ и пояснения к цифрам — nanabanana/.claude/skills/prod-health/SKILL.md.
set -u
OUT_DIR=${OUT_DIR:-/var/lib/infodash/projects}
APP=/opt/nanabanana
TS=$APP/.infodash-balances.ts
trap 'rm -f "$TS"' EXIT
cat > "$TS" <<'TSEOF'
import { PrismaClient } from '@prisma/client';
import { getRealApiKeys } from './src/services/runtime-config.service';
const prisma = new PrismaClient();
const KIE_TOKEN_USD = 0.005;
(async () => {
  const out: Record<string, number | string | null> = {};
  const keys: any = await getRealApiKeys(prisma);
  const { fetch: uf, ProxyAgent } = await import('undici');
  const proxy = process.env.GOOGLE_SOCKS_PROXY;
  const call = async (url: string, key: string) => {
    const o: any = { headers: { Authorization: `Bearer ${key}` }, signal: AbortSignal.timeout(12000) };
    if (proxy) o.dispatcher = new ProxyAgent(proxy);
    const r = await uf(url, o);
    return { status: r.status, body: (await r.json()) as any };
  };
  try {
    const j = await call('https://api.kie.ai/api/v1/chat/credit', keys.kieApiKey || '');
    out.kie_usd = j.body?.code === 200 ? Number(j.body.data) * KIE_TOKEN_USD : null;
  } catch { out.kie_usd = null; }
  try {
    const k = keys.openrouterGenerationKey || keys.openrouterSupportKey || '';
    const { status, body } = await call('https://openrouter.ai/api/v1/credits', k);
    out.openrouter_usd = status === 200 ? Number(body?.data?.total_credits ?? 0) - Number(body?.data?.total_usage ?? 0) : null;
  } catch { out.openrouter_usd = null; }
  try {
    const row = await prisma.setting.findUnique({ where: { key: 'provider_balances' } });
    const g = (row?.value as any)?.GOOGLE_AI;
    if (g) {
      const r = await prisma.$queryRaw<Array<{ total: number }>>`
        SELECT COALESCE(SUM("apiCostUsd"),0) as total FROM "Generation"
        WHERE "apiProvider"='GOOGLE_AI'::"ApiProvider" AND "createdAt" >= ${new Date(g.startDate)}`;
      out.google_usd = g.initialBalanceUsd - (Number(r[0]?.total ?? 0) + (g.costAdjustmentUsd ?? 0));
    } else out.google_usd = null;
  } catch { out.google_usd = null; }
  await prisma.$disconnect();
  console.log('BALANCES ' + JSON.stringify(out));
})();
TSEOF
LINE=$(cd "$APP" && timeout 120 npx tsx --env-file=.env "$TS" 2>/dev/null | grep '^BALANCES ' | tail -1)
[ -n "$LINE" ] || exit 1
mkdir -p "$OUT_DIR"
python3 - "$OUT_DIR/nanabanana-balances.json" "${LINE#BALANCES }" <<'PY'
import datetime as dt, json, os, sys
data = {k: (round(v, 2) if isinstance(v, (int, float)) else None) for k, v in json.loads(sys.argv[2]).items()}
data["generated_at"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
tmp = sys.argv[1] + ".tmp"
with open(tmp, "w") as fh:
    json.dump(data, fh)
os.chmod(tmp, 0o644)
os.replace(tmp, sys.argv[1])
PY
