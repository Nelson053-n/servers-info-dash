"""Read confirmed wallet rewards; keep transfers and unrecorded costs out of profit."""
import datetime as dt
import json
import time
import urllib.request
from decimal import Decimal

WALLET = 't1MRWH9Q9sWA1XvqmwGoWqynaFFquq8pb7K'
VL = dt.timezone(dt.timedelta(hours=10))
BASE = 'https://explorer.runonflux.io/api/txs?address=' + WALLET + '&pageNum='


def fetch(page):
    request = urllib.request.Request(BASE + str(page), headers={'User-Agent': 'infodash-collector'})
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.load(response)


def read_ledger(now, read=fetch):
    start = now.astimezone(VL).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    seen = {}; crossed = False; deadline = time.monotonic() + 80
    for page in range(20):
        if time.monotonic() > deadline:
            raise ValueError('Wallet scan time limit; month coverage incomplete')
        response = read(page)
        rows = response['txs']
        for tx in rows:
            if tx['time'] < start.timestamp():
                crossed = True
            elif tx['time'] <= now.timestamp():
                seen[tx['txid']] = tx
        if crossed or not rows:
            break
    if not crossed and rows:
        raise ValueError('Month boundary not reached')
    rewards = []; outgoing = []; unconfirmed = 0
    for tx in seen.values():
        if not tx.get('confirmations'):
            unconfirmed += 1
            continue
        inputs = tx.get('vin') or [{}]
        if 'coinbase' in inputs[0]:
            value = sum((Decimal(str(o['value'])) for o in tx.get('vout', [])
                         if WALLET in o.get('scriptPubKey', {}).get('addresses', [])), Decimal(0))
            if value:
                rewards.append(dict(txid=tx['txid'], time=tx['time'], native=str(value)))
        elif any(i.get('addr') == WALLET for i in inputs):
            outgoing.append(dict(txid=tx['txid'], time=tx['time'], fees=tx.get('fees')))
    return dict(wallet=WALLET, period=start.strftime('%Y-%m'), observed_at=now.isoformat(),
                start=start.isoformat(), native=str(sum((Decimal(x['native']) for x in rewards), Decimal(0))),
                rewards=rewards, outgoing=outgoing, unconfirmed=unconfirmed,
                complete=True, pages=page + 1)


def apply_ledger(doc, ledger):
    if ledger['wallet'] != WALLET or not ledger['complete']:
        raise ValueError('Unverified wallet/month coverage')
    stamp = ledger['observed_at']; period = ledger['period'] + ' MTD · Asia/Vladivostok'
    latest = max((x['time'] for x in ledger['rewards']), default=None)
    latest = dt.datetime.fromtimestamp(latest, dt.timezone.utc).isoformat() if latest else None
    for item in doc['kpis']:
        if item['id'] == 'native_month':
            item.update(value=float(Decimal(ledger['native'])), category='native_receipts',
                        source='Flux explorer: confirmed coinbase outputs to wallet', period=period,
                        generated_at=stamp, last_success=stamp, source_latest_at=latest,
                        status='ok', error=None,
                        hint=f"{len(ledger['rewards'])} подтверждённых выплат; переводы и залоги исключены")
    for item in doc['kpis']:
        if item['id'] == 'pa_accrued_month' and ledger.get('pa_shares') == 10:
            item.update(value=float(Decimal(ledger['native'])), category='accrual',
                        source='Confirmed native rewards × 10 Fusion shares × 10%', period=period,
                        generated_at=stamp, last_success=stamp, source_latest_at=latest,
                        status='ok', error=None,
                        hint='Начислено по выплатам, не факт claim. 10 долей сверены с Fusion; независимой месячной выписки PA нет.')
    additions = [dict(id='native_reward_count_month', metric='native_reward_count_month',
                      label='Выплаты нод за месяц', value=len(ledger['rewards']), unit='шт'),
                 dict(id='outgoing_transactions_month', metric='outgoing_transactions_month',
                      label='Исходящие транзакции кошелька за месяц', value=len(ledger['outgoing']), unit='шт')]
    for item in additions:
        item.update(category='activity', period=period, source='Flux explorer wallet transactions',
                    generated_at=stamp, last_success=stamp, source_latest_at=latest, status='ok', error=None)
    ids = {x['id'] for x in additions}
    doc['kpis'] = [x for x in doc['kpis'] if x['id'] not in ids] + additions
    doc['limitations'] = [x for x in doc.get('limitations', []) if x.get('id') not in ('flux_november_history', 'flux_monthly_pa')]
    if ledger.get('pa_shares') == 10:
        doc['limitations'].append(dict(id='flux_monthly_pa', title='PA за месяц рассчитаны по выплатам',
                    impact='Начисления: 10 × 10% native. Факт получения и комиссии за месяц отдельно не подтверждены.',
                    action='Для независимой сверки подключить помесячную выписку Fusion.'))
    else:
        doc['limitations'].append(dict(id='flux_monthly_pa', title='Нет месячной сверки PA',
                    impact='Native подтверждены; месячные PA не заполнены без проверки долей Fusion.',
                    action='Проверить Fusion и месячную выписку PA.'))
    for limit in doc.get('limitations', []):
        if limit.get('id') == 'flux_costs_profit':
            limit.update(impact='Native-выплаты подтверждены. Блокчейн не содержит полного учёта аренды, электричества и рублёвой реализации; чистая прибыль неизвестна.',
                         action='Добавить подтверждённый учёт расходов; переводы и залоги не считать расходами автоматически.')
    table = dict(id='native_month_ledger', title='Подтверждённые выплаты нод · ' + ledger['period'],
                 columns=[dict(key='date', label='Дата UTC'), dict(key='native', label='FLUX', num=True), dict(key='txid', label='Транзакция')],
                 rows=[dict(date=dt.datetime.fromtimestamp(x['time'], dt.timezone.utc).isoformat(), native=x['native'], txid=x['txid']) for x in ledger['rewards']],
                 source='Flux explorer coinbase ledger', period=period, generated_at=stamp,
                 last_success=stamp, source_latest_at=latest, status='ok', error=None)
    doc['tables'] = [x for x in doc.get('tables', []) if x['id'] != table['id']] + [table]
    return doc


def collect(doc, previous):
    try:
        ledger = read_ledger(dt.datetime.now(dt.timezone.utc))
        try:
            request = urllib.request.Request('https://fusion.runonflux.io/coinbase/summary?address=' + WALLET,
                                             headers={'User-Agent': 'infodash-collector'})
            with urllib.request.urlopen(request, timeout=15) as response:
                summary = json.load(response)['data']
            chains = summary['chainStatistics']
            totals = [Decimal(str(x['claimedAmount'])) + Decimal(str(x['possibleToClaim'])) for x in chains]
            if len({x['chain'] for x in chains}) == 10 and len(set(totals)) == 1:
                ledger['pa_shares'] = 10
        except Exception:
            pass
        return apply_ledger(doc, ledger)
    except Exception as exc:
        # Keep the original observation date of cached evidence when a live read fails.
        for key in ('kpis', 'tables'):
            ids = {'native_month', 'native_reward_count_month', 'outgoing_transactions_month'} if key == 'kpis' else {'native_month_ledger'}
            cached = [dict(x, status='stale', error='Wallet ledger refresh failed: ' + type(exc).__name__)
                      for x in previous.get(key, []) if x.get('id') in ids and x.get('last_success')]
            if cached:
                doc[key] = [x for x in doc.get(key, []) if x.get('id') not in ids] + cached
        doc.setdefault('limitations', []).append(dict(id='flux_wallet_refresh', title='Не обновился реестр выплат',
                    impact='Последний подтверждённый срез не заменён нулём.', action='Проверить доступность explorer и полноту месячной выборки.'))
        return doc
