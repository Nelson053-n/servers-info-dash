"""Показатели прежних sandbox-счетов trade4; только чтение, без ордеров."""
import datetime as dt
import json
import ssl
import urllib.request
from decimal import Decimal
from pathlib import Path


HOST = 'https://invest-public-api.tbank.ru/rest/'
NAMESPACE = 'tinkoff.public.invest.api.contract.v1.SandboxService/'
READ_METHODS = {'GetSandboxPositions', 'GetSandboxOrders', 'GetSandboxOperationsByCursor'}


def money(value):
    return Decimal(str(value.get('units', 0))) + Decimal(str(value.get('nano', 0))) / Decimal(10**9)


class Broker:
    def __init__(self, config):
        self.token = Path(config['token_file']).read_text().strip()
        if not self.token:
            raise ValueError('Пустой токен sandbox')
        self.context = ssl.create_default_context(cafile=config['ca_bundle'])

    def call(self, method, body):
        if method not in READ_METHODS:
            raise ValueError('Разрешены только методы чтения sandbox')
        request = urllib.request.Request(HOST + NAMESPACE + method,
            data=json.dumps(body).encode(), headers={
                'Authorization': 'Bearer ' + self.token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=self.context, timeout=15) as response:
            return json.load(response)


def operations(call, account, end):
    body = {'accountId': account, 'from': '2020-01-01T00:00:00Z', 'to': end,
            'state': 'OPERATION_STATE_EXECUTED', 'limit': 1000}
    rows, cursors = {}, set()
    while True:
        page = call('GetSandboxOperationsByCursor', body.copy())
        for row in page.get('items', []):
            if not row.get('id'):
                raise ValueError('Операция без id: полнота истории не подтверждена')
            rows[row['id']] = row
        if not page.get('hasNext'):
            return list(rows.values())
        cursor = page.get('nextCursor')
        if not cursor or cursor in cursors:
            raise ValueError('История операций неполна: курсор не продвигается')
        cursors.add(cursor)
        body['cursor'] = cursor


def engine_states(config):
    base = 'http://127.0.0.1:8004'
    opener = urllib.request.build_opener()
    with opener.open(base + '/health', timeout=12) as response:
        health = json.load(response)
    if not health.get('ok'):
        raise ValueError('trade4 не подтвердил работоспособность')
    if health.get('recovery_mode'):
        return health, {}
    values = {}
    for line in Path(config['auth_file']).read_text().splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('TRADE4_USER', 'TRADE4_PASS'):
            values[key] = value.strip().strip('"').strip("'")
    request = urllib.request.Request(base + '/login', data=json.dumps({
        'username': values['TRADE4_USER'], 'password': values['TRADE4_PASS']}).encode(),
        headers={'Content-Type': 'application/json'})
    with opener.open(request, timeout=12) as response:
        # Secure-cookie не отправляется CookieJar по localhost HTTP; передаём её явно.
        cookie = next(value.split(';', 1)[0] for value in response.headers.get_all('Set-Cookie', [])
                      if value.startswith('trade4_session='))
    states = {}
    for name in config['accounts']:
        request = urllib.request.Request(base + '/' + name + '/state', headers={'Cookie': cookie})
        with opener.open(request, timeout=15) as response:
            states[name] = json.load(response)
    return health, states


def account_summary(call, account, stamp):
    positions = call('GetSandboxPositions', {'accountId': account})
    if positions.get('limitsLoadingInProgress'):
        raise ValueError('Брокер ещё загружает остатки')
    rub = [x for x in positions.get('money', []) if x.get('currency') == 'rub']
    if len(rub) != 1:
        raise ValueError('Рублёвый остаток не подтверждён')
    balance = money(rub[0])
    orders = call('GetSandboxOrders', {'accountId': account}).get('orders', [])
    history = operations(call, account, stamp)
    transfers, fees = Decimal(0), Decimal(0)
    for row in history:
        kind = row.get('type', row.get('operationType'))
        payment = row.get('payment') or {}
        if kind not in ('OPERATION_TYPE_INPUT', 'OPERATION_TYPE_OUTPUT', 'OPERATION_TYPE_BROKER_FEE'):
            continue
        if payment.get('currency') != 'rub':
            raise ValueError('В истории есть нерублёвое пополнение или комиссия')
        if kind == 'OPERATION_TYPE_BROKER_FEE':
            fees -= money(payment)
        else:
            transfers += money(payment)
    # Без пополнений с открытия нельзя назвать разницу изменением денег за всю историю.
    if not any(x.get('type', x.get('operationType')) == 'OPERATION_TYPE_INPUT' for x in history):
        raise ValueError('Начало истории пополнений не подтверждено')
    held = []
    for key in ('securities', 'futures', 'options'):
        for position in positions.get(key, []):
            if Decimal(str(position.get('balance', 0))):
                held.append({'instrument': position.get('ticker') or position.get('figi'),
                             'lots': int(position['balance'])})
    return {'balance': balance, 'change': balance - transfers, 'fees': fees,
            'positions': held, 'orders': len(orders), 'operations': len(history),
            'period_from': min((x.get('date', stamp) for x in history), default=stamp)}


def build_document(config, call, health, states, metric, table, document, stamp):
    accounts = {name: account_summary(call, account, stamp) for name, account in config['accounts'].items()}
    recovery = bool(health.get('recovery_mode'))
    engine_unknown = not health.get('ok')
    live = None if engine_unknown else 0 if recovery else sum(bool(states.get(name, {}).get('live')) for name in accounts)
    if not recovery and not engine_unknown and any(states.get(name, {}).get('account_id') != account
                            or states.get(name, {}).get('mode') != 'tbank_sandbox'
                            for name, account in config['accounts'].items()):
        raise ValueError('Счёт или режим движка не совпадает с sandbox-источником Info')
    source = 'T-Bank SandboxService: GetSandboxPositions и полная история операций с открытия'
    period = min(x['period_from'] for x in accounts.values()) + ' — ' + stamp
    kpis = [metric('sandbox_cash', 'Деньги на sandbox-счетах', round(float(sum(x['balance'] for x in accounts.values())), 2), '₽', 'сейчас', source, category='sandbox_cash'),
            metric('sandbox_cash_change', 'Изменение денег · песочница', round(float(sum(x['change'] for x in accounts.values())), 2), '₽', period, source, category='sandbox_cash_change'),
            metric('sandbox_fees', 'Комиссии · песочница', round(float(sum(x['fees'] for x in accounts.values())), 2), '₽', period, source, category='sandbox_fees'),
            metric('running_robots', 'Работающие роботы', live, 'шт', 'сейчас', 'trade4 /health и /st8/state, /st9/state'),
            metric('sandbox_positions', 'Открытые позиции · песочница', sum(len(x['positions']) for x in accounts.values()), 'шт', 'сейчас', source)]
    alerts = []
    if engine_unknown:
        alerts.append({'severity': 'bad', 'text': 'Нет ответа от trade4: состояние роботов не подтверждено; остатки и позиции прочитаны у брокера.'})
    elif recovery:
        alerts.append({'severity': 'bad' if any(x['positions'] for x in accounts.values()) else 'warn',
                       'text': 'trade4 в режиме восстановления: роботы остановлены.' +
                               (' На sandbox-счёте есть открытая позиция без работающего движка.' if any(x['positions'] for x in accounts.values()) else '')})
    else:
        for name in accounts:
            if not states.get(name, {}).get('live'):
                alerts.append({'severity': 'warn', 'text': name + ': sandbox-движок остановлен'})
            if states[name].get('dd_halted'):
                alerts.append({'severity': 'warn', 'text': name + ': сработал стоп просадки'})
            elapsed = dt.datetime.fromisoformat(stamp).timestamp() * 1000 - (states[name].get('last_tick_ts') or 0)
            if states[name].get('live') and elapsed > (7200 if name == 'st8' else 180) * 1000:
                alerts.append({'severity': 'warn', 'text': name + ': нет свежего завершённого прохода движка'})
        st9_positions = {x['secid']: (-1 if x['position']['side'] == 'short' else 1) * x['position']['lots']
                         for x in states.get('st9', {}).get('instruments', []) if x.get('position')}
        broker_positions = {x['instrument']: x['lots'] for x in accounts.get('st9', {}).get('positions', [])}
        if st9_positions != broker_positions:
            alerts.append({'severity': 'bad', 'text': 'st9: позиции движка расходятся с sandbox-счётом'})
    rows = [{'strategy': name, 'mode': 'песочница', 'live': 'не подтверждено' if engine_unknown else 'нет' if recovery else 'да' if states.get(name, {}).get('live') else 'нет',
             'cash': round(float(value['balance']), 2), 'change': round(float(value['change']), 2),
             'fees': round(float(value['fees']), 2), 'positions': len(value['positions']),
             'orders': value['orders'], 'operations': value['operations']}
            for name, value in accounts.items()]
    held = [{'strategy': name, **position} for name, value in accounts.items() for position in value['positions']]
    tables = [table('sandbox_accounts', 'Проверенные sandbox-счета',
              [('strategy', 'Стратегия', False), ('mode', 'Режим', False), ('live', 'Работает', False),
               ('cash', 'Деньги ₽', True), ('change', 'Изменение денег ₽', True), ('fees', 'Комиссии ₽', True),
               ('positions', 'Позиций', True), ('orders', 'Заявок', True), ('operations', 'Операций с открытия', True)], rows),
              table('sandbox_positions', 'Позиции по данным брокера',
              [('strategy', 'Стратегия', False), ('instrument', 'Инструмент', False), ('lots', 'Количество со знаком', True)], held)]
    result = document(kpis, tables=tables, alerts=alerts)
    result['limitations'] = [{'id': 'sandbox_only', 'text': 'Все суммы относятся к виртуальным счетам. Изменение денег исключает пополнения и выводы; это не полная доходность портфеля и не выручка. Нереализованный результат отдельно не рассчитан.'}]
    return result


def read_trade(metric, table, document, config_file='/etc/trade4/info-sandbox.json'):
    config = json.loads(Path(config_file).read_text())
    broker = Broker(config)
    try:
        health, states = engine_states(config)
    except Exception:
        health, states = {'ok': False}, {}
    stamp = dt.datetime.now(dt.timezone.utc).isoformat()
    return build_document(config, broker.call, health, states, metric, table, document, stamp)
