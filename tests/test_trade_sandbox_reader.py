"""Проверка финансового источника trade4 без доступа к брокеру."""
import importlib.util
import io
import json
from email.message import Message
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1] / 'deploy/collectors'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reader = load('trade_reader_test', ROOT / 'trade_sandbox_reader.py')
sources = load('trade_sources_test', ROOT / 'info-business-sources.py')
STAMP = '2026-11-05T13:00:00+00:00'


def q(value):
    return {'currency': 'rub', 'units': str(value), 'nano': 0}


def fake_call(method, body):
    if method == 'GetSandboxPositions':
        return {'money': [q(990)], 'futures': [{'ticker': 'IMOEXF', 'balance': '-15'}]}
    if method == 'GetSandboxOrders':
        return {'orders': []}
    assert method == 'GetSandboxOperationsByCursor'
    return {'items': [
        {'id': 'input', 'type': 'OPERATION_TYPE_INPUT', 'payment': q(1000), 'date': '2026-07-09T00:00:00Z'},
        {'id': 'output', 'type': 'OPERATION_TYPE_OUTPUT', 'payment': q(-100), 'date': STAMP},
        {'id': 'fee', 'type': 'OPERATION_TYPE_BROKER_FEE', 'payment': q(-10), 'date': STAMP},
        {'id': 'sale', 'type': 'OPERATION_TYPE_SELL', 'payment': q(400000), 'date': STAMP}]}


def build(health, states):
    return reader.build_document({'accounts': {'st9': 'sandbox-id'}}, fake_call,
        health, states, sources.metric, sources.table, sources.document, STAMP)


def test_money_change_excludes_deposits_and_withdrawals_and_futures_notional():
    value = reader.account_summary(fake_call, 'sandbox-id', STAMP)
    assert value['balance'] == 990
    assert value['change'] == 90
    assert value['fees'] == 10
    assert value['positions'] == [{'instrument': 'IMOEXF', 'lots': -15}]


def test_recovery_reports_zero_robots_and_unmanaged_position_without_fake_profit():
    doc = build({'ok': True, 'recovery_mode': True}, {})
    kpis = {k['id']: k for k in doc['kpis']}
    assert kpis['running_robots']['value'] == 0
    assert kpis['sandbox_cash_change']['value'] == 90
    assert not {'revenue', 'profit', 'cash_receipts'} & kpis.keys()
    assert any(a['severity'] == 'bad' for a in doc['alerts'])
    assert 'sandbox-id' not in str(doc)


def test_live_position_must_match_broker_and_have_fresh_tick():
    state = {'mode': 'tbank_sandbox', 'account_id': 'sandbox-id', 'live': True,
             'last_tick_ts': 1793883600000, 'instruments': [
                 {'secid': 'IMOEXF', 'position': {'side': 'short', 'lots': 15}}]}
    doc = build({'ok': True}, {'st9': state})
    assert not doc['alerts']
    state['instruments'][0]['position']['lots'] = 14
    state['last_tick_ts'] = 0
    doc = build({'ok': True}, {'st9': state})
    assert any(a['severity'] == 'bad' for a in doc['alerts'])
    assert any('свежего' in a['text'] for a in doc['alerts'])


def test_real_or_wrong_account_is_rejected():
    with pytest.raises(ValueError, match='режим'):
        build({'ok': True}, {'st9': {'mode': 'tbank_real', 'account_id': 'sandbox-id'}})


def test_engine_failure_keeps_verified_broker_numbers_but_robot_count_unknown():
    doc = build({'ok': False}, {})
    kpis = {k['id']: k for k in doc['kpis']}
    assert kpis['running_robots']['value'] is None
    assert kpis['running_robots']['status'] == 'unknown'
    assert kpis['sandbox_cash']['value'] == 990
    assert doc['status'] == 'partial'
    assert doc['alerts'][0]['severity'] == 'bad'


def test_operations_reads_all_pages_and_deduplicates():
    calls = []
    def call(method, body):
        calls.append(body)
        if not body.get('cursor'):
            return {'items': [{'id': str(i)} for i in range(1000)], 'hasNext': True, 'nextCursor': 'next'}
        return {'items': [{'id': '999'}, {'id': '1000'}], 'hasNext': False}
    assert len(reader.operations(call, 'sandbox-id', STAMP)) == 1001
    assert len(calls) == 2 and calls[1]['cursor'] == 'next'


def test_repeated_cursor_and_missing_initial_deposit_are_not_success():
    def stuck(method, body):
        return {'items': [], 'hasNext': True, 'nextCursor': 'stuck'}
    with pytest.raises(ValueError, match='курсор'):
        reader.operations(stuck, 'sandbox-id', STAMP)
    def missing(method, body):
        result = fake_call(method, body)
        if method == 'GetSandboxOperationsByCursor':
            result['items'] = [x for x in result['items'] if x['id'] != 'input']
        return result
    with pytest.raises(ValueError, match='Начало истории'):
        reader.account_summary(missing, 'sandbox-id', STAMP)


def test_broker_rejects_order_method_before_network_access():
    broker = reader.Broker.__new__(reader.Broker)
    with pytest.raises(ValueError, match='только методы чтения'):
        broker.call('PostSandboxOrder', {})


def test_engine_reader_passes_secure_cookie_over_local_http(tmp_path, monkeypatch):
    auth = tmp_path / 'auth'
    auth.write_text('TRADE4_USER=test-user\nTRADE4_PASS=test-password\n')
    requests = []
    class Opener:
        def open(self, request, timeout):
            if isinstance(request, str):
                return io.StringIO('{"ok": true}')
            requests.append(request)
            if request.full_url.endswith('/login'):
                response = io.StringIO('{}')
                response.headers = Message()
                response.headers['Set-Cookie'] = 'trade4_session=signed; Secure; HttpOnly; Path=/'
                return response
            assert request.get_header('Cookie') == 'trade4_session=signed'
            return io.StringIO('{"live": true}')
    monkeypatch.setattr(reader.urllib.request, 'build_opener', lambda: Opener())
    health, states = reader.engine_states({'auth_file': str(auth), 'accounts': {'st8': 'a', 'st9': 'b'}})
    assert len(requests) == 3
    assert health['ok'] and states['st8']['live'] and states['st9']['live']
