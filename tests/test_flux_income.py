"""Run the collector's actual calculation helpers without SSH or HTTP."""
import ast
import datetime as dt
import json
import os
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/collectors/flux-analytics.sh'


@pytest.fixture
def collector():
    body = SOURCE.read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
    tree = ast.parse(body)
    names = {'pa_accrual', 'pa_totals', 'monthly_income', 'load_rewards', 'amount_range'}
    functions = ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[])
    scope = {'dt': dt, 'VL': dt.timezone(dt.timedelta(hours=10)), 'os': os, 'json': json, 'EXPLORER': 'test:'}
    exec(compile(functions, str(SOURCE), 'exec'), scope)
    return scope


def stamp(date):
    return dt.datetime.fromisoformat(date).replace(tzinfo=dt.timezone.utc).timestamp()


def test_ergo_shutdown_date_is_an_interval_not_an_invented_hour(collector):
    pa = collector['pa_accrual']
    assert pa(100, stamp('2026-09-20T23:59:59')) == (100, 100)
    assert pa(100, stamp('2026-09-21T00:00:00')) == (90, 100)
    assert pa(100, stamp('2026-09-21T23:59:59')) == (90, 100)
    assert pa(100, stamp('2026-09-22T00:00:00')) == (90, 90)


def test_native_reward_reduction_never_reprices_historical_coins(collector):
    rewards = {'old': [stamp('2026-10-26T15:00:00'), 3.5], 'new': [stamp('2026-10-27T00:00:00'), 3.15]}
    points = [{'t': t, 'usd': .06} for t, _ in rewards.values()]
    row = collector['monthly_income'](rewards, points, {dt.date(2026, 10, 1): 80})['2026-10']
    assert row['native'] == pytest.approx(6.65)
    assert row['pa_min'] == pytest.approx(5.985)
    assert row['pa_max'] == pytest.approx(5.985)
    assert row['total_min'] == pytest.approx(12.635)
    assert row['usd_min'] == pytest.approx(12.635 * .06)
    assert row['rub_min'] == pytest.approx(12.635 * .06 * 80)


def test_missing_prices_preserve_native_and_hide_incomplete_money(collector):
    rewards = {'a': [stamp('2026-10-20T00:00:00'), 10], 'b': [stamp('2026-10-21T00:00:00'), 10]}
    points = [{'t': rewards['a'][0], 'usd': .06}]
    rows = collector['monthly_income'](rewards, points, {dt.date(2026, 10, 1): 80})
    row = rows['2026-10']
    assert row['native'] == 20
    assert row['pa_min'] == 18
    assert row['rub_min'] is None and row['usd_min'] is None
    assert '2026-09' not in rows  # No rewards, no fabricated forecast/PA.
    assert collector['monthly_income']({}, points, {}) == {}


def test_missing_ruble_rate_does_not_hide_known_usd(collector):
    t = stamp('2026-10-20T00:00:00')
    row = collector['monthly_income']({'a': [t, 10]}, [{'t': t, 'usd': .06}], {})['2026-10']
    assert row['usd_min'] == pytest.approx(1.14)
    assert row['rub_min'] is None


def test_month_is_vladivostok_but_price_date_is_utc(collector):
    t = stamp('2026-08-31T15:00:00')
    row = collector['monthly_income']({'a': [t, 10]}, [{'t': stamp('2026-08-31T00:00:00'), 'usd': .05}], {dt.date(2026, 8, 28): 80})['2026-09']
    assert row['native'] == 10
    assert row['total_min'] == 20
    assert row['rub_min'] == 80


def test_unknown_shutdown_hour_propagates_to_monthly_total(collector):
    t = stamp('2026-09-21T12:00:00')
    row = collector['monthly_income']({'a': [t, 10]}, [{'t': t, 'usd': .05}], {dt.date(2026, 9, 21): 80})['2026-09']
    assert row['total_min'] == 19 and row['total_max'] == 20
    assert collector['amount_range'](row['total_min'], row['total_max']) == '19.00–20.00'


def test_pa_claimed_received_and_missing_data_are_separate(collector):
    totals = collector['pa_totals']
    assert totals(None) is None
    assert totals({'pa_chains': [], 'totals': {'is_estimate': False}}) is None
    assert totals({'pa_chains': [{'claimable': 1}], 'totals': {'is_estimate': True}}) is None
    wallet = {'totals': {'is_estimate': False}, 'pa_chains': [{'claimed': 100, 'received': 96, 'fees': 4, 'claimable': 10}]}
    assert totals(wallet) == {'claimed': 100, 'received': 96, 'fees': 4, 'claimable': 10}
    del wallet['pa_chains'][0]['received']
    assert totals(wallet)['received'] is None


def test_loader_deduplicates_and_excludes_change_transfers_unconfirmed(collector, monkeypatch, tmp_path):
    monkeypatch.setenv('WALLET', 'test-wallet')
    monkeypatch.setenv('STATE', str(tmp_path / 'rewards.json'))
    output = {'value': '3.15', 'scriptPubKey': {'addresses': ['test-wallet']}}
    tx = {'txid': 'reward', 'time': stamp('2026-10-30T00:00:00'), 'confirmations': 100,
          'vin': [{'coinbase': 'coinbase'}], 'vout': [output, {'value': '1000', 'scriptPubKey': {'addresses': ['other']}}]}
    transfer = {**tx, 'txid': 'change', 'vin': [{'addr': 'test-wallet'}]}
    unconfirmed = {**tx, 'txid': 'unconfirmed', 'confirmations': 0}
    collector['fetch'] = lambda _: json.dumps({'txs': [tx, tx, transfer, unconfirmed]}).encode()
    rows, backfill = collector['load_rewards'](stamp('2026-10-31T00:00:00'))
    assert rows == {'reward': [tx['time'], 3.15]}
    assert backfill is False
