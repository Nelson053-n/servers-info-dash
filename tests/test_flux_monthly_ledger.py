import copy
import datetime as dt
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('monthly', ROOT/'deploy/collectors/flux-monthly-ledger.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
NOW = dt.datetime(2026,11,5,tzinfo=dt.timezone.utc)

def tx(id, when, vin=None, confirmations=10):
    return dict(txid=id,time=when.timestamp(),confirmations=confirmations,
                vin=vin or [dict(coinbase='reward')],
                vout=[dict(value='3.15',scriptPubKey=dict(addresses=[m.WALLET])),
                      dict(value='1000',scriptPubKey=dict(addresses=['other']))])

def test_month_boundary_dedup_and_transfer_exclusion():
    reward=tx('a',NOW-dt.timedelta(hours=1))
    old=tx('old',dt.datetime(2026,10,31,13,tzinfo=dt.timezone.utc))
    rows=[reward,reward,tx('transfer',NOW,vin=[dict(addr='other')]),tx('pending',NOW,confirmations=0),old]
    ledger=m.read_ledger(NOW,lambda _:dict(txs=rows))
    assert ledger['native']=='3.15' and len(ledger['rewards'])==1
    assert ledger['outgoing']==[] and ledger['unconfirmed']==1
    assert ledger['period']=='2026-11'
    with pytest.raises(ValueError,match='boundary'):
        m.read_ledger(NOW,lambda _:dict(txs=[reward]))

def test_profit_unknown_and_recurring_replacement():
    ledger=m.read_ledger(NOW,lambda _:dict(txs=[tx('a',NOW),tx('old',NOW-dt.timedelta(days=10))]))
    doc=dict(kpis=[dict(id='native_month',value=None),dict(id='profit_month',value=None),dict(id='expenses_month',value=None)],tables=[],limitations=[dict(id='flux_november_history'),dict(id='flux_costs_profit')])
    result=m.apply_ledger(doc,ledger)
    assert {x['id']:x['value'] for x in result['kpis']}['native_month']==3.15
    assert all(x['value'] is None for x in result['kpis'] if x['id'] in ['profit_month','expenses_month'])
    assert result==m.apply_ledger(copy.deepcopy(result),ledger)
    assert not any(x['id']=='flux_november_history' for x in result['limitations'])

def test_failed_refresh_preserves_observation(monkeypatch):
    previous=dict(kpis=[dict(id='native_month',value=3.15,last_success='old')],tables=[])
    monkeypatch.setattr(m,'read_ledger',lambda _:(_ for _ in ()).throw(ValueError('incomplete')))
    doc=m.collect(dict(kpis=[],tables=[]),previous)
    assert doc['kpis'][0]['value']==3.15 and doc['kpis'][0]['last_success']=='old'
    assert doc['kpis'][0]['status']=='stale'
    producer=(ROOT/'deploy/collectors/info-business-collect.py').read_text()
    assert "doc=flux_monthly.collect(doc,previous('flux'))" in producer


def test_pa_accrual_uses_verified_shares_and_is_not_cash():
    ledger=m.read_ledger(NOW,lambda _:dict(txs=[tx('a',NOW),tx('old',NOW-dt.timedelta(days=10))]))
    ledger['pa_shares']=10
    doc=dict(kpis=[dict(id='native_month',value=None),dict(id='pa_accrued_month',value=None),dict(id='profit_month',value=None)],tables=[])
    result=m.apply_ledger(doc,ledger)
    pa=next(x for x in result['kpis'] if x['id']=='pa_accrued_month')
    assert pa['value']==3.15 and pa['category']=='accrual'
    assert 'не факт claim' in pa['hint']
    assert next(x for x in result['kpis'] if x['id']=='profit_month')['value'] is None
