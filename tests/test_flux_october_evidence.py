import ast
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'deploy/collectors/flux-october-evidence.py'
spec = importlib.util.spec_from_file_location('flux_october', SOURCE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def audit():
    return dict(period='2026-10', category='accrued_income_valuation',
                observed_at='2026-11-05T13:00:20.373168+00:00', source_latest_at='2026-11-02',
                display_rub=6241, valuation_rub='6241.46', native_flux='640.70',
                pa_flux_equivalent='640.70', total_flux_equivalent='1281.40',
                native_reward_count=196, rate_rub_per_flux='4.870813363148789')


def document(stamp='2026-11-05T13:05:00Z'):
    return dict(generated_at=stamp, error=module.MISSING, kpis=[
        dict(id=id, value=None, category=category, error=module.MISSING)
        for id, category in [('revenue_month', 'cash_receipts'),
                             ('revenue_prev_month', 'cash_receipts'),
                             ('expenses_month', 'expenses'), ('profit_month', 'profit')]], tables=[])


def test_accrued_valuation_is_separate_from_cash_costs_and_profit():
    doc = module.apply_october(document(), audit())
    rows = {x['id']: x for x in doc['kpis']}
    value = rows['october_accrued_valuation_rub']
    assert value['value'] == 6241 and value['exact_value'] == '6241.46'
    assert value['category'] == 'accrued_income_valuation'
    assert '2026-10' in value['period'] and value['status'] == 'historical'
    assert rows['october_native_flux']['value'] == 640.70
    assert rows['october_pa_accrued']['value'] == 640.70
    assert 'независимой месячной выписки PA нет' in value['hint']
    for id in ['revenue_month', 'revenue_prev_month', 'expenses_month', 'profit_month']:
        assert rows[id]['value'] is None


def test_second_collection_preserves_closed_period_and_audit_timestamps():
    first = module.apply_october(document(), audit())
    second = module.apply_october(document('2026-11-05T13:15:00Z'), audit())
    assert first['kpis'][:3] == second['kpis'][:3]
    assert first['tables'] == second['tables']
    assert first['generated_at'] != second['generated_at']


def test_limits_split_and_operational_errors_remain_visible():
    raw = document()
    raw['error'] = 'API unavailable; ' + module.MISSING
    doc = module.apply_october(raw, audit())
    assert doc['error'] == 'API unavailable'
    limits = {x['id']: x for x in doc['limitations']}
    assert set(limits) == {'flux_october_pa', 'flux_november_history', 'flux_costs_profit'}
    assert 'ноября' in limits['flux_november_history']['title']
    assert 'Расходы и прибыль неизвестны' == limits['flux_costs_profit']['title']
    assert '196' in limits['flux_october_pa']['impact']
    assert module.MISSING not in json.dumps(doc)


def test_reapplication_does_not_duplicate_metrics_or_tables():
    first = module.apply_october(document(), audit())
    second = module.apply_october(copy.deepcopy(first), audit())
    assert second == first


def test_actual_producer_flux_branch_publishes_evidence(tmp_path):
    directory = tmp_path / 'audit-aggregates'
    directory.mkdir()
    (directory / 'flux-october-safe.json').write_text(json.dumps(audit()))
    source = ROOT / 'deploy/collectors/info-business-collect.py'
    tree = ast.parse(source.read_text())
    branch = next(n for n in tree.body if isinstance(n, ast.Try)
                  and 'build_flux' in ast.unparse(n))
    env = dict(BASE=tmp_path, json=json, flux_october=module,
               acquire=SimpleNamespace(read_flux_sources=lambda: {'ops': {}}),
               flux=SimpleNamespace(build_flux=lambda *args: document()),
               previous=lambda name: {}, failed=lambda *args: document())
    exec(compile(ast.Module(body=[branch], type_ignores=[]), str(source), 'exec'), env)
    assert env['doc']['kpis'][0]['id'] == 'october_accrued_valuation_rub'
    assert env['doc']['kpis'][0]['value'] == 6241
