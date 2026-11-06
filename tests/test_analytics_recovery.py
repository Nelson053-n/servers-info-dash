import datetime as dt
import json
from app import projects


def test_financial_coverage_is_a_limit_not_an_outage(monkeypatch):
    import asyncio
    doc = {'error': 'Monthly native ledger/cost coverage unavailable; not zero',
           'kpis': [{'id': 'profit', 'value': None, 'status': 'unknown'}], 'alerts': []}
    monkeypatch.setattr(projects, 'fetch_analytics', lambda source: doc)
    monkeypatch.setattr(projects, 'probe_http', lambda url: {'http': 200, 'ms': 220})
    cfg = projects.ProjectsConfig(projects=[projects.ProjectConfig(id='flux', name='FluxRadar', check_url='https://example.test', analytics=projects.SummarySource(kind='file', path='unused'))])
    row = asyncio.run(projects.collect(cfg))['projects'][0]
    assert doc['error'] is None
    assert doc['limitations'][0]['id'] == 'monthly_finances'
    assert doc['kpis'][0]['value'] is None
    assert row['state'] == 'ok' and row['issues'] == []


def test_ops_coverage_is_deduplicated_and_real_errors_remain():
    doc = {'error': 'Некоммерческий HR сервис; денежный KPI неприменим, не0; Нет BobSSH/SQL/OPS capability; не проверено, не0/неbad',
           'alerts': [{'severity': 'warn', 'text': 'Не проверены: серверные бэкапы, CI runner, диск и контейнеры (прежний SSH-маршрут недоступен). OPS-метрики требуют отдельного доступа.'},
                      {'severity': 'bad', 'text': 'worker не работает'}]}
    projects._separate_coverage_limits(doc)
    projects._separate_coverage_limits(doc)
    assert len(doc['limitations']) == 1
    assert projects._state_of({'analytics': doc})[0] == 'bad'
    failed = {'error': 'источник ответил HTTP 503', 'stale': True, 'age_min': 60}
    projects._separate_coverage_limits(failed)
    assert failed['error'] == 'источник ответил HTTP 503'
    assert projects._state_of({'analytics': failed})[0] == 'warn'


def test_tunnel_probe_uses_http_time_not_ssh_handshake(tmp_path, monkeypatch):
    import asyncio
    from types import SimpleNamespace
    config = tmp_path / 'servers.yaml'
    config.write_text('ssh: {known_hosts: dummy}\nservers: [{name: probe, host: 127.0.0.1, user: monitor, client_key: dummy}]\n')
    class Connection:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        async def run(self, command, **kwargs):
            assert '%{time_total}' in command
            return SimpleNamespace(stdout='200 0.221', stderr='')
    monkeypatch.setattr(projects.asyncssh, 'connect', lambda *a, **k: Connection())
    ticks = iter([0.0, 4.8])
    monkeypatch.setattr(projects, 'time', SimpleNamespace(monotonic=lambda: next(ticks)))
    result = asyncio.run(projects.probe_via_server('https://example.test', 'probe', config))
    assert result['ms'] == 221
    assert result['probe_ms'] == 4800
    assert projects._http_probe_result(b'200 0.221', 4.8)['ms'] == 221


def test_failed_source_keeps_last_success_and_period(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / 'business.json'
    stamp = dt.datetime.now(dt.timezone.utc).isoformat()
    source.write_text(json.dumps({'generated_at': stamp, 'kpis': [{'id': 'cash_receipts', 'value': 123, 'unit': '₽', 'period': '2026-10', 'category': 'cash_receipts'}], 'tables': [{'id': 'ledger', 'rows': [{'amount': 123}]}]}))
    settings = projects.SummarySource(kind='file', path=str(source))
    first = projects.fetch_analytics(settings)
    source.unlink()
    failed = projects.fetch_analytics(settings)
    assert failed['error']
    assert failed['last_success'] == stamp
    assert failed['generated_at'] == stamp
    assert failed['kpis'][0]['value'] == 123
    assert failed['kpis'][0]['period'] == '2026-10'
    assert failed['kpis'][0]['status'] == 'stale'
    assert failed['tables'] == first['tables']


def test_unknown_is_null_and_summary_has_details(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    source = tmp_path / 'unknown.json'
    source.write_text(json.dumps({'generated_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'kpis': [{'id': 'expenses', 'value': 0, 'status': 'unknown'}, {'id': 'visitors', 'value': 0, 'status': 'ok'}]}))
    doc = projects.fetch_analytics(projects.SummarySource(kind='file', path=str(source)))
    metric = doc['kpis'][0]
    assert metric['value'] is None
    assert metric['last_success'] is None
    assert doc['kpis'][1]['value'] == 0
    assert doc['kpis'][1]['last_success'] is not None
    assert {'metric', 'unit', 'period', 'source', 'generated_at', 'last_success', 'error', 'status'} <= metric.keys()
    assert projects._card(doc)['has_details'] is True
