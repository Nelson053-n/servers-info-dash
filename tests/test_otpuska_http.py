import importlib.util
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    'otpuska_http', Path(__file__).resolve().parents[1] / 'deploy/collectors/otpuska-http.py'
)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def test_ops_uses_prometheus_text_instead_of_json(tmp_path):
    client = collector.Client(tmp_path / 'credentials', tmp_path / 'session')
    client.request = lambda path: b'otpusk_db_connections 12\n'
    assert client.get('/api/v1/ops/metrics', text=True) == 'otpusk_db_connections 12\n'


def test_ops_denial_names_required_access():
    doc = collector.build({'/api/v1/ops/metrics': 403}, True, None, None, None, None)
    assert any('ops.view (HTTP 403)' in alert['text'] for alert in doc['alerts'])
    assert 'ops_metrics' in doc['_source']['unverified']


def test_successful_ops_removes_access_warning_but_keeps_server_checks_unknown():
    doc = collector.build(
        {'/api/v1/ops/metrics': 200}, True, None, None, None, None,
        '# HELP otpusk_db_connections Connections\notpusk_db_connections 12\n'
        'otpusk_approval_overdue_tasks 3\n',
    )
    table = next(t for t in doc['tables'] if t['id'] == 'ops')
    assert [row['value'] for row in table['rows']] == [12, 3]
    assert not any('показатели приложения недоступны' in a['text'] for a in doc['alerts'])
    assert 'ops_metrics' not in doc['_source']['unverified']
    assert {'backups', 'disk', 'containers', 'ci_runner'} <= set(doc['_source']['unverified'])


def test_http_200_with_html_does_not_confirm_ops():
    doc = collector.build({'/api/v1/ops/metrics': 200}, True, None, None, None, None,
                          '<html>login</html>')
    assert 'ops_metrics' in doc['_source']['unverified']
    assert not any(t['id'] == 'ops' for t in doc['tables'])
