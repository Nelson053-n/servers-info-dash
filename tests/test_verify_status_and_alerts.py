"""Статус проверки импорта на карточке и уведомления о замечаниях проектов."""
import datetime as dt
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope='module')
def status_module():
    return load('project_status_for_verify', ROOT / 'deploy/backups/project-status.py')


NOW = dt.datetime(2026, 11, 16, 12, tzinfo=dt.timezone.utc)


def document(module, imports, verification):
    ts = NOW.isoformat()
    sources = {}
    for source in ('ru3', 'lv3', 'vm300-code', 'bob'):
        row = dict(result='success', restore_result='passed', error_code=None,
                   last_backup_success_at=ts, last_restore_verified_at=ts,
                   protected_projects=list(module.SOURCES[source]))
        if source in imports:
            row.update(database_restore_result='passed', database_restore_verified_at=ts)
        sources[source] = row
    data = dict(schema_version=2, source_id='giga-projects', collector_status='ok',
                observed_at=ts, attempted_at=ts, schedule_enabled=True, sources=sources,
                check_result='passed', last_check_verified_at=ts)
    if verification is not None:
        data['database_verification'] = verification
    return module.analytics(module.validate(data, NOW), NOW)


def _kpi(doc):
    return next(k for k in doc['kpis'] if k['id'] == 'database_imports')


def test_running_verification_reads_as_in_progress(status_module):
    doc = document(status_module, {'ru3'}, {'status': 'running', 'started_at': NOW.isoformat(),
                                            'finished_at': None, 'failed_sources': []})
    kpi = _kpi(doc)
    assert kpi['value'] == 'проверка идёт'
    assert kpi['state'] == 'warn'
    assert all('импорт серверных БД' not in a['text'].lower() for a in doc['alerts'])


def test_failed_verification_raises_bad_alert(status_module):
    doc = document(status_module, {'ru3'}, {'status': 'failed', 'started_at': NOW.isoformat(),
                                            'finished_at': NOW.isoformat(), 'failed_sources': ['bob']})
    kpi = _kpi(doc)
    assert kpi['value'] == 'не подтверждён'
    assert kpi['state'] == 'bad'
    assert any('не подтвердился' in a['text'] and 'bob' in a['text'] for a in doc['alerts'])


def test_complete_set_still_shows_four_of_four(status_module):
    doc = document(status_module, {'ru3', 'lv3', 'vm300-code', 'bob'},
                   {'status': 'ok', 'started_at': NOW.isoformat(), 'finished_at': NOW.isoformat(),
                    'failed_sources': []})
    assert _kpi(doc)['value'] == '4/4'


def test_unknown_field_still_rejected(status_module):
    ts = NOW.isoformat()
    data = dict(schema_version=2, source_id='giga-projects', collector_status='ok',
                observed_at=ts, attempted_at=ts, schedule_enabled=True, sources={},
                check_result='passed', last_check_verified_at=ts, surprise=1)
    with pytest.raises(ValueError):
        status_module.validate(data, NOW)


# ---------------------------------------------------------------- уведомления
@pytest.fixture
def alerts(main_module, monkeypatch, tmp_path):
    m = main_module
    state = tmp_path / 'project_alert_state.json'
    monkeypatch.setattr(m, 'PROJECT_ALERT_PATH', state)
    monkeypatch.setattr(m, '_PROJECT_ALERTS', {})
    monkeypatch.setattr(m.cfg.bot, 'token', 'test-token', raising=False)
    monkeypatch.setattr(m.cfg.bot, 'chat_id', 'test-chat', raising=False)
    sent = []

    def fake_send(token, chat_id, text):
        sent.append(text)
        return True

    monkeypatch.setattr(m, '_send_telegram', fake_send)
    snapshot = {'projects': [{'id': 'backups', 'name': 'Резервные копии', 'state': 'bad',
                              'issues': [{'severity': 'bad', 'text': 'импорт не подтвердился'}]}]}
    monkeypatch.setattr(m.projects_tab, 'snapshot', lambda: snapshot)
    return m, state, sent, snapshot


def test_bad_issue_notifies_once_and_recovers(alerts):
    import asyncio
    m, state, sent, snapshot = alerts
    # замечание подтверждается вторым циклом: одиночный сбой не будит
    asyncio.run(m._project_alert_cycle())
    assert sent == []
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 1 and 'Резервные копии' in sent[0]
    assert state.exists() and oct(state.stat().st_mode)[-3:] == '600'
    # повторный цикл не дублирует сообщение
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 1
    # замечание снято -> сообщение о восстановлении
    snapshot['projects'][0].update(state='ok', issues=[])
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 2 and 'снято' in sent[1]


def test_paused_project_is_not_reported(alerts):
    import asyncio
    m, _, sent, snapshot = alerts
    snapshot['projects'][0]['state'] = 'paused'
    asyncio.run(m._project_alert_cycle())
    assert sent == []


def test_no_token_sends_nothing(alerts, monkeypatch):
    import asyncio
    m, _, sent, _ = alerts
    monkeypatch.setattr(m.cfg.bot, 'token', '', raising=False)
    asyncio.run(m._project_alert_cycle())
    assert sent == []
