"""Состояние алертов переживает перезапуск, а замечания проектов — не шумят.

Перезапуск контейнера (а их было четыре за вечер) сбрасывал «уже сообщили»,
и один и тот же RustDesk DOWN приходил заново. Проектные замечания давали пару
«проблема»/«снято» на одиночном сетевом сбое проверки.
"""
import asyncio
import json

import pytest


def make_server(name='RustDesk', status='down', cpu=None):
    return {'name': name, 'status': status, 'cpu_percent': cpu, 'ping_ms': None,
            'disk_free_gb': None, 'disk_total_gb': None, 'rx_mbps': None, 'tx_mbps': None}


@pytest.fixture
def notify(main_module, monkeypatch, tmp_path):
    m = main_module
    sent = []
    monkeypatch.setattr(m, '_send_telegram', lambda token, chat, text: sent.append(text) or True)
    monkeypatch.setattr(m, '_trigger_counts', {})
    monkeypatch.setattr(m, '_notified_state', {})
    monkeypatch.setattr(m, '_clear_streak', {})
    monkeypatch.setattr(m, '_alert_last_sent', {})
    monkeypatch.setattr(m, 'NOTIFY_STATE_PATH', tmp_path / 'notify_state.json')
    monkeypatch.setattr(m, '_notify_state_dirty', False)
    bot = m.cfg.bot
    for attr, value in (('enabled', True), ('token', 't'), ('chat_id', 'c'), ('notify_down', True),
                        ('notify_delay', 1), ('notify_hysteresis', 5.0), ('notify_cooldown_min', 20),
                        ('notify_cpu_threshold', 90.0), ('quiet_from', ''), ('quiet_to', '')):
        monkeypatch.setattr(bot, attr, value, raising=False)
    return m, sent, tmp_path / 'notify_state.json'


def test_down_alert_is_not_repeated_after_restart(notify, monkeypatch):
    m, sent, state_path = notify
    asyncio.run(m._check_and_notify([make_server()]))
    asyncio.run(m._check_and_notify([make_server()]))
    assert len(sent) == 1, sent
    assert state_path.exists() and oct(state_path.stat().st_mode)[-3:] == '600'
    # «перезапуск»: память пустая, состояние читаем с диска
    monkeypatch.setattr(m, '_notified_state', {})
    monkeypatch.setattr(m, '_alert_last_sent', {})
    m._load_notify_state()
    asyncio.run(m._check_and_notify([make_server()]))
    assert len(sent) == 1, f'после перезапуска пришёл повтор: {sent}'


def test_loaded_state_suppresses_cooldown_repeat(notify, monkeypatch):
    m, sent, _ = notify
    monkeypatch.setattr(m.cfg.bot, 'notify_delay', 1)
    asyncio.run(m._check_and_notify([make_server(status='up', cpu=99.0)]))
    assert len(sent) == 1
    monkeypatch.setattr(m, '_notified_state', {})
    monkeypatch.setattr(m, '_alert_last_sent', {})
    m._load_notify_state()
    asyncio.run(m._check_and_notify([make_server(status='up', cpu=10.0)]))  # спад
    asyncio.run(m._check_and_notify([make_server(status='up', cpu=99.0)]))  # новый всплеск в паузе
    assert len(sent) == 2, sent  # тревога + спад, без второй тревоги


@pytest.fixture
def projects_alert(main_module, monkeypatch, tmp_path):
    m = main_module
    monkeypatch.setattr(m, 'PROJECT_ALERT_PATH', tmp_path / 'project_alert_state.json')
    monkeypatch.setattr(m, '_PROJECT_ALERTS', {})
    monkeypatch.setattr(m, '_PROJECT_PENDING', {})
    monkeypatch.setattr(m.cfg.bot, 'token', 't', raising=False)
    monkeypatch.setattr(m.cfg.bot, 'chat_id', 'c', raising=False)
    sent = []
    monkeypatch.setattr(m, '_send_telegram', lambda token, chat, text: sent.append(text) or True)
    snapshot = {'projects': []}
    monkeypatch.setattr(m.projects_tab, 'snapshot', lambda: snapshot)
    return m, sent, snapshot


def _issue(snapshot, text='Kuma API: HTTP/JSON check failed', present=True):
    project = {'id': 'kuma', 'name': 'Uptime Kuma', 'state': 'bad' if present else 'ok',
               'issues': [{'severity': 'bad', 'text': text}] if present else []}
    snapshot['projects'] = [project]


def test_single_blip_does_not_alert(projects_alert):
    m, sent, snapshot = projects_alert
    _issue(snapshot, present=True)
    asyncio.run(m._project_alert_cycle())   # первый цикл: копим подтверждение
    _issue(snapshot, present=False)
    asyncio.run(m._project_alert_cycle())   # сбой прошёл
    assert sent == []


def test_confirmed_issue_alerts_on_second_cycle(projects_alert):
    m, sent, snapshot = projects_alert
    _issue(snapshot, present=True)
    asyncio.run(m._project_alert_cycle())
    assert sent == []
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 1 and 'Kuma' in sent[0]
    # третьего повтора нет
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 1
