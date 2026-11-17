"""Меньше шума: «мигающий» сервер сообщает о себе один раз, застарелое замечание — реже."""
import asyncio
import datetime as dt

import pytest


def server(name='Россия (вход)', status='up', cpu=10.0):
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
    monkeypatch.setattr(m, '_flap_history', {})
    monkeypatch.setattr(m, '_mute_until', {})
    monkeypatch.setattr(m, 'NOTIFY_STATE_PATH', tmp_path / 'notify_state.json')
    monkeypatch.setattr(m, '_notify_state_dirty', False)
    bot = m.cfg.bot
    for attr, value in (('enabled', True), ('token', 't'), ('chat_id', 'c'), ('notify_down', True),
                        ('notify_delay', 1), ('notify_hysteresis', 5.0), ('notify_cooldown_min', 0),
                        ('notify_cpu_threshold', 90.0), ('quiet_from', ''), ('quiet_to', '')):
        monkeypatch.setattr(bot, attr, value, raising=False)
    return m, sent


def test_flapping_host_is_reported_once_and_then_muted(notify):
    m, sent = notify
    for status in ('up', 'down', 'up', 'down', 'up'):
        asyncio.run(m._check_and_notify([server(status=status)]))
    assert len(sent) == 4, sent
    assert 'мигает' in sent[-1]
    # В течение часа переходы того же сервера молчат
    sent.clear()
    for status in ('down', 'up'):
        asyncio.run(m._check_and_notify([server(status=status)]))
    assert sent == [], sent


def test_single_outage_still_announced_instantly(notify):
    m, sent = notify
    asyncio.run(m._check_and_notify([server(status='down')]))
    assert len(sent) == 1 and 'DOWN' in sent[0]


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
    snapshot = {'projects': [{'id': 'kuma', 'name': 'Uptime Kuma', 'state': 'bad',
                              'issues': [{'severity': 'bad', 'text': 'Kuma API: HTTP/JSON check failed'}]}]}
    monkeypatch.setattr(m.projects_tab, 'snapshot', lambda: snapshot)
    return m, sent


def _backdate(m, hours):
    for meta in m._PROJECT_ALERTS.values():
        if meta.get('state') == 'bad':
            meta['at'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)).isoformat()


def test_standing_issue_repeats_less_and_less(projects_alert):
    m, sent = projects_alert
    asyncio.run(m._project_alert_cycle())   # подтверждение
    asyncio.run(m._project_alert_cycle())   # первое сообщение
    assert len(sent) == 1
    asyncio.run(m._project_alert_cycle())   # сразу повторять нельзя
    assert len(sent) == 1
    # повтор тоже требует подтверждения двумя циклами — от одиночного сбоя не будит
    _backdate(m, 13)                        # прошло 13 часов — напоминание
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 1
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 2
    _backdate(m, 13)                        # второй интервал уже сутки — рано
    asyncio.run(m._project_alert_cycle())
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 2
    _backdate(m, 25)
    asyncio.run(m._project_alert_cycle())
    asyncio.run(m._project_alert_cycle())
    assert len(sent) == 3
