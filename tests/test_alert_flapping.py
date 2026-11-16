"""Антидребезг алертов: выдержка, гистерезис, пауза повторов и тихие часы.

Ночной шквал «CPU 98% / CPU OK» каждые две минуты — это дребезг: один всплеск
на 30-секундном цикле поднимал тревогу, а следующее измерение её снимало.
"""
import asyncio

import pytest


def make_server(name='Россия (вход)', cpu=10.0, status='up', **extra):
    row = {'name': name, 'status': status, 'cpu_percent': cpu, 'ping_ms': 10,
           'disk_free_gb': 50.0, 'disk_total_gb': 100.0, 'rx_mbps': 0.1, 'tx_mbps': 0.1,
           'error': None}
    row.update(extra)
    return row


@pytest.fixture
def alerts(main_module, monkeypatch):
    m = main_module
    sent = []
    monkeypatch.setattr(m, '_send_telegram', lambda token, chat, text: sent.append(text) or True)
    monkeypatch.setattr(m, '_trigger_counts', {})
    monkeypatch.setattr(m, '_notified_state', {})
    monkeypatch.setattr(m, '_alert_last_sent', {})
    monkeypatch.setattr(m, '_clear_streak', {})
    bot = m.cfg.bot
    monkeypatch.setattr(bot, 'enabled', True, raising=False)
    monkeypatch.setattr(bot, 'token', 't', raising=False)
    monkeypatch.setattr(bot, 'chat_id', 'c', raising=False)
    monkeypatch.setattr(bot, 'notify_delay', 3, raising=False)
    monkeypatch.setattr(bot, 'notify_hysteresis', 5.0, raising=False)
    monkeypatch.setattr(bot, 'notify_cooldown_min', 20, raising=False)
    monkeypatch.setattr(bot, 'quiet_from', '', raising=False)
    monkeypatch.setattr(bot, 'quiet_to', '', raising=False)
    return m, sent


def cycle(m, cpu, status='up'):
    asyncio.run(m._check_and_notify([make_server(cpu=cpu, status=status)]))


def test_single_spike_does_not_alert(alerts):
    m, sent = alerts
    cycle(m, 98.0)
    cycle(m, 15.0)
    assert sent == []


def test_sustained_load_alerts_once(alerts):
    m, sent = alerts
    for _ in range(3):
        cycle(m, 98.0)
    assert len(sent) == 1 and 'CPU' in sent[0]


def test_hysteresis_keeps_alarm_until_value_drops_below_margin(alerts):
    m, sent = alerts
    for _ in range(3):
        cycle(m, 98.0)
    sent.clear()
    # 88% ниже порога 90, но выше 85: тревога не снимается
    for _ in range(4):
        cycle(m, 88.0)
    assert sent == []
    # 80% — ниже порога с гистерезисом, но снять нужно тоже после выдержки
    cycle(m, 80.0)
    cycle(m, 80.0)
    assert sent == []
    cycle(m, 80.0)
    assert len(sent) == 1 and 'OK' in sent[0]


def test_repeat_alerts_are_paused_by_cooldown(alerts, monkeypatch):
    m, sent = alerts
    clock = [1000.0]
    monkeypatch.setattr(m.time, 'monotonic', lambda: clock[0])
    for _ in range(3):
        cycle(m, 98.0)
    assert len(sent) == 1
    # спад и новый всплеск через 2 минуты — сообщения быть не должно
    for _ in range(3):
        cycle(m, 10.0)
    clock[0] += 120
    for _ in range(3):
        cycle(m, 99.0)
    assert len(sent) == 2  # одно «OK» и ни одного нового «пожара»
    # после паузы повторы снова разрешены
    clock[0] += 21 * 60
    for _ in range(3):
        cycle(m, 99.0)
    assert len(sent) == 3


def test_quiet_hours_mute_metrics_but_not_down(alerts, monkeypatch):
    m, sent = alerts
    monkeypatch.setattr(m.cfg.bot, 'quiet_from', '00:00', raising=False)
    monkeypatch.setattr(m.cfg.bot, 'quiet_to', '23:59', raising=False)
    for _ in range(3):
        cycle(m, 99.0)
    assert sent == []
    for _ in range(3):
        cycle(m, None, status='down')
    assert len(sent) == 1 and 'DOWN' in sent[0]
