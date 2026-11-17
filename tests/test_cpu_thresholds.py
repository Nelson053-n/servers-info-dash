"""Индивидуальные пороги CPU: горячий вход не шумит, холодный — предупреждает как раньше."""
import asyncio

import pytest


def server(name, cpu):
    return {'name': name, 'status': 'up', 'cpu_percent': cpu, 'ping_ms': None,
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
                        ('notify_delay', 3), ('notify_hysteresis', 5.0), ('notify_cooldown_min', 0),
                        ('notify_cpu_threshold', 90.0), ('quiet_from', ''), ('quiet_to', ''),
                        ('notify_cpu_thresholds', {'Россия (вход 4)': 98.0}),
                        ('notify_cpu_delays', {'Россия (вход 4)': 10})):
        monkeypatch.setattr(bot, attr, value, raising=False)
    return m, sent


def test_hot_node_ignores_its_normal_90_percent_load(notify):
    m, sent = notify
    for _ in range(6):  # 3 минуты на 96% — для горячего узла это норма
        asyncio.run(m._check_and_notify([server('Россия (вход 4)', 96.0)]))
    assert sent == []


def test_hot_node_alerts_when_really_saturated(notify):
    m, sent = notify
    for _ in range(10):  # пять минут на 99%
        asyncio.run(m._check_and_notify([server('Россия (вход 4)', 99.0)]))
    assert len(sent) == 1 and '99.0%' in sent[0] and '98.0%' in sent[0]


def test_other_nodes_keep_the_global_threshold(notify):
    m, sent = notify
    for _ in range(3):  # холодный узел: 91% три замера подряд — тревога
        asyncio.run(m._check_and_notify([server('Россия (вход 3)', 91.0)]))
    assert len(sent) == 1 and 'Россия (вход 3)' in sent[0]
