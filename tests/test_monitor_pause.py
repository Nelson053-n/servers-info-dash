"""Сервер можно снять с наблюдения и вернуть одной кнопкой.

Выключенный сервер не опрашивается, не попадает в тревоги и не считается
упавшим — иначе недоступная нода, которую сейчас сознательно не смотрят,
постоянно шумит ошибками.
"""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def app_client(main_module, monkeypatch, tmp_path):
    m = main_module
    state_path = tmp_path / "monitor_state.json"
    monkeypatch.setattr(m, "MONITOR_STATE_PATH", state_path)
    monkeypatch.setattr(m, "MONITOR_PAUSED", {})
    monkeypatch.setattr(m, "_trigger_counts", {})
    m._auth.password_hash = "pbkdf2$dummy"
    sid = "t" * 32
    m._auth.sessions.clear()
    m._auth.session_created.clear()
    m._auth.sessions[sid] = "testclient"
    m._auth.session_created[sid] = m.dt.datetime.now(
        m.dt.timezone.utc,
    ).isoformat()

    async def _no_collector():
        return None

    monkeypatch.setattr(m, "_background_collector", _no_collector)

    server = m.ServerConfig(name="Казахстан", host="10.0.0.1", user="monitor")
    monkeypatch.setattr(
        m, "cfg", m.cfg.model_copy(update={"servers": [server]}),
    )
    monkeypatch.setattr(m.collector, "cfg", m.cfg)

    async def _fake_collect(srv):
        return {
            "name": srv.name, "host": srv.host, "status": "up",
            "cpu_percent": 1.0, "ping_ms": 10, "error": None,
        }

    monkeypatch.setattr(m.collector, "collect_server", _fake_collect)
    monkeypatch.setattr(m, "_attach_traffic_1d", lambda rows: None)
    monkeypatch.setattr(m, "_attach_traffic_30d", lambda rows: None)
    monkeypatch.setattr(
        m, "_cached_metrics",
        {"generated_at": "2026-01-01T00:00:00+00:00", "servers": []},
    )

    with TestClient(m.app) as client:
        client.cookies.set("sid", sid)
        yield client, m, state_path


def test_disable_writes_state_and_returns_paused_row(app_client):
    client, m, state_path = app_client
    r = client.put(
        "/api/servers/Казахстан/monitor",
        json={"enabled": False, "note": "нода недоступна"},
    )
    assert r.status_code == 200, r.text
    assert r.json()["monitoring"] is False
    assert "Казахстан" in r.json()["paused_servers"]

    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["paused"]["Казахстан"]["note"] == "нода недоступна"
    assert saved["paused"]["Казахстан"]["since"]


def test_enable_clears_state(app_client):
    client, m, state_path = app_client
    client.put("/api/servers/Казахстан/monitor", json={"enabled": False})
    assert "Казахстан" in m.MONITOR_PAUSED

    r = client.put("/api/servers/Казахстан/monitor", json={"enabled": True})
    assert r.status_code == 200, r.text
    assert r.json()["monitoring"] is True
    assert m.MONITOR_PAUSED == {}
    assert json.loads(state_path.read_text(encoding="utf-8"))["paused"] == {}


def test_unknown_server_is_rejected(app_client):
    client, _m, _p = app_client
    r = client.put("/api/servers/nope/monitor", json={"enabled": False})
    assert r.status_code == 404


def test_paused_server_is_not_probed(main_module, monkeypatch):
    m = main_module
    server = m.ServerConfig(name="Казахстан", host="10.0.0.1", user="monitor")
    monkeypatch.setattr(m, "MONITOR_PAUSED", {"Казахстан": {"since": "x", "note": None}})

    async def _boom(_server):
        raise AssertionError("paused server must not be pinged")

    monkeypatch.setattr(m.collector, "_get_ping", _boom)
    row = asyncio.run(m.collector.collect_server(server))
    assert row["status"] == "paused"
    assert row["monitoring"] is False
    assert row["error"] is None


def test_alerts_ignore_paused_servers(main_module, monkeypatch):
    m = main_module
    sent = []
    monkeypatch.setattr(m, "_send_telegram", lambda *a, **k: sent.append(a) or True)
    monkeypatch.setattr(
        m, "cfg",
        m.cfg.model_copy(update={
            "bot": m.cfg.bot.model_copy(update={
                "enabled": True, "token": "t", "chat_id": "1", "notify_down": True,
            }),
        }),
    )
    monkeypatch.setattr(m, "_trigger_counts", {})
    asyncio.run(m._check_and_notify([
        {"name": "Казахстан", "status": "paused"},
    ]))
    assert sent == []
    assert "Казахстан" not in m._trigger_counts
