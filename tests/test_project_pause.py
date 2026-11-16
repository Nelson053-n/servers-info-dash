"""Пауза наблюдения для проектов и мониторов Kuma.

Снятый проект не опрашивается вовсе (ни сайт, ни TLS, ни сводка), снятый монитор
Kuma не попадает в «мониторы DOWN», а истёкшее время возврата включает наблюдение
само — без человека.
"""
import datetime as dt
import json
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def projects_module(main_module, monkeypatch, tmp_path):
    p = main_module.projects_tab
    state_path = tmp_path / "pause_state.json"
    monkeypatch.setattr(p, "PAUSE_STATE_PATH", state_path)
    monkeypatch.setattr(p, "PAUSED", {"projects": {}, "monitors": {}})
    monkeypatch.setattr(p, "_cache", {"generated_at": None, "projects": [], "tls": [], "ready": False})
    return p, state_path


def test_pause_project_writes_state_and_skips_probing(projects_module, monkeypatch):
    p, state_path = projects_module
    from app.projects import ProjectConfig, ProjectsConfig

    def _boom(*a, **k):
        raise AssertionError("снятый проект не должен опрашиваться")

    monkeypatch.setattr(p, "probe_http", _boom)
    monkeypatch.setattr(p, "tls_expiry", _boom)
    monkeypatch.setattr(p, "fetch_analytics", _boom)

    p.set_pause("projects", "soyuzremont", enabled=False, note="ждём сертификат")
    assert state_path.exists()
    assert oct(state_path.stat().st_mode)[-3:] == "600"
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["projects"]["soyuzremont"]["note"] == "ждём сертификат"

    cfg = ProjectsConfig(projects=[ProjectConfig(
        id="soyuzremont", name="АО «СОЮЗ-РЕМОНТ»", check_url="https://soyuzremont.ru",
        tls_host="soyuzremont.ru",
    )])
    import asyncio
    result = asyncio.run(p.collect(cfg))
    row = result["projects"][0]
    assert row["state"] == "paused"
    assert row["issues"] == []
    assert row["check"] is None and row["tls"] is None
    assert row["paused_note"] == "ждём сертификат"


def test_resume_clears_pause(projects_module):
    p, state_path = projects_module
    p.set_pause("projects", "soyuzremont", enabled=False, note="пауза")
    meta = p.set_pause("projects", "soyuzremont", enabled=True)
    assert meta is None
    assert p.PAUSED["projects"] == {}
    saved = json.loads(state_path.read_text(encoding="utf-8"))
    assert saved["projects"] == {}


def test_kuma_alerts_ignore_paused_monitors(projects_module):
    p, _ = projects_module
    p.set_pause("monitors", "Монитор #56", enabled=False, note="сертификат не продлён")
    data = {
        "tables": [{"id": "kuma_monitors", "rows": [
            {"monitor": "Монитор #56", "state": "DOWN"},
            {"monitor": "Монитор #57", "state": "DOWN"},
            {"monitor": "Монитор #58", "state": "UP"},
        ]}],
        "alerts": [],
    }
    p._kuma_alerts(data)
    texts = [a["text"] for a in data["alerts"]]
    assert any("Монитор #57" in t for t in texts)
    assert all("Монитор #56" not in t for t in texts)
    assert data["tables"][0]["rows"][0]["paused"] is True
    assert "paused" not in data["tables"][0]["rows"][1]


def test_resume_due_reenables_after_deadline(projects_module):
    p, _ = projects_module
    past = (p._now() - dt.timedelta(minutes=5)).isoformat(timespec="seconds")
    future = (p._now() + dt.timedelta(hours=2)).isoformat(timespec="seconds")
    p.set_pause("projects", "old", enabled=False, resume_at=past)
    p.set_pause("monitors", "Монитор #56", enabled=False, resume_at=future)
    resumed = p.resume_due()
    assert ("projects", "old") in resumed
    assert p.PAUSED["projects"] == {}
    assert "Монитор #56" in p.PAUSED["monitors"]


def test_api_pauses_project_and_refreshes_cache(main_module, projects_module, monkeypatch):
    m = main_module
    p, _ = projects_module
    m._auth.password_hash = "pbkdf2$dummy"
    sid = "p" * 32
    m._auth.sessions.clear()
    m._auth.session_created.clear()
    m._auth.sessions[sid] = "testclient"
    m._auth.session_created[sid] = m.dt.datetime.now(m.dt.timezone.utc).isoformat()
    p._cache = {"generated_at": "2026-01-01T00:00:00+00:00", "ready": True,
                "projects": [{"id": "soyuzremont", "name": "СОЮЗ-РЕМОНТ", "state": "bad",
                              "issues": [{"severity": "bad", "text": "сертификат истёк"}]}],
                "tls": []}
    cfg = p.ProjectsConfig(projects=[p.ProjectConfig(id="soyuzremont", name="СОЮЗ-РЕМОНТ")])
    monkeypatch.setattr(p, "load_projects_config", lambda path=None: cfg)

    with TestClient(m.app) as client:
        client.cookies.set("sid", sid)
        r = client.put("/api/projects/soyuzremont/monitor", json={"enabled": False, "note": "ждём"})
        assert r.status_code == 200, r.text
        assert r.json()["monitoring"] is False
        row = p._cache["projects"][0]
        assert row["state"] == "paused" and row["issues"] == []

        r = client.put("/api/projects/unknown/monitor", json={"enabled": False})
        assert r.status_code == 404

        key = quote("Монитор #57", safe="")
        r = client.put(f"/api/monitors/{key}/monitor", json={"enabled": False})
        assert r.status_code == 200
        assert "Монитор #57" in p.PAUSED["monitors"]
