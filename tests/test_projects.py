"""Вкладка «Проекты»: пороги статусов, чтение сводок и закрытый эндпоинт."""
import json
import os
import time

from app import projects


def _row(**kw):
    row = {"check": None, "tls": None, "summary": None}
    row.update(kw)
    return row


def test_site_down_is_bad():
    state, reasons = projects._state_of(_row(check={"http": None, "ms": 15000, "error": "timeout"}))
    assert state == "bad"
    assert "сайт не отвечает" in reasons


def test_healthy_site_is_ok():
    state, reasons = projects._state_of(_row(
        check={"http": 200, "ms": 300, "error": None},
        tls={"host": "x", "expires": "2027-01-01", "days_left": 80, "error": None},
    ))
    assert (state, reasons) == ("ok", [])


def test_certificate_thresholds():
    soon = projects._state_of(_row(tls={"host": "x", "expires": None, "days_left": 10, "error": None}))
    expiring = projects._state_of(_row(tls={"host": "x", "expires": None, "days_left": 3, "error": None}))
    broken = projects._state_of(_row(tls={"host": "x", "expires": None, "days_left": None, "error": "SSLError"}))
    assert soon[0] == "warn"
    assert expiring[0] == "bad"
    assert broken[0] == "bad"


def test_stopped_service_is_bad():
    state, reasons = projects._state_of(_row(summary={"services": {"nb-bot": "inactive", "nb-web": "active"}}))
    assert state == "bad"
    assert "nb-bot: inactive" in reasons


def test_dead_vpn_exit_is_reported():
    summary = {"rf": [{"label": "ru3", "error": None, "exits_total": 8, "exits_alive": 7}]}
    state, reasons = projects._state_of(_row(summary=summary))
    assert state == "warn"
    assert "ru3: живых выходов 7 из 8" in reasons


def test_file_summary_marks_stale(tmp_path):
    path = tmp_path / "nb.json"
    path.write_text(json.dumps({"services": {}}), encoding="utf-8")
    old = time.time() - 3600
    os.utime(path, (old, old))
    data = projects.fetch_summary(projects.SummarySource(kind="file", path=str(path), max_age_min=30))
    assert data["stale"] is True
    assert data["age_min"] >= 59


def test_missing_summary_file_is_an_error_not_a_crash(tmp_path):
    data = projects.fetch_summary(projects.SummarySource(kind="file", path=str(tmp_path / "none.json")))
    assert "error" in data


def test_projects_endpoint_requires_login(main_module):
    from fastapi.testclient import TestClient

    main_module._auth.password_hash = main_module._hash_password("pw-for-tests")
    try:
        r = TestClient(main_module.app).get("/api/projects")
    finally:
        main_module._auth.password_hash = ""
    assert r.status_code == 401
