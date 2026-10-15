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
    state, issues = projects._state_of(_row(check={"http": None, "ms": 15000, "error": "timeout"}))
    assert state == "bad"
    assert {"severity": "bad", "text": "сайт не отвечает"} in issues


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


def test_project_alerts_set_the_state():
    doc = {"alerts": [{"severity": "bad", "text": "nb-bot: inactive"}, {"severity": "warn", "text": "диск 86 %"}]}
    state, issues = projects._state_of(_row(analytics=doc))
    assert state == "bad"
    assert issues == [{"severity": "bad", "text": "nb-bot: inactive"}, {"severity": "warn", "text": "диск 86 %"}]


def test_unreachable_analytics_is_a_warning():
    state, issues = projects._state_of(_row(analytics={"error": "источник ответил HTTP 404"}))
    assert (state, issues) == ("warn", [{"severity": "warn", "text": "источник ответил HTTP 404"}])


def test_file_analytics_marks_stale_by_generated_at(tmp_path):
    path = tmp_path / "nb.json"
    old = (projects._now() - projects.dt.timedelta(hours=1)).isoformat()
    path.write_text(json.dumps({"generated_at": old, "kpis": []}), encoding="utf-8")
    data = projects.fetch_analytics(projects.SummarySource(kind="file", path=str(path), max_age_min=30))
    assert data["stale"] is True
    assert data["age_min"] >= 59


def test_missing_analytics_file_is_an_error_not_a_crash(tmp_path):
    data = projects.fetch_analytics(projects.SummarySource(kind="file", path=str(tmp_path / "none.json")))
    assert "error" in data


def test_overview_carries_only_the_first_four_kpis():
    projects._cache.clear()
    doc = {"kpis": [{"id": str(i), "label": str(i), "value": i} for i in range(7)],
           "charts": [{"id": "a", "kind": "bar", "series": []}, {"id": "b", "kind": "line", "series": []}]}
    projects._cache.update({"projects": [{"id": "x", "analytics": doc}], "tls": [], "ready": True})
    card = projects.snapshot()["projects"][0]["analytics"]
    assert [k["id"] for k in card["kpis"]] == ["0", "1", "2", "3"]
    assert card["spark"]["id"] == "a"
    assert projects.detail("x")["analytics"] is doc
    assert projects.detail("nope") is None


def test_projects_endpoint_requires_login(main_module):
    from fastapi.testclient import TestClient

    main_module._auth.password_hash = main_module._hash_password("pw-for-tests")
    try:
        r = TestClient(main_module.app).get("/api/projects")
    finally:
        main_module._auth.password_hash = ""
    assert r.status_code == 401


def test_server_groups_are_passed_to_the_overview(tmp_path):
    import asyncio
    path = tmp_path / "projects.yaml"
    path.write_text("server_groups:\n  - title: РФ-входы\n    servers: [Россия вход 2]\n", encoding="utf-8")
    cfg = projects.load_projects_config(path)
    result = asyncio.run(projects.collect(cfg))
    assert result["server_groups"] == [{"title": "РФ-входы", "servers": ["Россия вход 2"]}]


def test_server_history_averages_by_hour_and_skips_old_rows(main_module, tmp_path, monkeypatch):
    import datetime as dt
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    now = dt.datetime.now(dt.timezone.utc)
    hour = now.replace(minute=0, second=0, microsecond=0)
    rows = [
        (hour, 10, 1.0), (hour + dt.timedelta(minutes=min(30, now.minute)), 30, 3.0),
        (hour - dt.timedelta(hours=30), 99, 9.0),  # за пределами окна
    ]
    by_day = {}
    for ts, cpu, rx in rows:
        by_day.setdefault(ts.date().isoformat(), []).append(
            f"{ts.strftime('%Y-%m-%d %H:%M')},Сервер,h,up,1,1,{cpu},1,2,1,2,{rx},0,eth0,")
    header = "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent,ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb,rx_mbps,tx_mbps,interface,error"
    for d, lines in by_day.items():
        (tmp_path / f"{main_module._safe_filename('Сервер')}_{d}.csv").write_text(header + "\n" + "\n".join(lines) + "\n", encoding="utf-8")
    h = main_module._server_history("Сервер", 24)
    assert h["series"]["cpu"] == [[hour.isoformat(), 20.0]]
    assert h["series"]["rx"] == [[hour.isoformat(), 2.0]]
    assert h["series"]["ram"] == [[hour.isoformat(), 50.0]]
