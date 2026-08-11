from pathlib import Path

SOURCE = Path("app/main.py").read_text(encoding="utf-8")
DEPLOY_SCRIPT = Path("deploy/dash-autodeploy.sh").read_text(encoding="utf-8")


def test_health_endpoint_exists_and_is_public():
    """Probes must reach /api/health without a session."""
    assert '@app.get("/api/health")' in SOURCE
    public = SOURCE.split("_PUBLIC_PATHS = {", 1)[1].split("}", 1)[0]
    assert '"/api/health"' in public


def test_health_reports_503_when_stale():
    """A dead collector must not answer 200."""
    body = SOURCE.split('@app.get("/api/health")', 1)[1]
    body = body.split("@app.get", 1)[0]
    assert "response.status_code = 503" in body
    assert "_HEALTH_MAX_AGE_CYCLES" in body


def test_deploy_healthcheck_probes_collector():
    """Deploy must verify the collector, not just served HTML."""
    assert "/api/health" in DEPLOY_SCRIPT
    assert "$HEALTH_URL" in DEPLOY_SCRIPT
    # A probe without a response timeout hangs forever on a wedged
    # event loop, which is the very thing it is meant to catch.
    assert "--max-time" in DEPLOY_SCRIPT


def test_deploy_rolls_back_on_failed_health():
    """A commit that never goes healthy must not stay deployed."""
    assert "rolling back" in DEPLOY_SCRIPT
    assert 'git reset --hard "$local_sha"' in DEPLOY_SCRIPT


def test_traffic_attach_runs_off_event_loop(main_module, monkeypatch):
    """Traffic maps read every CSV — must not block the event loop.

    Checked by running a cycle and recording which thread each traffic
    call lands on, so an equivalent refactor does not fail this while a
    real regression does.
    """
    import asyncio
    import threading

    main_thread = threading.get_ident()
    threads = {}

    def _record(name):
        def _fn(servers):
            threads[name] = threading.get_ident()
        return _fn

    async def _collect():
        return {"servers": [], "generated_at": "", "ready": True}

    monkeypatch.setattr(main_module.collector, "collect_all", _collect)
    monkeypatch.setattr(
        main_module, "_attach_traffic_30d", _record("30d"),
    )
    monkeypatch.setattr(main_module, "_attach_traffic_1d", _record("1d"))
    monkeypatch.setattr(main_module, "_log_server_metrics", lambda s: None)

    asyncio.run(main_module._run_collector_cycle(0))

    assert set(threads) == {"30d", "1d"}, f"not called: {threads}"
    for name, tid in threads.items():
        assert tid != main_thread, f"{name} ran on the event loop thread"
