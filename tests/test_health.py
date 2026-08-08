from pathlib import Path

SOURCE = Path("app/main.py").read_text(encoding="utf-8")
WORKFLOW = Path(".github/workflows/deploy.yml").read_text(encoding="utf-8")


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
    assert "/api/health" in WORKFLOW
    assert "curl -fsS http://127.0.0.1:8000/ >" not in WORKFLOW


def test_traffic_attach_runs_off_event_loop():
    """Traffic maps read every CSV — must not block the event loop."""
    body = SOURCE.split("async def _background_collector", 1)[1]
    body = body.split("@app.on_event", 1)[0]
    for fn in ("_attach_traffic_30d", "_attach_traffic_1d"):
        assert f"None, {fn}, data[\"servers\"]" in body, fn
        assert f"{fn}(data[\"servers\"])" not in body, fn
