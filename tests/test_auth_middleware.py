"""End-to-end checks that the middleware actually closes the door.

These drive real requests through the app rather than asserting on the
source, so a regression in auth_middleware fails the suite.
"""
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(main_module, monkeypatch):
    monkeypatch.setattr(
        main_module, "_auth", main_module._AuthState(password_hash=""),
    )
    monkeypatch.setattr(main_module, "_setup_token", "test-setup-token")
    # Setting a password writes auth.yaml; keep tests off the real one.
    monkeypatch.setattr(main_module, "_save_auth", lambda state: None)

    # Startup launches the collector, which would SSH to the example
    # hosts. These tests only exercise routing.
    async def _no_collector() -> None:
        return None

    monkeypatch.setattr(main_module, "_background_collector", _no_collector)
    with TestClient(main_module.app) as c:
        yield c


def test_unconfigured_dashboard_blocks_server_creation(client):
    """The C1 file-deletion path must not be reachable without a password."""
    r = client.post(
        "/api/servers",
        json={"name": "x", "host": "127.0.0.1", "user": "monitor"},
    )

    assert r.status_code == 403, r.text
    assert r.json().get("needs_setup") is True


def test_unconfigured_dashboard_blocks_metrics(client):
    """Metrics leak server IPs; they are not first-run material."""
    r = client.get("/api/metrics")

    assert r.status_code == 403, r.text


def test_unconfigured_dashboard_blocks_server_deletion(client):
    r = client.delete("/api/servers/anything")

    assert r.status_code == 403, r.text


def test_health_stays_reachable_for_probes(client):
    """Deploy probes must work before setup, or rollout can't verify."""
    r = client.get("/api/health")

    assert r.status_code in (200, 503), r.text


def test_first_password_requires_setup_token(client):
    r = client.put(
        "/api/auth/settings",
        json={"password": "correct-horse", "allowed_networks": []},
    )

    assert r.status_code == 403, r.text
    assert "setup token" in r.json()["detail"].lower()


def test_first_password_accepted_with_setup_token(client, main_module):
    r = client.put(
        "/api/auth/settings",
        json={
            "password": "correct-horse",
            "allowed_networks": [],
            "setup_token": "test-setup-token",
        },
    )

    assert r.status_code == 200, r.text
    assert main_module._auth.password_hash
    assert main_module._setup_token is None, "token must be retired"


def test_wrong_setup_token_is_rejected(client):
    r = client.put(
        "/api/auth/settings",
        json={
            "password": "correct-horse",
            "allowed_networks": [],
            "setup_token": "wrong",
        },
    )

    assert r.status_code == 403, r.text
