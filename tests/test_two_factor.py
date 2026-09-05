"""Second factor over Telegram, and the hardening that shipped with it.

Real requests through the app: login → code → session, plus the
session cap, the Secure cookie flag, CSP on short-circuit responses,
and the global login budget.
"""
import pytest
from fastapi.testclient import TestClient

PASSWORD = "correct-horse-battery"


@pytest.fixture
def m(main_module, monkeypatch):
    state = main_module._AuthState(
        password_hash=main_module._hash_password(PASSWORD),
    )
    monkeypatch.setattr(main_module, "_auth", state)
    monkeypatch.setattr(main_module, "_save_auth", lambda state: None)
    monkeypatch.setattr(main_module, "_geo_lookup", lambda ip: "")
    monkeypatch.setattr(
        main_module, "_login_limiter", main_module._RateLimiter(1000, 60),
    )
    monkeypatch.setattr(
        main_module,
        "_login_global_limiter",
        main_module._RateLimiter(1000, 60),
    )
    monkeypatch.setattr(main_module, "_pending_2fa", {})

    async def _no_collector() -> None:
        return None

    monkeypatch.setattr(main_module, "_background_collector", _no_collector)
    return main_module


@pytest.fixture
def client(m):
    with TestClient(m.app) as c:
        yield c


@pytest.fixture
def telegram(m, monkeypatch):
    """Capture outgoing Telegram messages instead of calling the API."""
    sent: list[str] = []

    def fake_send(token, chat_id, text):
        sent.append(text)
        return True

    monkeypatch.setattr(m, "_send_telegram", fake_send)
    m.cfg.bot.token = "t"
    m.cfg.bot.chat_id = "c"
    m._auth.two_factor = True
    return sent


def _code_from(text: str) -> str:
    return text.split("<code>")[1].split("</code>")[0]


def test_password_alone_does_not_log_in_with_2fa(client, telegram):
    r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200
    assert r.json() == {"status": "2fa_required"}
    assert "sid" not in r.cookies, "session issued before the code"
    assert len(telegram) == 1 and _code_from(telegram[0]).isdigit()

    assert client.get("/api/metrics").status_code == 401


def test_right_code_logs_in_and_wrong_one_counts_as_a_failure(
    client, telegram,
):
    client.post("/api/auth/login", json={"password": PASSWORD})
    code = _code_from(telegram[0])

    r = client.post("/api/auth/verify", json={"code": "000000"})
    assert r.status_code == 403
    assert r.json()["remaining"] == 4

    r = client.post("/api/auth/verify", json={"code": code})
    assert r.status_code == 200, r.text
    assert client.get("/api/metrics").status_code != 401

    # A code is single use.
    client.cookies.clear()
    r = client.post("/api/auth/verify", json={"code": code})
    assert r.status_code == 401


def test_five_wrong_codes_block_the_address(client, telegram):
    client.post("/api/auth/login", json={"password": PASSWORD})
    for _ in range(4):
        assert client.post(
            "/api/auth/verify", json={"code": "111111"},
        ).status_code == 403
    r = client.post("/api/auth/verify", json={"code": "111111"})
    assert r.status_code == 429
    # …and the pending login is gone with it.
    code = _code_from(telegram[0])
    assert client.post(
        "/api/auth/verify", json={"code": code},
    ).status_code == 429


def test_login_fails_closed_when_telegram_is_down(client, m, monkeypatch):
    monkeypatch.setattr(m, "_send_telegram", lambda *a: False)
    m.cfg.bot.token = "t"
    m.cfg.bot.chat_id = "c"
    m._auth.two_factor = True
    r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 503
    assert not m._pending_2fa
    assert client.get("/api/metrics").status_code == 401


def test_2fa_is_ignored_until_the_bot_is_configured(client, m):
    m._auth.two_factor = True
    m.cfg.bot.token = ""
    r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_enabling_2fa_needs_password_and_a_reachable_bot(
    client, m, monkeypatch,
):
    m.cfg.bot.token = "t"
    m.cfg.bot.chat_id = "c"
    client.post("/api/auth/login", json={"password": PASSWORD})

    r = client.put("/api/auth/settings", json={"two_factor": True})
    assert r.status_code == 403, "toggled without the current password"

    monkeypatch.setattr(m, "_send_telegram", lambda *a: False)
    r = client.put(
        "/api/auth/settings",
        json={"two_factor": True, "current_password": PASSWORD},
    )
    assert r.status_code == 502
    assert m._auth.two_factor is False

    monkeypatch.setattr(m, "_send_telegram", lambda *a: True)
    r = client.put(
        "/api/auth/settings",
        json={"two_factor": True, "current_password": PASSWORD},
    )
    assert r.status_code == 200 and r.json()["two_factor"] is True
    assert client.get("/api/auth/settings").json()["two_factor"] is True


def test_sessions_are_capped_per_address(client, m):
    for _ in range(m._MAX_SESSIONS_PER_IP + 5):
        client.cookies.clear()
        assert client.post(
            "/api/auth/login", json={"password": PASSWORD},
        ).status_code == 200
    assert len(m._auth.sessions) == m._MAX_SESSIONS_PER_IP
    # The newest session is the one that survived.
    assert client.get("/api/metrics").status_code != 401


def test_expired_sessions_are_dropped_on_load(m, tmp_path):
    state = m._AuthState(
        password_hash="x",
        sessions={"old": "1.1.1.1", "legacy": "1.1.1.1", "new": "1.1.1.1"},
        session_created={
            "old": "2000-01-01T00:00:00+00:00",
            "new": m.dt.datetime.now(m.dt.timezone.utc).isoformat(),
        },
    )
    m._prune_sessions(state)
    assert set(state.sessions) == {"new"}
    assert set(state.session_created) == {"new"}


def test_cookie_is_secure_over_https(m):
    with TestClient(m.app, base_url="https://testserver") as c:
        r = c.post("/api/auth/login", json={"password": PASSWORD})
        assert r.status_code == 200
        assert "secure" in r.headers["set-cookie"].lower()


def test_security_headers_reach_short_circuit_responses(client):
    r = client.get("/api/metrics")
    assert r.status_code == 401
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    r = client.get("/")
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]


def test_global_login_budget(client, m, monkeypatch):
    monkeypatch.setattr(
        m, "_login_global_limiter", m._RateLimiter(3, 60),
    )
    for _ in range(3):
        client.post("/api/auth/login", json={"password": "nope"})
    r = client.post("/api/auth/login", json={"password": PASSWORD})
    assert r.status_code == 429


def test_index_has_no_inline_script():
    from pathlib import Path
    html = Path(__file__).resolve().parents[1] / "app/static/index.html"
    text = html.read_text(encoding="utf-8")
    assert "<script>" not in text
    assert 'src="/static/app.js' in text


# ---- API tokens ----

def _login(client):
    assert client.post(
        "/api/auth/login", json={"password": PASSWORD},
    ).status_code == 200


def test_token_gives_read_only_access_without_2fa(client, m, telegram):
    # Mint through the API as the admin (session first, code second).
    client.post("/api/auth/login", json={"password": PASSWORD})
    client.post("/api/auth/verify", json={"code": _code_from(telegram[0])})
    r = client.post(
        "/api/auth/tokens",
        json={"name": "neder32", "current_password": PASSWORD},
    )
    assert r.status_code == 201, r.text
    token = r.json()["token"]
    assert m._auth.api_tokens["neder32"]["hash"] != token, "stored in clear"

    client.cookies.clear()
    hdr = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/metrics", headers=hdr).status_code == 200
    assert client.get("/api/auth/settings", headers=hdr).status_code == 200
    r = client.put("/api/interval", json={"interval": 5}, headers=hdr)
    assert r.status_code == 403, "token allowed a write"
    assert client.get(
        "/api/metrics", headers={"Authorization": "Bearer nope"},
    ).status_code == 401


def test_token_needs_password_and_unique_name(client, m):
    _login(client)
    r = client.post(
        "/api/auth/tokens", json={"name": "a", "current_password": "bad"},
    )
    assert r.status_code == 403
    assert client.post(
        "/api/auth/tokens", json={"name": "a", "current_password": PASSWORD},
    ).status_code == 201
    assert client.post(
        "/api/auth/tokens", json={"name": "a", "current_password": PASSWORD},
    ).status_code == 409
    assert client.post(
        "/api/auth/tokens", json={"name": "a b", "current_password": PASSWORD},
    ).status_code == 400
    assert client.delete("/api/auth/tokens/a").status_code == 200
    assert client.delete("/api/auth/tokens/a").status_code == 404
    assert client.get("/api/auth/settings").json()["api_tokens"] == []


def test_tokens_are_not_reachable_without_a_session(client):
    assert client.post(
        "/api/auth/tokens", json={"name": "x", "current_password": PASSWORD},
    ).status_code == 401
