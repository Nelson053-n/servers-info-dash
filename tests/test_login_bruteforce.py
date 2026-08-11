"""Login must resist brute force, not just count failures per exact IP."""
import pytest
from fastapi.testclient import TestClient


PASSWORD = "correct-horse-battery"


@pytest.fixture
def client(main_module, monkeypatch):
    monkeypatch.setattr(
        main_module,
        "_auth",
        main_module._AuthState(
            password_hash=main_module._hash_password(PASSWORD),
        ),
    )
    monkeypatch.setattr(main_module, "_setup_token", None)
    # Keep the brute-force state out of the repo's config dir.
    monkeypatch.setattr(main_module, "_save_auth", lambda state: None)
    monkeypatch.setattr(
        main_module, "_login_limiter", main_module._RateLimiter(
            max_requests=main_module._LOGIN_MAX_PER_WINDOW,
            window_sec=main_module._LOGIN_WINDOW_SEC,
        ),
    )

    async def _no_collector() -> None:
        return None

    monkeypatch.setattr(main_module, "_background_collector", _no_collector)
    with TestClient(main_module.app) as c:
        yield c


@pytest.fixture
def limiter_only(main_module, monkeypatch):
    """Disable the failure counter so only the limiter can answer 429.

    Without this the pre-existing 5-attempt block satisfies these
    assertions and they pass even with the limiter removed entirely.
    """
    monkeypatch.setattr(main_module, "_MAX_LOGIN_ATTEMPTS", 10_000)
    monkeypatch.setattr(main_module, "_record_login_failure", lambda ip: 9_999)


def test_login_is_rate_limited(client, main_module, limiter_only):
    """Sustained guessing must hit the limiter, not just the counter."""
    budget = main_module._LOGIN_MAX_PER_WINDOW
    codes = [
        client.post("/api/auth/login", json={"password": "wrong"}).status_code
        for _ in range(budget + 5)
    ]

    assert 429 in codes, "no rate limit on /api/auth/login"
    # The limiter alone must draw the line, at its own budget.
    assert codes.index(429) == budget, (
        f"429 first seen at {codes.index(429)}, expected {budget}"
    )
    assert codes[-1] == 429, f"limit not sustained: tail={codes[-3:]}"


def test_rate_limit_survives_correct_password(
    client, main_module, limiter_only,
):
    """A limited client must not slip through by guessing right at the end."""
    for _ in range(main_module._LOGIN_MAX_PER_WINDOW + 2):
        client.post("/api/auth/login", json={"password": "wrong"})

    r = client.post("/api/auth/login", json={"password": PASSWORD})

    assert r.status_code == 429, "limiter bypassed by a correct password"


def test_ipv6_limiter_key_covers_prefix(main_module):
    """A /64 is one host's worth of addresses; count it as one client."""
    key_a = main_module._limiter_key("2001:db8:1:2::1")
    key_b = main_module._limiter_key("2001:db8:1:2::dead:beef")
    key_other = main_module._limiter_key("2001:db8:1:3::1")

    assert key_a == key_b, "addresses in one /64 must share a limiter key"
    assert key_a != key_other, "different /64s must not collide"


def test_ipv4_limiter_key_is_the_address(main_module):
    assert main_module._limiter_key("192.168.1.5") == "192.168.1.5"


def test_limiter_key_handles_garbage(main_module):
    """An unparsable client address must not crash the limiter."""
    assert main_module._limiter_key("not-an-ip") == "not-an-ip"


def test_failure_state_is_bounded(main_module, monkeypatch):
    """fail_counts must not grow without limit — it is written to disk."""
    state = main_module._AuthState(password_hash="x")
    monkeypatch.setattr(main_module, "_auth", state)
    monkeypatch.setattr(main_module, "_save_auth", lambda s: None)

    for n in range(main_module._MAX_TRACKED_IPS * 3):
        main_module._record_login_failure(f"10.0.{n // 256}.{n % 256}")

    assert len(state.fail_counts) <= main_module._MAX_TRACKED_IPS, (
        f"fail_counts grew to {len(state.fail_counts)}"
    )
    assert len(state.blocked_until) <= main_module._MAX_TRACKED_IPS


def test_flooding_cannot_clear_an_active_block(main_module, monkeypatch):
    """Evicting old entries must not release an address under block."""
    import datetime as dt

    state = main_module._AuthState(password_hash="x")
    future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=30)
    state.blocked_until["10.9.9.9"] = future.isoformat()
    monkeypatch.setattr(main_module, "_auth", state)
    monkeypatch.setattr(main_module, "_save_auth", lambda s: None)

    # Attacker floods fresh addresses hoping to push their block out.
    for n in range(main_module._MAX_TRACKED_IPS * 2):
        main_module._record_login_failure(f"10.1.{n // 256}.{n % 256}")

    assert "10.9.9.9" in state.blocked_until, "active block was evicted"


def test_expired_blocks_are_dropped(main_module, monkeypatch):
    """Stale block entries must be evicted, not kept forever."""
    import datetime as dt

    state = main_module._AuthState(password_hash="x")
    past = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=2)
    state.blocked_until["10.0.0.1"] = past.isoformat()
    state.fail_counts["10.0.0.1"] = 3
    monkeypatch.setattr(main_module, "_auth", state)
    monkeypatch.setattr(main_module, "_save_auth", lambda s: None)

    main_module._prune_login_state()

    assert "10.0.0.1" not in state.blocked_until
    assert "10.0.0.1" not in state.fail_counts
