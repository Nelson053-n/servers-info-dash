"""Defects found auditing the fixes in f9ef6f7, 71524c9, b45c9d1.

Each test here reproduces a specific hole in an earlier fix, so a
regression re-opens a named door rather than failing something vague.
"""
import datetime as dt

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(main_module, monkeypatch):
    monkeypatch.setattr(
        main_module, "_auth", main_module._AuthState(password_hash=""),
    )
    monkeypatch.setattr(main_module, "_setup_token", "test-setup-token")
    monkeypatch.setattr(main_module, "_save_auth", lambda state: None)

    async def _no_collector() -> None:
        return None

    monkeypatch.setattr(main_module, "_background_collector", _no_collector)
    with TestClient(main_module.app) as c:
        yield c


# ---- setup gate ----

def test_whitelist_cannot_be_set_without_the_setup_token(client, main_module):
    """A payload with no password must not slip past the token check.

    Pinning allowed_networks to the attacker's address before setup would
    lock the real operator out for good.
    """
    r = client.put(
        "/api/auth/settings",
        json={"allowed_networks": ["203.0.113.9/32"]},
    )

    assert r.status_code == 403, r.text
    assert main_module._auth.allowed_networks != ["203.0.113.9/32"]


def test_existing_whitelist_cannot_be_wiped_before_setup(client, main_module):
    main_module._auth.allowed_networks = ["192.168.10.0/24"]

    r = client.put("/api/auth/settings", json={"allowed_networks": []})

    assert r.status_code == 403, r.text
    assert main_module._auth.allowed_networks == ["192.168.10.0/24"]


def test_login_history_is_not_readable_before_setup(client, main_module):
    """Pre-setup GET leaked admin IPs, countries and user agents."""
    main_module._auth.history = [
        {
            "time": "2026-08-01 10:00",
            "ip": "192.168.10.50",
            "country": "ru",
            "ua": "Mozilla",
        },
    ]
    main_module._auth.allowed_networks = ["192.168.10.0/24"]

    r = client.get("/api/auth/settings")

    body = r.text
    assert "192.168.10.50" not in body, "login history leaked before setup"
    assert "192.168.10.0/24" not in body, "whitelist leaked before setup"


# ---- limiter keying ----

def test_ipv4_mapped_addresses_do_not_share_one_bucket(main_module):
    """::ffff:a.b.c.d collapsed to ::/64, locking out every client."""
    a = main_module._limiter_key("::ffff:203.0.113.9")
    b = main_module._limiter_key("::ffff:192.168.10.50")

    assert a != b, "mapped IPv4 addresses share a limiter key"
    # A mapped address must land in the same bucket as its plain form,
    # or an attacker switches representation to get a fresh budget.
    assert main_module._limiter_key("::ffff:192.168.10.50") == \
        main_module._limiter_key("192.168.10.50")


def test_ipv6_failures_accumulate_per_prefix(main_module, monkeypatch):
    """Blocking keyed on the raw address never fires for IPv6."""
    state = main_module._AuthState(password_hash="x")
    monkeypatch.setattr(main_module, "_auth", state)
    monkeypatch.setattr(main_module, "_save_auth", lambda s: None)

    for n in range(main_module._MAX_LOGIN_ATTEMPTS):
        main_module._record_login_failure(f"2001:db8:1:2::{n}")

    assert state.blocked_until, (
        "spreading attempts across one /64 never triggers a block"
    )


# ---- limiter memory ----

def test_limiter_forgets_idle_keys(main_module):
    """_hits only ever grew — the leak the bounded state fix missed."""
    limiter = main_module._RateLimiter(max_requests=5, window_sec=1)
    for n in range(2000):
        limiter.is_limited(f"10.0.{n // 256}.{n % 256}")
    peak = len(limiter._hits)

    # Walk the clock past the window instead of sleeping.
    future = dt.datetime.now(dt.timezone.utc).timestamp() + 3600
    limiter._prune(now=future)

    assert peak > 0
    assert len(limiter._hits) == 0, (
        f"idle keys retained: {len(limiter._hits)} of {peak}"
    )


def test_limiter_is_bounded_under_flood(main_module):
    limiter = main_module._RateLimiter(max_requests=5, window_sec=300)
    for n in range(main_module._MAX_TRACKED_IPS * 3):
        limiter.is_limited(f"10.{n // 65536}.{(n // 256) % 256}.{n % 256}")

    assert len(limiter._hits) <= main_module._MAX_TRACKED_IPS, (
        f"limiter grew to {len(limiter._hits)} keys"
    )


# ---- key deletion provenance ----

def test_only_generated_keys_are_deleted(main_module, tmp_path, monkeypatch):
    """Directory membership was the only check, so any key was fair game."""
    managed = tmp_path / ".ssh"
    managed.mkdir()
    monkeypatch.setattr(main_module, "_MANAGED_KEY_DIR", managed)

    operator_key = managed / "id_ed25519"
    operator_key.write_text("OPERATOR PRIVATE KEY", encoding="utf-8")
    unrelated = managed / "id_rsa_github"
    unrelated.write_text("GITHUB KEY", encoding="utf-8")

    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(operator_key), cfg)
    main_module._cleanup_server_key(str(unrelated), cfg)

    assert operator_key.exists(), "deleted the operator's own SSH key"
    assert unrelated.exists(), "deleted an unrelated key in ~/.ssh"


def test_generated_key_is_still_cleaned_up(main_module, tmp_path, monkeypatch):
    managed = tmp_path / ".ssh"
    managed.mkdir()
    monkeypatch.setattr(main_module, "_MANAGED_KEY_DIR", managed)

    key = managed / "id_ed25519_web01"
    key.write_text("PRIVATE", encoding="utf-8")
    pub = managed / "id_ed25519_web01.pub"
    pub.write_text("ssh-ed25519 AAAA", encoding="utf-8")

    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(key), cfg)

    assert not key.exists()
    assert not pub.exists()
