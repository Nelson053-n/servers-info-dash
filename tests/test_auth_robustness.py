"""Writing auth state must not be able to leave a half-written file.

A truncated auth.yaml is what fed the "no password set" bypass: a kill
mid-write leaves valid YAML with the password_hash gone.
"""
import ipaddress
import stat


def test_write_is_atomic(main_module, tmp_path, monkeypatch):
    """A crash mid-write must leave the previous file intact."""
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)
    main_module._save_auth(
        main_module._AuthState(password_hash="original"),
    )

    real_dump = main_module.yaml.safe_dump

    def _explode(data, stream=None, **kwargs):
        real_dump(data, stream, **kwargs)
        raise OSError("disk full")

    monkeypatch.setattr(main_module.yaml, "safe_dump", _explode)
    try:
        main_module._save_auth(
            main_module._AuthState(password_hash="replacement"),
        )
    except OSError:
        pass

    reloaded = main_module._load_auth()
    assert reloaded.password_hash == "original", (
        "a failed write destroyed the previous auth state"
    )


def test_temp_file_is_not_left_behind(main_module, tmp_path, monkeypatch):
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)

    main_module._save_auth(main_module._AuthState(password_hash="x"))

    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "auth.yaml"]
    assert not leftovers, f"temp files left in place: {leftovers}"


def test_permissions_survive_the_atomic_write(
    main_module, tmp_path, monkeypatch,
):
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)

    main_module._save_auth(main_module._AuthState(password_hash="x"))

    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"created with {oct(mode)}"


def test_ip_allowed_rejects_unparsable_entries(main_module):
    """A garbled entry must be ignored, not matched as text."""
    assert not main_module._ip_allowed("10.0.0.1", ["not-a-network"])
    assert not main_module._ip_allowed(
        "example.com", ["example.com"],
    ), "matched a hostname by string comparison"


def test_ip_allowed_tolerates_stray_whitespace(main_module):
    """Whitespace in a hand-edited entry must not lock the operator out."""
    assert main_module._ip_allowed("192.168.1.5", [" 192.168.1.0/24 "])


def test_ip_allowed_matches_real_networks(main_module):
    assert main_module._ip_allowed("192.168.1.5", ["192.168.1.0/24"])
    assert main_module._ip_allowed("10.0.0.7", ["10.0.0.7"])
    assert not main_module._ip_allowed("172.16.0.1", ["192.168.1.0/24"])


def test_ip_allowed_handles_mapped_ipv4(main_module):
    """A dual-stack socket reports IPv4 clients as ::ffff:a.b.c.d."""
    assert main_module._ip_allowed(
        "::ffff:192.168.1.5", ["192.168.1.0/24"],
    ), "mapped IPv4 client locked out of its own whitelist"


def test_login_survives_a_failing_geo_lookup(main_module, monkeypatch):
    """Login must not hinge on a third-party geo service answering."""
    from fastapi.testclient import TestClient

    password = "correct-horse-battery"
    monkeypatch.setattr(
        main_module, "_auth",
        main_module._AuthState(
            password_hash=main_module._hash_password(password),
        ),
    )
    monkeypatch.setattr(main_module, "_save_auth", lambda state: None)
    monkeypatch.setattr(
        main_module, "_login_limiter",
        main_module._RateLimiter(max_requests=50, window_sec=60),
    )

    def _explode(ip):
        raise OSError("ip-api unreachable")

    monkeypatch.setattr(main_module, "_geo_lookup", _explode)

    async def _no_collector() -> None:
        return None

    monkeypatch.setattr(main_module, "_background_collector", _no_collector)
    with TestClient(main_module.app) as client:
        r = client.post("/api/auth/login", json={"password": password})

    assert r.status_code == 200, (
        f"a geo lookup failure blocked login: {r.status_code} {r.text}"
    )
