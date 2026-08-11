"""auth.yaml holds session tokens in the clear — it must not be world-readable.

Verified on the production host: with the default umask the file lands
at 0644, and `nobody` could read every live session token plus the
password hash.
"""
import stat


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_new_auth_file_is_not_world_readable(main_module, tmp_path, monkeypatch):
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)

    main_module._save_auth(main_module._AuthState(password_hash="x"))

    assert _mode(target) == 0o600, f"created with {oct(_mode(target))}"


def test_existing_permissions_are_tightened(main_module, tmp_path, monkeypatch):
    """A file already deployed at 0644 must be fixed on the next write."""
    target = tmp_path / "auth.yaml"
    target.write_text("password_hash: ''\n", encoding="utf-8")
    target.chmod(0o644)
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)

    main_module._save_auth(main_module._AuthState(password_hash="x"))

    assert _mode(target) == 0o600, f"left at {oct(_mode(target))}"


def test_file_is_never_world_readable_mid_write(
    main_module, tmp_path, monkeypatch,
):
    """The mode must be set at creation, not patched up afterwards.

    Creating at the umask default and chmod-ing later leaves the tokens
    readable for the duration of the write.
    """
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)
    seen = []

    real_dump = main_module.yaml.safe_dump

    def spy(data, stream=None, **kwargs):
        # Called with the contents being written. The write goes to a
        # temp sibling that is renamed into place, so check whichever
        # files exist at this moment — none may be world-readable.
        for path in tmp_path.iterdir():
            seen.append(_mode(path))
        return real_dump(data, stream, **kwargs)

    monkeypatch.setattr(main_module.yaml, "safe_dump", spy)
    main_module._save_auth(main_module._AuthState(password_hash="x"))

    assert seen, "safe_dump was not called — test needs updating"
    assert all(m == 0o600 for m in seen), (
        f"file was {[oct(m) for m in seen]} while being written"
    )


def test_saved_state_is_still_readable_back(main_module, tmp_path, monkeypatch):
    """Tightening the mode must not break the app's own round-trip."""
    target = tmp_path / "auth.yaml"
    monkeypatch.setattr(main_module, "_AUTH_PATH", target)
    state = main_module._AuthState(
        password_hash="pbkdf2$deadbeef$cafe",
        allowed_networks=["192.168.10.0/24"],
    )

    main_module._save_auth(state)
    loaded = main_module._load_auth()

    assert loaded.password_hash == state.password_hash
    assert loaded.allowed_networks == state.allowed_networks
