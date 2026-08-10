"""An unconfigured dashboard must not be wide open.

Two separate defects are covered here:
  * a corrupted auth.yaml used to degrade into "no password set", which
    silently unlocked every endpoint;
  * with no password set at all, every endpoint was served to anyone.
"""
import pytest


def test_corrupt_auth_file_fails_closed(main_module, tmp_path, monkeypatch):
    """A truncated auth.yaml must raise, not degrade to no-password."""
    broken = tmp_path / "auth.yaml"
    # Valid YAML, but the structure the app wrote is gone — exactly what a
    # kill mid-write leaves behind.
    broken.write_text("sessions:\n  abc: 1.2.3.4\n", encoding="utf-8")
    monkeypatch.setattr(main_module, "_AUTH_PATH", broken)

    with pytest.raises(RuntimeError, match="password_hash"):
        main_module._load_auth()


def test_missing_auth_file_is_first_run(main_module, tmp_path, monkeypatch):
    """No file at all is a legitimate first run, not corruption."""
    monkeypatch.setattr(main_module, "_AUTH_PATH", tmp_path / "absent.yaml")

    state = main_module._load_auth()

    assert state.password_hash == ""


def test_empty_auth_file_is_first_run(main_module, tmp_path, monkeypatch):
    """An empty file is what mkdir+touch leaves; treat it as first run."""
    empty = tmp_path / "auth.yaml"
    empty.write_text("", encoding="utf-8")
    monkeypatch.setattr(main_module, "_AUTH_PATH", empty)

    state = main_module._load_auth()

    assert state.password_hash == ""


def test_setup_token_is_generated_when_no_password(main_module, monkeypatch):
    """First run must mint a token instead of leaving the app open."""
    monkeypatch.setattr(
        main_module, "_auth", main_module._AuthState(password_hash=""),
    )
    monkeypatch.setattr(main_module, "_setup_token", None)

    token = main_module._ensure_setup_token()

    assert token
    assert len(token) >= 20, "setup token must not be guessable"


def test_no_setup_token_once_password_is_set(main_module, monkeypatch):
    """A configured dashboard must not keep a bootstrap backdoor."""
    monkeypatch.setattr(
        main_module,
        "_auth",
        main_module._AuthState(password_hash="pbkdf2_sha256$1$x$y"),
    )
    monkeypatch.setattr(main_module, "_setup_token", None)

    assert main_module._ensure_setup_token() is None


def test_setup_token_is_required_to_set_first_password(
    main_module, monkeypatch,
):
    """Setting the first password must prove possession of the token."""
    monkeypatch.setattr(
        main_module, "_auth", main_module._AuthState(password_hash=""),
    )
    monkeypatch.setattr(main_module, "_setup_token", "correct-token")

    assert main_module._check_setup_token("correct-token") is True
    assert main_module._check_setup_token("wrong-token") is False
    assert main_module._check_setup_token(None) is False


def test_setup_token_check_passes_once_configured(main_module, monkeypatch):
    """With a password set the token gate is inert, not a second door."""
    monkeypatch.setattr(
        main_module,
        "_auth",
        main_module._AuthState(password_hash="pbkdf2_sha256$1$x$y"),
    )
    monkeypatch.setattr(main_module, "_setup_token", None)

    # No token exists, so nothing can satisfy the gate.
    assert main_module._check_setup_token("anything") is False
