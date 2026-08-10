"""Deleting a server must never unlink files outside the app's key dir."""


def _server(main_module, name, client_key):
    return main_module.ServerConfig(
        name=name, host="127.0.0.1", user="monitor", client_key=client_key,
    )


def test_external_key_is_not_deleted(main_module, tmp_path):
    """A client_key outside the managed dir must survive server deletion."""
    victim = tmp_path / "nginx.conf"
    victim.write_text("important", encoding="utf-8")

    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(victim), cfg)

    assert victim.exists(), "external file was deleted by server cleanup"


def test_sibling_suffix_file_is_not_deleted(main_module, tmp_path):
    """with_suffix('.pub') must not turn config.yaml into config.pub."""
    victim = tmp_path / "config.yaml"
    victim.write_text("servers: []", encoding="utf-8")
    sibling = tmp_path / "config.pub"
    sibling.write_text("unrelated", encoding="utf-8")

    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(victim), cfg)

    assert sibling.exists(), "unrelated .pub sibling was deleted"


def test_managed_key_is_deleted(main_module, tmp_path, monkeypatch):
    """Keys the app generated itself are still cleaned up."""
    managed_dir = tmp_path / ".ssh"
    managed_dir.mkdir()
    monkeypatch.setattr(main_module, "_MANAGED_KEY_DIR", managed_dir)

    key = managed_dir / "id_ed25519_web01"
    key.write_text("PRIVATE", encoding="utf-8")
    pub = managed_dir / "id_ed25519_web01.pub"
    pub.write_text("ssh-ed25519 AAAA", encoding="utf-8")

    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(key), cfg)

    assert not key.exists(), "managed private key should be removed"
    assert not pub.exists(), "managed public key should be removed"


def test_managed_key_still_used_is_kept(main_module, tmp_path, monkeypatch):
    """A key shared with another server must not be removed."""
    managed_dir = tmp_path / ".ssh"
    managed_dir.mkdir()
    monkeypatch.setattr(main_module, "_MANAGED_KEY_DIR", managed_dir)

    key = managed_dir / "id_ed25519_shared"
    key.write_text("PRIVATE", encoding="utf-8")

    cfg = main_module.AppConfig(
        refresh_interval_sec=5,
        servers=[_server(main_module, "other", str(key))],
    )
    main_module._cleanup_server_key(str(key), cfg)

    assert key.exists(), "key still referenced by another server was removed"


def test_traversal_out_of_managed_dir_is_rejected(
    main_module, tmp_path, monkeypatch,
):
    """A path escaping the managed dir via .. must not be deleted."""
    managed_dir = tmp_path / ".ssh"
    managed_dir.mkdir()
    monkeypatch.setattr(main_module, "_MANAGED_KEY_DIR", managed_dir)

    victim = tmp_path / "outside.txt"
    victim.write_text("keep me", encoding="utf-8")

    escaped = managed_dir / ".." / "outside.txt"
    cfg = main_module.AppConfig(refresh_interval_sec=5, servers=[])
    main_module._cleanup_server_key(str(escaped), cfg)

    assert victim.exists(), "path traversal out of managed dir was deleted"
