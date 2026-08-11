"""Per-server state must follow the server it belongs to.

Only _previous used to be handled, so deleting a server left its ping
cache, error counts and pooled SSH connection behind, and renaming one
resent every alert that was already firing.
"""


def _server(main_module, name="srv"):
    return main_module.ServerConfig(
        name=name, host="10.0.0.1", user="monitor",
    )


def _fill_state(main_module, collector, name):
    collector._previous[name] = main_module.PreviousSample(
        cpu_total=1, cpu_idle=1, rx_bytes=1, tx_bytes=1, at=1.0,
    )
    collector._ping_cache[name] = 12.3
    collector._ping_last_time[name] = 100.0
    collector._error_counts[name] = 2
    collector._last_good[name] = {"name": name, "status": "up"}


def test_forget_server_clears_every_store(main_module):
    collector = main_module.MetricsCollector(main_module.cfg)
    server = _server(main_module)
    _fill_state(main_module, collector, server.name)

    collector.forget_server(server)

    for store_name in (
        "_previous", "_ping_cache", "_ping_last_time",
        "_error_counts", "_last_good",
    ):
        store = getattr(collector, store_name)
        assert server.name not in store, f"{store_name} kept the server"


def test_forget_server_drops_the_pooled_connection(main_module):
    collector = main_module.MetricsCollector(main_module.cfg)
    server = _server(main_module)
    key = f"{server.host}:{server.port}:{server.user}"
    closed = []

    class _Conn:
        def close(self):
            closed.append(True)

    collector._pool[key] = _Conn()
    collector._pool_locks[key] = object()

    collector.forget_server(server)

    assert key not in collector._pool, "connection left open to a removed host"
    assert key not in collector._pool_locks, "lock entry leaked"
    assert closed, "connection was dropped without being closed"


def test_forget_server_leaves_other_servers_alone(main_module):
    collector = main_module.MetricsCollector(main_module.cfg)
    gone = _server(main_module, "gone")
    kept = _server(main_module, "kept")
    _fill_state(main_module, collector, gone.name)
    _fill_state(main_module, collector, kept.name)

    collector.forget_server(gone)

    assert kept.name in collector._previous
    assert kept.name in collector._last_good


def test_delete_endpoint_clears_state(main_module, monkeypatch):
    """The handler must actually use forget_server, not just have it."""
    import asyncio

    server = _server(main_module, "doomed")
    monkeypatch.setattr(main_module.cfg, "servers", [server])
    monkeypatch.setattr(main_module, "save_config", lambda cfg: None)
    _fill_state(main_module, main_module.collector, "doomed")

    asyncio.run(main_module.delete_server("doomed"))

    for store_name in (
        "_previous", "_ping_cache", "_ping_last_time",
        "_error_counts", "_last_good",
    ):
        store = getattr(main_module.collector, store_name)
        assert "doomed" not in store, (
            f"{store_name} still holds the deleted server"
        )


def test_rename_carries_alert_state(main_module, monkeypatch):
    """A rename must not resend alerts that are already firing."""
    import asyncio

    server = _server(main_module, "old")
    monkeypatch.setattr(main_module.cfg, "servers", [server])
    monkeypatch.setattr(main_module, "save_config", lambda cfg: None)
    monkeypatch.setitem(main_module._notified_state, "old", {"cpu"})
    monkeypatch.setitem(main_module._trigger_counts, "old", {"cpu": 3})
    _fill_state(main_module, main_module.collector, "old")

    asyncio.run(
        main_module.rename_server(
            "old", main_module.RenameServerRequest(new_name="new"),
        ),
    )

    assert main_module._notified_state.get("new") == {"cpu"}, (
        "alert state lost — every firing alert would be resent"
    )
    assert "old" not in main_module._notified_state
    assert main_module.collector._ping_cache.get("new") == 12.3
    assert "old" not in main_module.collector._previous
