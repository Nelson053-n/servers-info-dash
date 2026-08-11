"""CSV logging and shutdown must not fail on awkward real-world state."""
import asyncio


def _server_row(name="srv"):
    return {
        "name": name, "host": "10.0.0.1", "status": "up",
        "uptime_days": 1.0, "ping_ms": 2.0, "cpu_percent": 3.0,
        "ram_used_gb": 4.0, "ram_total_gb": 5.0,
        "disk_free_gb": 6.0, "disk_total_gb": 7.0,
        "rx_mbps": 8.0, "tx_mbps": 9.0, "interface": "eth0", "error": None,
    }


def test_logging_survives_a_foreign_header(main_module, tmp_path, monkeypatch):
    """A legacy file whose first column is not "timestamp" must not raise.

    DictWriter rejects keys outside its fieldnames, so this used to kill
    logging for every server until the next day's file.
    """
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    today = main_module.dt.datetime.now(
        main_module.dt.timezone.utc,
    ).date().isoformat()
    legacy = tmp_path / f"srv_{today}.csv"
    legacy.write_text(
        "time,name,host,status,rx_mbps,tx_mbps\n"
        "2026-08-01 00:00,srv,10.0.0.1,up,1,2\n",
        encoding="utf-8",
    )

    main_module._log_server_metrics([_server_row()])

    assert legacy.read_text(encoding="utf-8").count("\n") >= 3, (
        "the row was not appended"
    )


def test_logging_writes_a_normal_file(main_module, tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)

    main_module._log_server_metrics([_server_row()])

    written = list(tmp_path.glob("srv_*.csv"))
    assert written, "no log file created"
    text = written[0].read_text(encoding="utf-8")
    assert "timestamp" in text.splitlines()[0]
    assert "8.0" in text and "9.0" in text


def test_shutdown_closes_pooled_connections(main_module, monkeypatch):
    closed = []

    class _Conn:
        def close(self):
            closed.append(True)

        async def wait_closed(self):
            return None

    monkeypatch.setitem(
        main_module.collector._pool, "10.0.0.1:22:monitor", _Conn(),
    )

    asyncio.run(main_module._stop_background_tasks())

    assert closed, "shutdown left SSH connections open"
    assert not main_module.collector._pool, "pool not emptied"
