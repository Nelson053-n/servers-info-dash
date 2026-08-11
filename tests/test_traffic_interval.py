"""Traffic totals must not move when refresh_interval_sec changes.

Rates in the logs are instantaneous Mbit/s samples; turning them into a
volume needs the gap each sample covered. Multiplying by the *current*
interval rewrites history: raising it from 5s to 60s multiplied every
past total by twelve without a byte being transferred.
"""


def _write_log(path, *, rows, name="srv"):
    header = (
        "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent,"
        "ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb,"
        "rx_mbps,tx_mbps,interface,error\n"
    )
    body = "".join(
        f"{ts},{name},1.2.3.4,up,1,2,3,4,5,6,7,{rx},{tx},eth0,\n"
        for ts, rx, tx in rows
    )
    path.write_text(header + body, encoding="utf-8")


def _totals(main_module, tmp_path, monkeypatch, interval):
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    monkeypatch.setattr(main_module.cfg, "refresh_interval_sec", interval)
    return main_module._calculate_traffic_30d_gb()


def test_totals_do_not_depend_on_the_current_interval(
    main_module, tmp_path, monkeypatch,
):
    # Ten minutes of samples, one per minute.
    rows = [
        (f"2026-08-03 02:{minute:02d}", "8.0", "8.0")
        for minute in range(10)
    ]
    _write_log(tmp_path / "srv_2026-08-03.csv", rows=rows)

    at_5s = _totals(main_module, tmp_path, monkeypatch, 5)
    at_60s = _totals(main_module, tmp_path, monkeypatch, 60)

    assert at_5s["srv"] == at_60s["srv"], (
        f"history rewritten by the interval setting: "
        f"{at_5s['srv']} vs {at_60s['srv']}"
    )


def test_volume_matches_the_gap_between_samples(
    main_module, tmp_path, monkeypatch,
):
    """16 Mbit/s across one minute is 0.12 GB, whatever the setting."""
    rows = [
        ("2026-08-03 02:00", "8.0", "8.0"),
        ("2026-08-03 02:01", "8.0", "8.0"),
    ]
    _write_log(tmp_path / "srv_2026-08-03.csv", rows=rows)

    totals = _totals(main_module, tmp_path, monkeypatch, 5)

    # 16 Mbit/s * 60 s = 960 Mbit = 120 MB = 0.12 GB.
    assert abs(totals["srv"] - 0.12) < 0.005, totals


def test_a_gap_in_the_log_is_not_extrapolated(
    main_module, tmp_path, monkeypatch,
):
    """An outage must not be billed as if traffic continued."""
    rows = [
        ("2026-08-03 02:00", "8.0", "8.0"),
        ("2026-08-03 02:01", "8.0", "8.0"),
        # Collector was down for two hours.
        ("2026-08-03 04:01", "8.0", "8.0"),
    ]
    _write_log(tmp_path / "srv_2026-08-03.csv", rows=rows)

    totals = _totals(main_module, tmp_path, monkeypatch, 60)

    assert totals["srv"] < 0.5, (
        f"two-hour gap counted as continuous traffic: {totals}"
    )
