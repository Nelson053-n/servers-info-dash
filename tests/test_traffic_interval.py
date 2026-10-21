"""Traffic totals must not move when refresh_interval_sec changes.

Rates in the logs are instantaneous Mbit/s samples; turning them into a
volume needs the gap each sample covered. Multiplying by the *current*
interval rewrites history: raising it from 5s to 60s multiplied every
past total by twelve without a byte being transferred.
"""
import datetime as dt

# The totals cover a rolling 30-day window, so a hard-coded date stops
# counting once it scrolls out of it; yesterday is always inside.
DAY = (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)).isoformat()


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
    # Per-file sums are cached (in memory and in .daily_totals.json); without
    # a reset the second call would just replay the first and the comparison
    # in these tests could never notice an interval-dependent total.
    (tmp_path / ".daily_totals.json").unlink(missing_ok=True)
    main_module._traffic_file_cache.update(dir=None, files={})
    return main_module._calculate_traffic_30d_gb()


def test_totals_do_not_depend_on_the_current_interval(
    main_module, tmp_path, monkeypatch,
):
    # Ten minutes of samples, one per minute.
    rows = [
        (f"{DAY} 02:{minute:02d}", "8.0", "8.0")
        for minute in range(10)
    ]
    _write_log(tmp_path / f"srv_{DAY}.csv", rows=rows)

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
        (f"{DAY} 02:00", "8.0", "8.0"),
        (f"{DAY} 02:01", "8.0", "8.0"),
    ]
    _write_log(tmp_path / f"srv_{DAY}.csv", rows=rows)

    totals = _totals(main_module, tmp_path, monkeypatch, 5)

    # 16 Mbit/s * 60 s = 960 Mbit = 120 MB = 0.12 GB.
    assert abs(totals["srv"] - 0.12) < 0.005, totals


def test_a_gap_in_the_log_is_not_extrapolated(
    main_module, tmp_path, monkeypatch,
):
    """An outage must not be billed as if traffic continued."""
    rows = [
        (f"{DAY} 02:00", "8.0", "8.0"),
        (f"{DAY} 02:01", "8.0", "8.0"),
        # Collector was down for two hours.
        (f"{DAY} 04:01", "8.0", "8.0"),
    ]
    _write_log(tmp_path / f"srv_{DAY}.csv", rows=rows)

    totals = _totals(main_module, tmp_path, monkeypatch, 60)

    assert totals["srv"] < 0.5, (
        f"two-hour gap counted as continuous traffic: {totals}"
    )
