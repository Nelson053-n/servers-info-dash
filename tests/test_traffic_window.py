"""The 1-day total must cover 24 hours, not "today plus yesterday".

Filtering whole files by the date in their name made the window run from
24 to 48 hours depending on the time of day, so the figure roughly
halved at every midnight without traffic changing. The tests pin "now"
so the behaviour does not depend on when the suite runs.
"""
import datetime as dt

import pytest

HEADER = (
    "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent,"
    "ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb,"
    "rx_mbps,tx_mbps,interface,error\n"
)

# Late in the day: "today plus yesterday" is then ~46 hours wide.
NOW = dt.datetime(2026, 8, 12, 22, 0, tzinfo=dt.timezone.utc)


@pytest.fixture
def frozen_now(main_module, monkeypatch):
    """Pin the clock the traffic maths reads."""
    real_datetime = dt.datetime

    class _Frozen(real_datetime):
        @classmethod
        def now(cls, tz=None):
            return NOW if tz else NOW.replace(tzinfo=None)

    monkeypatch.setattr(main_module.dt, "datetime", _Frozen)
    return NOW


def _row(when, rx="8.0", tx="8.0", name="srv"):
    stamp = when.strftime("%Y-%m-%d %H:%M")
    return f"{stamp},{name},1.2.3.4,up,1,2,3,4,5,6,7,{rx},{tx},eth0,\n"


def _write_day(tmp_path, day, rows):
    path = tmp_path / f"srv_{day.strftime('%Y-%m-%d')}.csv"
    path.write_text(HEADER + "".join(rows), encoding="utf-8")


def test_day_window_excludes_samples_older_than_24h(
    main_module, tmp_path, monkeypatch, frozen_now,
):
    # 34 hours ago: yesterday by filename, but outside 24 hours.
    old = NOW - dt.timedelta(hours=34)
    _write_day(
        tmp_path, old.date(),
        [_row(old), _row(old + dt.timedelta(minutes=1))],
    )
    # One hour ago, well inside the window.
    recent = NOW - dt.timedelta(hours=1)
    _write_day(
        tmp_path, recent.date(),
        [_row(recent), _row(recent + dt.timedelta(minutes=1))],
    )

    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    totals = main_module._calculate_traffic_1d_gb()

    # Only the recent minute counts: 16 Mbit/s * 60 s = 0.12 GB.
    assert totals.get("srv", 0) == pytest.approx(0.12, abs=0.01), (
        f"34-hour-old samples counted in the day total: {totals}"
    )


def test_day_window_keeps_recent_samples_from_yesterdays_file(
    main_module, tmp_path, monkeypatch, frozen_now,
):
    """Just after midnight the last 24h mostly live in yesterday's file."""
    recent = NOW - dt.timedelta(hours=2)
    _write_day(
        tmp_path, recent.date(),
        [_row(recent), _row(recent + dt.timedelta(minutes=1))],
    )

    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    totals = main_module._calculate_traffic_1d_gb()

    assert totals.get("srv", 0) > 0, (
        f"recent samples dropped because of the file's name: {totals}"
    )
