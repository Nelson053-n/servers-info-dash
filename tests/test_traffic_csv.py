import datetime as dt
from pathlib import Path

import pytest


def _yesterday():
    """Log dates must fall inside the 30-day window whenever the suite runs."""
    return (dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=1)).isoformat()


def _write_log(path: Path, *, trailer: bytes = b"", row: str | None = None):
    header = "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent," \
        "ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb," \
        "rx_mbps,tx_mbps,interface,error\n"
    body = row if row is not None else (
        "2026-08-03 02:17,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
    )
    path.write_bytes((header + body).encode() + trailer)


GOOD_ROW = "2026-08-03 02:17,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
NEXT_ROW = "2026-08-03 02:19,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"


def test_trailing_nul_block_does_not_hide_good_rows(main_module, tmp_path):
    """A log whose tail was zeroed by a crash keeps the rows before it."""
    bad = tmp_path / "srv_2026-08-03.csv"
    _write_log(bad, trailer=b"\x00" * 100)

    rows = main_module._read_traffic_rows(bad)

    assert rows == [("srv", "8.5", "9.5", "2026-08-03 02:17")]


def test_nul_block_between_rows_keeps_the_row_after_it(main_module, tmp_path):
    """Production pattern: NULs sit directly before an intact row."""
    f = tmp_path / "srv_2026-08-03.csv"
    _write_log(f, row=GOOD_ROW + "\x00" * 103 + NEXT_ROW)

    rows = main_module._read_traffic_rows(f)

    assert [r[3] for r in rows] == ["2026-08-03 02:17", "2026-08-03 02:19"]


def test_record_cut_off_before_nul_block_is_not_glued_to_the_next_row(
    main_module, tmp_path,
):
    """Stripping the NULs would glue the cut-off row onto the next one."""
    f = tmp_path / "srv_2026-08-03.csv"
    cut_off = "2026-08-03 02:18,srv,1.2.3.4,up,1,2,3"
    _write_log(f, row=GOOD_ROW + cut_off + "\x00" * 50 + NEXT_ROW)

    rows = main_module._read_traffic_rows(f)

    assert rows == [
        ("srv", "8.5", "9.5", "2026-08-03 02:17"),
        ("srv", "8.5", "9.5", "2026-08-03 02:19"),
    ]


def test_no_nul_reaches_the_rows(main_module, tmp_path):
    """Corruption in the middle of a field must not reach the traffic sums."""
    f = tmp_path / "srv_2026-08-03.csv"
    _write_log(f, row=GOOD_ROW + "2026-08-03 02:18,sr\x00v,1.2.3.4,up,1,2,3,4,5,6,7,99,99,eth0,\n" + NEXT_ROW)

    rows = main_module._read_traffic_rows(f)

    assert all("\x00" not in v for row in rows for v in row)
    assert ("srv", "99", "99", "2026-08-03 02:18") not in rows


def test_intact_log_is_read(main_module, tmp_path):
    """The guard must not reject healthy files."""
    good = tmp_path / "srv_2026-08-03.csv"
    _write_log(good)

    rows = main_module._read_traffic_rows(good)

    assert rows == [("srv", "8.5", "9.5", "2026-08-03 02:17")]


def test_file_with_nul_is_counted_not_dropped(main_module, tmp_path, monkeypatch):
    """A crash-damaged log must still contribute its intact rows."""
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    day = _yesterday()
    # Totals are keyed by the name column, not the filename. Two rows
    # are needed for a volume: the gap between them is the period.
    _write_log(
        tmp_path / f"healthy_{day}.csv",
        row=(
            f"{day} 02:17,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
            f"{day} 02:18,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
        ),
    )
    _write_log(
        tmp_path / f"damaged_{day}.csv",
        row=(
            f"{day} 02:17,other,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
            + "\x00" * 103
            + f"{day} 02:18,other,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
        ),
        trailer=b"\x00" * 50,
    )

    totals = main_module._calculate_traffic_30d_gb()

    # 18 Mbit/s over the one-minute gap = 0.135 GB, for each file.
    assert totals.get("srv") == pytest.approx(0.135, abs=0.001)
    assert totals.get("other") == pytest.approx(0.135, abs=0.001), (
        "rows around the NUL block were thrown away with the file"
    )


def test_traffic_calc_skips_corrupted_files():
    """_calculate_traffic_* must not die on one unreadable log."""
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert source.count("_read_traffic_rows(file_path)") == 2
    assert source.count("skipping unreadable traffic log") == 2


def test_background_collector_logs_failures():
    """A dead collector must leave a trace in the journal."""
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert "background collector cycle failed" in source
    assert "        except Exception:  # noqa: BLE001\n            pass" \
        not in source
