import csv
from pathlib import Path

import pytest


def _write_log(path: Path, *, trailer: bytes = b"", row: str | None = None):
    header = "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent," \
        "ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb," \
        "rx_mbps,tx_mbps,interface,error\n"
    body = row if row is not None else (
        "2026-08-03 02:17,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
    )
    path.write_bytes((header + body).encode() + trailer)


def test_nul_bytes_raise_csv_error(main_module, tmp_path):
    """A log truncated by a crash must raise, not return bad data.

    csv.reader does not object to NUL bytes on its own — it returns them
    inside the fields — so the check has to be explicit.
    """
    bad = tmp_path / "srv_2026-08-03.csv"
    _write_log(bad, trailer=b"\x00" * 100)

    with pytest.raises(csv.Error):
        main_module._read_traffic_rows(bad)


def test_nul_byte_inside_a_field_is_rejected(main_module, tmp_path):
    """Corruption in the middle of a row must not reach the traffic sums."""
    bad = tmp_path / "srv_2026-08-03.csv"
    _write_log(
        bad,
        row="2026-08-03 02:17,sr\x00v,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n",
    )

    with pytest.raises(csv.Error):
        main_module._read_traffic_rows(bad)


def test_intact_log_is_read(main_module, tmp_path):
    """The guard must not reject healthy files."""
    good = tmp_path / "srv_2026-08-03.csv"
    _write_log(good)

    rows = main_module._read_traffic_rows(good)

    assert rows == [("srv", "8.5", "9.5", "2026-08-03 02:17")]


def test_corrupted_file_is_skipped_not_fatal(main_module, tmp_path, monkeypatch):
    """One bad log must not zero out the whole traffic calculation."""
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    # Totals are keyed by the name column, not the filename. Two rows
    # are needed for a volume: the gap between them is the period.
    _write_log(
        tmp_path / "healthy_2026-08-03.csv",
        row=(
            "2026-08-03 02:17,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
            "2026-08-03 02:18,srv,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
        ),
    )
    _write_log(
        tmp_path / "broken_2026-08-03.csv",
        row=(
            "2026-08-03 02:17,other,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
            "2026-08-03 02:18,other,1.2.3.4,up,1,2,3,4,5,6,7,8.5,9.5,eth0,\n"
        ),
        trailer=b"\x00" * 50,
    )

    totals = main_module._calculate_traffic_30d_gb()

    assert "srv" in totals, "healthy log dropped along with the corrupt one"
    assert "other" not in totals, "data from the corrupted log was counted"


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
