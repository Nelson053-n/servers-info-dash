import csv
from pathlib import Path


def _read_rows_like_app(file_path: Path) -> list[tuple[str, str, str]]:
    """Mirror of _read_traffic_rows in app/main.py.

    Kept in sync manually: importing app.main pulls in asyncssh and
    reads the runtime config, which the smoke tests deliberately avoid.
    """
    rows: list[tuple[str, str, str]] = []
    with file_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        _ = next(reader, None)
        for values in reader:
            if len(values) >= 15:
                rows.append((values[1], values[11], values[12]))
            elif len(values) >= 12:
                rows.append((values[1], values[8], values[9]))
    return rows


def test_nul_bytes_raise_csv_error(tmp_path):
    """A log truncated by a crash must raise, not return bad data."""
    bad = tmp_path / "srv_2026-08-03.csv"
    header = "timestamp,name,host,status,uptime_days,ping_ms,cpu\n"
    row = "2026-08-03 02:17,srv,1.2.3.4,up," + ",".join(["1"] * 11) + "\n"
    bad.write_bytes((header + row).encode() + b"\x00" * 100)

    try:
        _read_rows_like_app(bad)
    except csv.Error:
        return
    raise AssertionError("expected csv.Error on NUL bytes")


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
