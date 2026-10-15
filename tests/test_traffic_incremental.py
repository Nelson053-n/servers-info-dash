"""The month/30-day traffic totals must not re-parse unchanged logs.

Every refresh used to re-read the whole month of CSV logs (111 MB,
~1M rows, ~6 s CPU in production). Per-file totals are now cached in
memory and in logs/.daily_totals.json, keyed by the file's size and
mtime. These tests pin that the numbers are exactly those of the old
full re-read, and that only new or changed files are read.
"""
import datetime as dt
import json
import os
import random
from fractions import Fraction

import pytest

HEADER = (
    "timestamp,name,host,status,uptime_days,ping_ms,cpu_percent,"
    "ram_used_gb,ram_total_gb,disk_free_gb,disk_total_gb,"
    "rx_mbps,tx_mbps,interface,error\n"
)
TODAY = dt.datetime.now(dt.timezone.utc).date()


def _reference_30d(main_module, since=None):
    """The pre-cache implementation, kept verbatim as the oracle."""
    m = main_module
    cutoff = since or dt.datetime.now(dt.timezone.utc).date() - dt.timedelta(days=30)
    totals_raw = {}
    for file_path in m._LOGS_DIR.glob("*.csv"):
        parts = file_path.stem.rsplit("_", 1)
        if len(parts) != 2:
            continue
        safe_name, date_part = parts
        try:
            file_date = dt.date.fromisoformat(date_part)
        except ValueError:
            continue
        if file_date < cutoff:
            continue
        if file_path.stat().st_size <= 0:
            continue
        try:
            rows = m._read_traffic_rows(file_path)
        except (OSError, m.csv.Error, UnicodeDecodeError):
            continue
        last_seen = {}
        for row_name, rx_raw, tx_raw, row_ts in rows:
            row_key = m._safe_filename(row_name) if row_name else safe_name
            period_sec, parsed = m._sample_period_sec(row_ts, last_seen.get(row_key))
            last_seen[row_key] = parsed
            try:
                rx = float(rx_raw or 0.0)
            except (TypeError, ValueError):
                rx = 0.0
            try:
                tx = float(tx_raw or 0.0)
            except (TypeError, ValueError):
                tx = 0.0
            if rx <= 0 and tx <= 0:
                continue
            if period_sec is None:
                continue
            totals_raw[row_key] = totals_raw.get(row_key, 0.0) + (
                (rx + tx) * period_sec / 8.0 / 1000.0
            )
    return {k: round(v, 3) for k, v in totals_raw.items()}


def _exact_totals(main_module):
    """Rational totals: tells a rounding tie from a real discrepancy."""
    m = main_module
    exact = {}
    for fp in m._LOGS_DIR.glob("*.csv"):
        safe = fp.stem.rsplit("_", 1)[0]
        last = {}
        for name, rx, tx, ts in m._read_traffic_rows(fp):
            key = m._safe_filename(name) if name else safe
            period, parsed = m._sample_period_sec(ts, last.get(key))
            last[key] = parsed
            vals = []
            for raw in (rx, tx):
                try:
                    vals.append(Fraction(raw or "0"))
                except ValueError:
                    vals.append(Fraction(0))
            if (vals[0] <= 0 and vals[1] <= 0) or period is None:
                continue
            exact[key] = exact.get(key, 0) + sum(vals) * Fraction(period) / 8000
    return exact


def _assert_same(main_module, new, old):
    """Equal to the old full re-read, digit for digit.

    The one allowed difference: a total whose exact value ends in a
    half (x.xxx5) is a rounding tie, and which way round() goes there is
    decided by float summation order — the old code's own result
    changed with it. There ±0.001 is accepted.
    """
    assert new.keys() == old.keys()
    exact = _exact_totals(main_module)
    for key in old:
        if new[key] == old[key]:
            continue
        is_tie = (exact[key] * 1000) % 1 == Fraction(1, 2)
        assert is_tie and abs(new[key] - old[key]) == pytest.approx(0.001), (
            key, new[key], old[key], float(exact[key]),
        )


def _row(when, name, rx, tx):
    stamp = when.strftime("%Y-%m-%d %H:%M")
    return f"{stamp},{name},1.2.3.4,up,1,2,3,4,5,6,7,{rx},{tx},eth0,\n"


def _write_day(logs, name, day, rows):
    path = logs / f"{name}_{day.isoformat()}.csv"
    path.write_text(HEADER + "".join(rows), encoding="utf-8")
    return path


def _synthetic(logs, *, servers=4, days=6, rows_per_day=120, seed=7):
    rnd = random.Random(seed)
    for s in range(servers):
        name = f"Srv {s}/x"  # exercises _safe_filename on the row name
        safe = f"Srv {s}_x"
        for d in range(days):
            day = TODAY - dt.timedelta(days=d)
            start = dt.datetime.combine(day, dt.time(0, 0))
            rows = []
            minute = 0
            for _ in range(rows_per_day):
                minute += rnd.choice([1, 1, 1, 2, 5, 20])  # 20 min = outage gap
                rx = "" if rnd.random() < 0.03 else f"{rnd.uniform(0, 300):.2f}"
                tx = "bad" if rnd.random() < 0.02 else f"{rnd.uniform(0, 300):.2f}"
                rows.append(_row(start + dt.timedelta(minutes=minute), name, rx, tx))
            _write_day(logs, safe, day, rows)


@pytest.fixture
def logs(main_module, tmp_path, monkeypatch):
    monkeypatch.setattr(main_module, "_LOGS_DIR", tmp_path)
    # Forget any in-memory cache from other tests: "start" fresh.
    main_module._traffic_file_cache.update(dir=None, files={})
    return tmp_path


@pytest.fixture
def read_counter(main_module, monkeypatch):
    opened = []
    real = main_module._read_traffic_rows

    def counting(path):
        opened.append(path.name)
        return real(path)

    monkeypatch.setattr(main_module, "_read_traffic_rows", counting)
    return opened


def _restart(main_module):
    main_module._traffic_file_cache.update(dir=None, files={})


def test_matches_full_reread(main_module, logs):
    _synthetic(logs)
    month = TODAY.replace(day=1)
    expected_30d = _reference_30d(main_module)
    expected_month = _reference_30d(main_module, since=month)
    assert len(expected_30d) == 4 and all(v > 0 for v in expected_30d.values())

    first = main_module._calculate_traffic_30d_gb()
    _assert_same(main_module, first, expected_30d)
    _assert_same(
        main_module,
        main_module._calculate_traffic_30d_gb(since=month),
        expected_month,
    )
    # From memory, then from the disk cache: bit-identical to the first.
    assert main_module._calculate_traffic_30d_gb() == first
    _restart(main_module)
    assert main_module._calculate_traffic_30d_gb() == first


def test_second_call_reads_nothing_unchanged(main_module, logs, read_counter):
    _synthetic(logs)
    main_module._calculate_traffic_30d_gb()
    assert len(read_counter) == 4 * 6
    read_counter.clear()

    main_module._calculate_traffic_30d_gb()
    main_module._calculate_traffic_30d_gb(since=TODAY.replace(day=1))
    assert read_counter == [], "unchanged logs were parsed again"

    # After a restart the disk cache stands in for the parse.
    _restart(main_module)
    main_module._calculate_traffic_30d_gb()
    assert read_counter == [], "disk cache not used after restart"


def test_appended_row_adds_exactly_its_volume(main_module, logs, read_counter):
    _synthetic(logs)
    today_file = logs / f"Srv 0_x_{TODAY.isoformat()}.csv"
    before = main_module._calculate_traffic_30d_gb()
    cache = main_module._traffic_file_cache["files"]
    before_raw = cache[today_file.name]["totals"]["Srv 0_x"]
    read_counter.clear()

    # A row one minute after the last one: 16 Mbit/s * 60 s = 0.12 GB.
    last_ts = today_file.read_text(encoding="utf-8").strip().splitlines()[-1].split(",")[0]
    last = dt.datetime.strptime(last_ts, "%Y-%m-%d %H:%M")
    with today_file.open("a", encoding="utf-8") as fh:
        fh.write(_row(last + dt.timedelta(minutes=1), "Srv 0/x", "8.0", "8.0"))

    after = main_module._calculate_traffic_30d_gb()
    assert read_counter == [today_file.name], "only today's file should be re-read"
    # Unrounded: the rounded map could flip a tie by 0.001.
    after_raw = cache[today_file.name]["totals"]["Srv 0_x"]
    assert after_raw == pytest.approx(before_raw + 0.12, abs=1e-9)
    assert after["Srv 0_x"] == pytest.approx(before["Srv 0_x"] + 0.12, abs=0.0011)
    assert {k: v for k, v in after.items() if k != "Srv 0_x"} == {
        k: v for k, v in before.items() if k != "Srv 0_x"
    }
    _assert_same(main_module, after, _reference_30d(main_module))


def test_closed_day_rewritten_is_recounted(main_module, logs):
    day = TODAY - dt.timedelta(days=3)
    start = dt.datetime.combine(day, dt.time(10, 0))
    rows = [_row(start + dt.timedelta(minutes=i), "srv", "8.0", "8.0") for i in range(3)]
    path = _write_day(logs, "srv", day, rows)
    assert main_module._calculate_traffic_30d_gb() == {"srv": 0.24}

    # Same size, different numbers: only the mtime gives it away.
    stat = path.stat()
    path.write_text(path.read_text(encoding="utf-8").replace("8.0", "9.0"), encoding="utf-8")
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert path.stat().st_size == stat.st_size

    assert main_module._calculate_traffic_30d_gb() == {"srv": 0.27}


def test_damaged_cache_file_is_silently_rebuilt(main_module, logs, read_counter):
    _synthetic(logs)
    expected = _reference_30d(main_module)
    main_module._calculate_traffic_30d_gb()
    cache_file = logs / main_module._TRAFFIC_TOTALS_CACHE_NAME
    assert cache_file.exists()

    for garbage in ("{not json", '{"version": 1, "files": {"x.csv": {"size": "a"}}}', "[]"):
        cache_file.write_text(garbage, encoding="utf-8")
        _restart(main_module)
        read_counter.clear()
        got = main_module._calculate_traffic_30d_gb()
        assert len(read_counter) == 4 * 6, "damaged cache should mean a full re-read"
        _assert_same(main_module, got, expected)
        json.loads(cache_file.read_text(encoding="utf-8"))  # rewritten valid


def test_deleted_logs_leave_the_cache(main_module, logs):
    _synthetic(logs)
    main_module._calculate_traffic_30d_gb()
    old = logs / f"Srv 1_x_{(TODAY - dt.timedelta(days=5)).isoformat()}.csv"
    old.unlink()

    _assert_same(
        main_module, main_module._calculate_traffic_30d_gb(), _reference_30d(main_module),
    )
    cached = json.loads((logs / main_module._TRAFFIC_TOTALS_CACHE_NAME).read_text())
    assert old.name not in cached["files"]


def test_no_logs_gives_empty_map(main_module, logs):
    assert main_module._calculate_traffic_30d_gb() == {}
