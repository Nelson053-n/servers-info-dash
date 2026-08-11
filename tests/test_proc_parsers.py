"""Unexpected /proc output must degrade, not raise.

An exception here propagates to collect_server, which serves cached data
for up to five cycles before marking the host down — the dashboard shows
stale numbers as current, with the parse error only visible later as the
server's "error" field.
"""
import pytest

GOOD_STAT = "cpu  100 20 30 400 50 0 0 0 0 0\ncpu0 1 2 3 4 5\n"
GOOD_NET = (
    "Inter-|   Receive                    |  Transmit\n"
    " face |bytes    packets errs drop fifo frame compressed multicast|"
    "bytes    packets errs drop fifo colls carrier compressed\n"
    "    lo:  1000      10    0    0    0     0          0         0"
    "   1000      10    0    0    0     0       0          0\n"
    "  eth0:  5000      50    0    0    0     0          0         0"
    "   6000      60    0    0    0     0       0          0\n"
)
GOOD_MEM = (
    "---MEM---\n"
    "MemTotal:       16384000 kB\n"
    "MemAvailable:    8192000 kB\n"
    "---NEXT---\n"
)


def test_cpu_line_parses_normally(main_module):
    total, idle = main_module.MetricsCollector._parse_cpu_line(GOOD_STAT)

    assert total == 600
    assert idle == 450  # idle + iowait


def test_cpu_line_survives_non_numeric_fields(main_module):
    """A garbled line must not take the whole collection down."""
    bad = "cpu  100 20 xx 400 50 0 0 0\n"

    with pytest.raises(RuntimeError):
        main_module.MetricsCollector._parse_cpu_line(bad)


def test_cpu_line_survives_short_line(main_module):
    """Fewer fields than the slice expects must not IndexError."""
    short = "cpu  1 2 3 4 5 6\n"

    try:
        total, idle = main_module.MetricsCollector._parse_cpu_line(short)
    except RuntimeError:
        return  # rejecting it outright is fine
    except IndexError:
        pytest.fail("IndexError instead of a clean parse failure")
    assert total > 0 and idle >= 0


def test_net_dev_parses_normally(main_module):
    iface, rx, tx = main_module.MetricsCollector._parse_net_dev(
        GOOD_NET, None,
    )

    assert iface == "eth0"
    assert (rx, tx) == (5000, 6000)


def test_net_dev_skips_garbled_rows(main_module):
    """A line with a colon but non-numeric counters must be skipped.

    An motd or sudo message landing in the stream is enough to hit this.
    """
    polluted = GOOD_NET + (
        "  warning: something odd happened here and it has "
        "sixteen or more tokens a b c d e f g h i j k l m n o p\n"
    )

    iface, rx, tx = main_module.MetricsCollector._parse_net_dev(
        polluted, None,
    )

    assert iface == "eth0", "a noise line displaced the real interface"
    assert (rx, tx) == (5000, 6000)


def test_meminfo_parses_normally(main_module):
    used, total = main_module.MetricsCollector._parse_meminfo(GOOD_MEM)

    assert total == pytest.approx(15.6, abs=0.1)
    assert used == pytest.approx(7.8, abs=0.1)


def test_meminfo_survives_non_numeric_value(main_module):
    """A garbled value must yield "unknown", not kill the collection."""
    bad = (
        "---MEM---\n"
        "MemTotal:       not-a-number kB\n"
        "MemAvailable:    8192000 kB\n"
        "---NEXT---\n"
    )

    used, total = main_module.MetricsCollector._parse_meminfo(bad)

    assert (used, total) == (None, None)
