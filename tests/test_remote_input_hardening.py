"""Input a monitored host or the admin can shape must stay inert."""
import os
import stat

import pytest


def test_oversized_snapshot_is_rejected(main_module):
    norm = main_module.MetricsCollector._normalize_output
    assert norm("cpu 1 2 3") == "cpu 1 2 3"
    with pytest.raises(RuntimeError):
        norm("x" * (main_module._MAX_REMOTE_OUTPUT_CHARS + 1))


def test_bogus_interface_names_are_skipped(main_module):
    parse = main_module.MetricsCollector._parse_net_dev
    out = (
        "cpu 1 2 3 4 5 6 7\n"
        "Inter-|   Receive\n"
        " face |bytes\n"
        "=HYPERLINK(evil): " + " ".join(["9"] * 16) + "\n"
        "eth0: " + " ".join(["5"] * 16) + "\n"
    )
    iface, rx, tx = parse(out, None)
    assert iface == "eth0"


def test_csv_download_neutralises_formulas(main_module):
    cell = main_module._csv_cell
    assert cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert cell("+1234") == "+1234", "numbers stay numbers"
    assert cell("-0.5") == "-0.5"
    assert cell("eth0") == "eth0"
    assert cell("") == ""
    assert cell(3.5) == 3.5


@pytest.mark.parametrize("host", ["-fping", "--help", "a b", "x;y", ""])
def test_host_that_looks_like_an_option_is_refused(main_module, host):
    with pytest.raises(Exception):
        main_module.AddServerRequest(name="n", host=host, user="monitor")


@pytest.mark.parametrize(
    "host", ["10.0.0.1", "2001:db8::1", "srv-01.example.com", " host "],
)
def test_real_hosts_are_accepted(main_module, host):
    req = main_module.AddServerRequest(name="n", host=host, user="monitor")
    assert req.host == host.strip()


def test_save_config_keeps_the_token_private(main_module, tmp_path, monkeypatch):
    target = tmp_path / "servers.yaml"
    monkeypatch.setattr(main_module, "CONFIG_PATH", target)
    old_umask = os.umask(0o000)  # worst case: everything world-readable
    try:
        main_module.save_config(main_module.cfg)
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(tmp_path.glob(".*.tmp"))
