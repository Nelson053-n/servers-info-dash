"""Cached readings served during an SSH failure must be marked as such.

collect_server falls back to the last good snapshot for up to five
cycles. That snapshot said status "up" and carried the old rx/tx rates,
so the logs recorded traffic that never happened and the UI showed a
failing host as healthy.
"""
import asyncio


def _server(main_module):
    return main_module.ServerConfig(
        name="srv", host="10.0.0.1", user="monitor",
    )


def _seed_cache(collector, name):
    collector._last_good[name] = {
        "name": name, "host": "10.0.0.1", "status": "up",
        "cpu_percent": 20.0, "rx_mbps": 5.0, "tx_mbps": 7.0,
        "ping_ms": 1.0, "error": None,
    }


def test_cached_result_is_a_copy(main_module, monkeypatch):
    """Callers mutate the result; the cache must not follow."""
    collector = main_module.MetricsCollector(main_module.cfg)
    _seed_cache(collector, "srv")

    async def _boom(*a, **kw):
        raise OSError("ssh down")

    async def _no_ping(server):
        return None

    monkeypatch.setattr(collector, "_run_ssh_command", _boom)
    monkeypatch.setattr(collector, "_get_ping", _no_ping)

    result = asyncio.run(collector.collect_server(_server(main_module)))
    result["traffic_30d_gb"] = 999

    assert "traffic_30d_gb" not in collector._last_good["srv"], (
        "the cache was mutated through the returned object"
    )


def test_cached_result_does_not_claim_live_traffic(
    main_module, monkeypatch,
):
    """Old rates must not be logged as if measured this cycle."""
    collector = main_module.MetricsCollector(main_module.cfg)
    _seed_cache(collector, "srv")

    async def _boom(*a, **kw):
        raise OSError("ssh down")

    async def _no_ping(server):
        return None

    monkeypatch.setattr(collector, "_run_ssh_command", _boom)
    monkeypatch.setattr(collector, "_get_ping", _no_ping)

    result = asyncio.run(collector.collect_server(_server(main_module)))

    assert result.get("rx_mbps") in (None, 0, 0.0), (
        f"stale rx rate served as current: {result.get('rx_mbps')}"
    )
    assert result.get("tx_mbps") in (None, 0, 0.0), (
        f"stale tx rate served as current: {result.get('tx_mbps')}"
    )


def test_cached_result_is_flagged(main_module, monkeypatch):
    """The UI and the CSV need to be able to tell this apart from live."""
    collector = main_module.MetricsCollector(main_module.cfg)
    _seed_cache(collector, "srv")

    async def _boom(*a, **kw):
        raise OSError("ssh down")

    async def _no_ping(server):
        return None

    monkeypatch.setattr(collector, "_run_ssh_command", _boom)
    monkeypatch.setattr(collector, "_get_ping", _no_ping)

    result = asyncio.run(collector.collect_server(_server(main_module)))

    assert result.get("stale") is True, "cached reading not flagged"
