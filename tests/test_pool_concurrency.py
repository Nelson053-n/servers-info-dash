"""Persistent SSH connections must be established in parallel.

A single lock held across asyncssh.connect() serialises every server, so
asyncio.gather buys nothing: with slow connects the cycle takes
servers x connect_timeout. That pushes /api/health past its staleness
window and makes the health-gated deploy roll back a healthy commit.
"""
import asyncio


def _run(coro):
    return asyncio.run(coro)


def test_connections_are_not_serialised(main_module, monkeypatch):
    CONNECT_DELAY = 0.4
    SERVERS = 5
    in_flight = 0
    peak = 0

    class _FakeConn:
        async def run(self, *a, **kw):
            return None

        def close(self):
            pass

        async def wait_closed(self):
            return None

    async def _slow_connect(**kwargs):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        try:
            await asyncio.sleep(CONNECT_DELAY)
            return _FakeConn()
        finally:
            in_flight -= 1

    monkeypatch.setattr(main_module.asyncssh, "connect", _slow_connect)
    collector = main_module.MetricsCollector(main_module.cfg)
    monkeypatch.setattr(
        collector, "_resolve_client_keys", lambda server: [],
    )

    servers = [
        main_module.ServerConfig(
            name=f"srv{i}", host=f"10.0.0.{i}", user="monitor",
        )
        for i in range(SERVERS)
    ]

    async def _drive():
        started = asyncio.get_running_loop().time()
        await asyncio.gather(
            *(collector._get_connection(s) for s in servers)
        )
        return asyncio.get_running_loop().time() - started

    elapsed = _run(_drive())

    assert peak > 1, (
        f"connects ran one at a time (peak concurrency {peak})"
    )
    assert elapsed < CONNECT_DELAY * SERVERS * 0.6, (
        f"took {elapsed:.2f}s, close to the serialised "
        f"{CONNECT_DELAY * SERVERS:.2f}s"
    )


def test_one_connection_per_server_is_reused(main_module, monkeypatch):
    """Dropping the global lock must not create duplicate connections."""
    connects = 0

    class _FakeConn:
        async def run(self, *a, **kw):
            return None

        def close(self):
            pass

        async def wait_closed(self):
            return None

    async def _count_connect(**kwargs):
        nonlocal connects
        connects += 1
        await asyncio.sleep(0.05)
        return _FakeConn()

    monkeypatch.setattr(main_module.asyncssh, "connect", _count_connect)
    collector = main_module.MetricsCollector(main_module.cfg)
    monkeypatch.setattr(
        collector, "_resolve_client_keys", lambda server: [],
    )
    server = main_module.ServerConfig(
        name="srv", host="10.0.0.1", user="monitor",
    )

    async def _drive():
        # Ten concurrent callers for the same server must share one.
        conns = await asyncio.gather(
            *(collector._get_connection(server) for _ in range(10))
        )
        return conns

    conns = _run(_drive())

    assert connects == 1, f"opened {connects} connections for one server"
    assert len({id(c) for c in conns}) == 1, "callers got different objects"
