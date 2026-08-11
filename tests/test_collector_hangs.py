"""The collector loop must survive a hang, not just an exception.

_background_collector wraps its body in try/except, which catches a
failing cycle but does nothing for one that never returns: the await
simply never completes, asyncio.sleep is never reached, and metrics
freeze until the service is restarted.
"""
import asyncio


def _run(coro):
    """Drive a coroutine without pulling in a pytest async plugin."""
    return asyncio.run(coro)


def test_ping_gives_up_on_a_hanging_process(main_module, monkeypatch):
    """A ping that never exits must not stall the cycle forever."""

    class _NeverExits:
        returncode = None

        async def communicate(self):
            await asyncio.sleep(3600)  # resolver wedged, no output ever

        def kill(self):
            self.killed = True

        async def wait(self):
            return 0

    async def _fake_exec(*args, **kwargs):
        return _NeverExits()

    monkeypatch.setattr(
        asyncio, "create_subprocess_exec", _fake_exec,
    )
    collector = main_module.MetricsCollector(main_module.cfg)

    async def _drive():
        return await asyncio.wait_for(collector._ping("10.0.0.1"), timeout=15)

    result = _run(_drive())

    assert result is None, "a hung ping must report no latency, not hang"


def test_ping_still_parses_a_normal_reply(main_module, monkeypatch):
    """The timeout must not break the ordinary path."""

    class _Ok:
        returncode = 0

        async def communicate(self):
            return (b"64 bytes from 10.0.0.1: time=12.3 ms\n", b"")

    async def _fake_exec(*args, **kwargs):
        return _Ok()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)
    collector = main_module.MetricsCollector(main_module.cfg)

    assert _run(collector._ping("10.0.0.1")) == 12.3


def test_collector_cycle_recovers_from_a_hang(main_module, monkeypatch):
    """One stuck cycle must not end the loop."""
    calls = []

    async def _hangs_once():
        calls.append(1)
        if len(calls) == 1:
            await asyncio.sleep(3600)
        return {"servers": [], "generated_at": "", "ready": True}

    monkeypatch.setattr(main_module.collector, "collect_all", _hangs_once)
    monkeypatch.setattr(main_module.cfg, "refresh_interval_sec", 1)
    monkeypatch.setattr(main_module, "_CYCLE_TIMEOUT_CYCLES", 1)

    async def _drive():
        task = asyncio.create_task(main_module._background_collector())
        try:
            # Long enough for the first cycle to be abandoned and a
            # second to start, but far below the 3600s hang.
            await asyncio.sleep(6)
        finally:
            task.cancel()

    _run(_drive())

    assert len(calls) >= 2, (
        f"loop did not recover from a hung cycle (cycles: {len(calls)})"
    )
