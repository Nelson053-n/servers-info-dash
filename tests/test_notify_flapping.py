"""A server going down must not look like its metrics recovered.

When a host drops, every metric comes back as None. The threshold checks
treat "no value" the same as "below the threshold", so the counters reset
and the alerts that were firing are reported as recovered — in the same
message that announces the outage.
"""
import asyncio


def _bot(main_module, **overrides):
    settings = {
        "enabled": True,
        "token": "123:AAA",
        "chat_id": "42",
        "notify_down": True,
        "notify_cpu_threshold": 90,
        "notify_delay": 1,
    }
    settings.update(overrides)
    return main_module.BotConfig(**settings)


def _up(name="srv", cpu=95.0):
    return {
        "name": name, "status": "up", "cpu_percent": cpu,
        "ping_ms": 10.0, "disk_free_gb": 50.0, "disk_total_gb": 100.0,
        "rx_mbps": 1.0, "tx_mbps": 1.0,
    }


def _down(name="srv"):
    return {
        "name": name, "status": "down", "cpu_percent": None,
        "ping_ms": None, "disk_free_gb": None, "disk_total_gb": None,
        "rx_mbps": None, "tx_mbps": None,
    }


def _capture(main_module, monkeypatch):
    sent = []
    monkeypatch.setattr(
        main_module, "_send_telegram",
        lambda token, chat_id, text: sent.append(text),
    )
    monkeypatch.setattr(main_module.cfg, "bot", _bot(main_module))
    main_module._notified_state.clear()
    main_module._trigger_counts.clear()
    return sent


def test_going_down_does_not_report_cpu_recovered(main_module, monkeypatch):
    sent = _capture(main_module, monkeypatch)

    asyncio.run(main_module._check_and_notify([_up()]))   # CPU alert fires
    sent.clear()
    asyncio.run(main_module._check_and_notify([_down()]))  # host drops

    body = "\n".join(sent)
    assert "DOWN" in body, f"outage not reported: {body!r}"
    assert "CPU" not in body or "OK" not in body, (
        f"claimed CPU recovered while the host is down: {body!r}"
    )


def test_recovery_is_reported_when_the_host_returns(main_module, monkeypatch):
    """The real recovery must still be announced."""
    sent = _capture(main_module, monkeypatch)

    asyncio.run(main_module._check_and_notify([_up()]))
    asyncio.run(main_module._check_and_notify([_down()]))
    sent.clear()
    asyncio.run(main_module._check_and_notify([_up(cpu=5.0)]))

    body = "\n".join(sent)
    assert "OK" in body or "✅" in body, (
        f"no recovery message after the host came back: {body!r}"
    )


def test_flapping_does_not_resend_the_same_alert(main_module, monkeypatch):
    """Repeated down cycles must not repeat the outage message."""
    sent = _capture(main_module, monkeypatch)

    asyncio.run(main_module._check_and_notify([_down()]))
    first = len(sent)
    asyncio.run(main_module._check_and_notify([_down()]))
    asyncio.run(main_module._check_and_notify([_down()]))

    assert len(sent) == first, (
        f"outage repeated on every cycle: {sent!r}"
    )
