"""bot.enabled=false must stop getUpdates polling (two instances sharing one token got 409 from each other)."""
import asyncio

import pytest


@pytest.fixture
def poller(main_module, monkeypatch):
    calls = []

    class Stop(Exception):
        pass

    def fake_api(token, method, payload=None, timeout=10):
        calls.append(method)
        raise Stop          # прерываем после первого запроса: настоящий опрос крутится бесконечно

    async def fake_sleep(_seconds):
        raise Stop

    monkeypatch.setattr(main_module, "_tg_api", fake_api)
    monkeypatch.setattr(main_module.asyncio, "sleep", fake_sleep)

    def run():
        try:
            asyncio.run(asyncio.wait_for(main_module._telegram_callback_poller(), 5))
        except Stop:
            pass
        return calls

    return main_module, run


def _configure(m, monkeypatch, enabled):
    monkeypatch.setattr(m.cfg.bot, "token", "123:abc")
    monkeypatch.setattr(m.cfg.bot, "chat_id", "-1")
    monkeypatch.setattr(m.cfg.bot, "enabled", enabled)


def test_disabled_bot_does_not_poll(poller, monkeypatch):
    m, run = poller
    _configure(m, monkeypatch, False)
    assert run() == []


def test_enabled_bot_polls(poller, monkeypatch):
    m, run = poller
    _configure(m, monkeypatch, True)
    assert run() == ["getUpdates"]
