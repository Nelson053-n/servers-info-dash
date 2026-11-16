"""Telegram через SOCKS5: с RU2 прямой api.telegram.org недоступен."""
import io
import json

import pytest


class _FakeResponse:
    def __init__(self, payload):
        self._payload = json.dumps(payload).encode()

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def telegram(main_module, monkeypatch):
    m = main_module
    monkeypatch.setattr(m.cfg.bot, 'socks_proxy', '172.18.0.1:1080', raising=False)
    calls = []

    def direct(req, timeout=10):
        calls.append(req.full_url)
        return _FakeResponse({'ok': True, 'result': {'message_id': 1}})

    monkeypatch.setattr(m.urllib.request, 'urlopen', direct)
    return m, calls


def test_telegram_call_prefers_proxy_and_parses_result(telegram, monkeypatch):
    m, calls = telegram
    class FakeConn:
        def __init__(self, host, proxy, timeout=15):
            self.host, self.proxy = host, proxy

        def request(self, method, path, body=None, headers=None):
            self.path = path

        def getresponse(self):
            return _FakeResponse({'ok': True, 'result': {'username': 'bot'}})

        def close(self):
            pass

    monkeypatch.setattr(m, '_SocksHTTPSConnection', FakeConn)
    result = m._telegram_call('token', 'getMe', {})
    assert result == {'username': 'bot'}
    assert calls == []  # напрямую не ходили


def test_telegram_call_falls_back_to_direct(telegram, monkeypatch):
    m, calls = telegram

    class BrokenConn:
        def __init__(self, *a, **k):
            raise OSError('socks down')

    monkeypatch.setattr(m, '_SocksHTTPSConnection', BrokenConn)
    result = m._telegram_call('token', 'sendMessage', {'chat_id': '1', 'text': 'x'})
    assert result == {'message_id': 1}
    assert calls and 'api.telegram.org' in calls[0]


def test_send_telegram_reports_failure(main_module, monkeypatch):
    m = main_module
    monkeypatch.setattr(m, '_telegram_call', lambda *a, **k: (_ for _ in ()).throw(OSError('offline')))
    assert m._send_telegram('token', 'chat', 'text') is False


def test_send_telegram_reports_success(main_module, monkeypatch):
    m = main_module
    monkeypatch.setattr(m, '_telegram_call', lambda *a, **k: {'message_id': 5})
    assert m._send_telegram('token', 'chat', 'text') is True
