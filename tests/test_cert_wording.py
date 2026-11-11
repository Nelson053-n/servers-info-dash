import datetime as dt
import importlib.util

import pytest


@pytest.fixture(scope="module")
def projects():
    spec = importlib.util.spec_from_file_location("projects_cert", "app/projects.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _project(projects, check=None, tls=None):
    return {"id": "t", "name": "t", "stage": "", "link": "https://e/", "check": check, "tls": tls}


def test_expired_certificate_is_not_reported_as_dead_site(projects):
    state, issues = projects._state_of(_project(projects, check={
        "http": None, "ms": 33,
        "error": "URLError: <urlopen error [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired (_ssl.c:1010)>",
        "valid": True, "scope": "site", "slow_streak": 0,
    }, tls={"host": "e", "expires": None, "days_left": None, "fail_streak": 3,
            "error": "SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired"}))
    texts = [i["text"] for i in issues]
    assert state == "bad"
    assert "сертификат истёк — браузеры блокируют сайт" in texts
    assert "сайт не отвечает" not in texts


def test_network_failure_still_reports_site_down(projects):
    state, issues = projects._state_of(_project(projects, check={
        "http": None, "ms": 5000, "error": "URLError: <urlopen error [Errno 111] Connection refused>",
        "valid": True, "scope": "site", "slow_streak": 0,
    }))
    assert state == "bad"
    assert [i["text"] for i in issues] == ["сайт не отвечает"]


def test_other_tls_error_keeps_generic_wording(projects):
    state, issues = projects._state_of(_project(projects, tls={
        "host": "e", "expires": None, "days_left": None, "fail_streak": 3,
        "error": "TimeoutError: handshake timed out"}))
    assert state == "bad"
    assert [i["text"] for i in issues] == ["сертификат не проверяется"]
