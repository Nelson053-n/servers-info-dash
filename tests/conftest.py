"""Make app.main importable in tests.

app.main calls load_config() at module level and refuses to start without
config/servers.yaml, which is gitignored. That is why the older tests
grep the source instead of importing it. This shim creates the config
from the committed example when it is absent, so tests can import the
module and check real behaviour, then removes it again.

An existing config/servers.yaml is never touched.
"""
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_CONFIG = REPO_ROOT / "config" / "servers.yaml"
_EXAMPLE = REPO_ROOT / "config" / "servers.example.yaml"
_MARKER = REPO_ROOT / "config" / ".servers.yaml.pytest"


@pytest.fixture(scope="session")
def main_module(tmp_path_factory):
    """Import app.main against a throwaway config and auth file.

    A crash (SIGKILL, OOM) skips the cleanup below, so the marker file
    records that the config is ours to remove on the next run — without
    it an orphan looks like the developer's real config forever.
    """
    created = False
    if not _CONFIG.exists() or _MARKER.exists():
        shutil.copy(_EXAMPLE, _CONFIG)
        _MARKER.write_text("written by the test suite\n", encoding="utf-8")
        created = True

    try:
        import app.main as module
    except Exception:
        if created:
            _CONFIG.unlink(missing_ok=True)
            _MARKER.unlink(missing_ok=True)
        raise

    # Auth state is written on password changes and failed logins; keep
    # every test off the real config/auth.yaml.
    module._AUTH_PATH = tmp_path_factory.mktemp("auth") / "auth.yaml"
    try:
        yield module
    finally:
        if created:
            _CONFIG.unlink(missing_ok=True)
            _MARKER.unlink(missing_ok=True)
