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


@pytest.fixture(scope="session")
def main_module():
    """Import app.main against a config, cleaning up a temporary one."""
    created = False
    if not _CONFIG.exists():
        shutil.copy(_EXAMPLE, _CONFIG)
        created = True

    try:
        import app.main as module
        yield module
    finally:
        if created:
            _CONFIG.unlink(missing_ok=True)
