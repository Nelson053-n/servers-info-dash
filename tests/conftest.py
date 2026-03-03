from pathlib import Path

CONFIG_PATH = Path("config/servers.yaml")
EXAMPLE_PATH = Path("config/servers.example.yaml")

_created_temp_config = False

if not CONFIG_PATH.exists() and EXAMPLE_PATH.exists():
    CONFIG_PATH.write_text(
        EXAMPLE_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    _created_temp_config = True


def pytest_sessionfinish(session, exitstatus):
    if _created_temp_config and CONFIG_PATH.exists():
        CONFIG_PATH.unlink()