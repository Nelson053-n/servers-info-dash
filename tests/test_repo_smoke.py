from pathlib import Path

import yaml


def test_example_config_required_keys_present():
    path = Path("config/servers.example.yaml")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert "refresh_interval_sec" in data
    assert "ssh" in data
    assert "servers" in data
    assert isinstance(data["servers"], list)


def test_static_index_exists():
    assert Path("app/static/index.html").exists()


def test_main_has_fastapi_app_declaration():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert "app = FastAPI(" in source