from pathlib import Path
import hashlib

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


def test_ui_uses_matching_stylesheet_content_version():
    static = Path("app/static")
    version = hashlib.sha256((static / "shell.css").read_bytes()).hexdigest()[:12]
    url = f"/static/shell.css?v={version}"
    assert f'href="{url}"' in (static / "index.html").read_text()
    assert f'const requiredStyle = "{url}"' in (static / "views.js").read_text()


def test_main_has_fastapi_app_declaration():
    source = Path("app/main.py").read_text(encoding="utf-8")
    assert "app = FastAPI(" in source
