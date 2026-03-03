from fastapi.testclient import TestClient

from app.main import app


def test_root_page_is_available():
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")