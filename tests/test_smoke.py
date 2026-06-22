"""Smoke test ensuring the app factory wires up (not a security test)."""
from vulnapp.app import create_app


def test_app_boots():
    app = create_app()
    client = app.test_client()
    assert client.get("/health").status_code == 200
