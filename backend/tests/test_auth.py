"""BACKEND_API_KEY is unset in the test environment (see conftest.py), so every
other test exercises the default "auth disabled" path implicitly. These tests
cover the gate itself by toggling the setting directly on the shared instance
for the duration of one test — monkeypatch restores it afterward."""

from app.auth import settings


def test_api_open_by_default(client):
    assert settings.backend_api_key == ""
    response = client.get("/api/cases")
    assert response.status_code == 200


def test_health_never_requires_a_key(client, monkeypatch):
    monkeypatch.setattr(settings, "backend_api_key", "secret123")
    assert client.get("/health").status_code == 200


def test_protected_route_rejects_missing_key(client, monkeypatch):
    monkeypatch.setattr(settings, "backend_api_key", "secret123")
    response = client.get("/api/cases")
    assert response.status_code == 401


def test_protected_route_rejects_wrong_key(client, monkeypatch):
    monkeypatch.setattr(settings, "backend_api_key", "secret123")
    response = client.get("/api/cases", headers={"X-API-Key": "wrong"})
    assert response.status_code == 401


def test_protected_route_accepts_correct_key(client, monkeypatch):
    monkeypatch.setattr(settings, "backend_api_key", "secret123")
    response = client.get("/api/cases", headers={"X-API-Key": "secret123"})
    assert response.status_code == 200
