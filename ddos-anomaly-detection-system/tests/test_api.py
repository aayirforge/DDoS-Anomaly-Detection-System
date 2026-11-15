"""Tests for FastAPI service and HTTP 503 missing-model guard."""

from fastapi.testclient import TestClient
import pytest
from ddos_ads.api import create_app


def test_api_health_check() -> None:
    """Verify /health endpoint responds with 200 and system details."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "models_ready" in data


def test_api_score_returns_503_when_models_missing() -> None:
    """
    CRITICAL ACCEPTANCE CRITERIA:
    When models are missing, /score MUST return HTTP 503 with 'Models not found. Run: make train'.
    """
    from unittest.mock import patch
    with patch("ddos_ads.api.check_models_exist", return_value=False):
        app = create_app()
        client = TestClient(app)

        sample_flow = {
            "Source IP": "192.168.1.100",
            "Destination IP": "10.0.0.1",
            "Source Port": 45678,
            "Destination Port": 80,
            "Protocol": 6,
            "Total Fwd Packets": 10,
            "Flow Duration": 5000,
        }

        response = client.post("/score", json={"model": "rf", "flows": [sample_flow]})
        assert response.status_code == 503
        assert "Models not found. Run: make train" in response.json()["detail"]


def test_api_score_invalid_model_returns_400() -> None:
    """Verify selecting an unknown model returns HTTP 400."""
    app = create_app()
    client = TestClient(app)

    response = client.post("/score", json={"model": "non_existent_model", "flows": []})
    assert response.status_code == 400


def test_api_alerts_endpoint() -> None:
    """Verify /alerts returns 200 and a list of detections."""
    app = create_app()
    client = TestClient(app)

    response = client.get("/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
