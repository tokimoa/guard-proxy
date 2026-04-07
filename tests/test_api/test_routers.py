"""Tests for API routers (health, cache, config, metrics, audit, sbom)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routers.audit import router as audit_router
from app.api.routers.cache import router as cache_router
from app.api.routers.config import router as config_router
from app.api.routers.health import router as health_router
from app.api.routers.metrics import router as metrics_router
from app.api.routers.sbom import router as sbom_router
from app.core.version import VERSION


@pytest.fixture
def mock_cache_service():
    svc = AsyncMock()
    svc.stats.return_value = {"entries": 42, "size_mb": 1.5}
    svc.clear.return_value = 42
    svc.evict_expired.return_value = 3
    return svc


@pytest.fixture
def mock_audit_service():
    svc = AsyncMock()
    svc.recent.return_value = [
        {"package": "express", "verdict": "allow", "timestamp": "2026-04-03T00:00:00Z"},
    ]
    return svc


@pytest.fixture
def mock_settings():
    settings = MagicMock()
    settings.model_dump.return_value = {
        "app_name": "Guard Proxy",
        "debug": False,
        "llm_enabled": True,
        "anthropic_api_key": "sk-ant-api03-abcdefghij",
        "openai_api_key": "",
        "custom_llm_api_key": "custom-key-12345",
    }
    return settings


@pytest.fixture
def app(mock_cache_service, mock_audit_service, mock_settings):
    app = FastAPI()
    app.state.cache_service = mock_cache_service
    app.state.audit_service = mock_audit_service
    app.state.settings = mock_settings
    app.include_router(health_router)
    app.include_router(cache_router)
    app.include_router(config_router)
    app.include_router(metrics_router)
    app.include_router(audit_router)
    app.include_router(sbom_router)
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


# --- Health ---


class TestHealthRouter:
    def test_health_returns_ok(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == VERSION


# --- Cache ---


class TestCacheRouter:
    def test_cache_stats(self, client, mock_cache_service):
        resp = client.get("/cache")
        assert resp.status_code == 200
        assert resp.json() == {"entries": 42, "size_mb": 1.5}
        mock_cache_service.stats.assert_awaited_once()

    def test_clear_cache(self, client, mock_cache_service):
        resp = client.delete("/cache")
        assert resp.status_code == 200
        assert resp.json() == {"cleared": 42}
        mock_cache_service.clear.assert_awaited_once()

    def test_evict_expired(self, client, mock_cache_service):
        resp = client.post("/cache/evict")
        assert resp.status_code == 200
        assert resp.json() == {"evicted": 3}
        mock_cache_service.evict_expired.assert_awaited_once()


# --- Config ---


class TestConfigRouter:
    def test_show_config_redacts_secrets(self, client):
        resp = client.get("/config")
        assert resp.status_code == 200
        data = resp.json()
        # API key should be fully redacted
        assert data["anthropic_api_key"] == "****"
        # Empty key stays empty
        assert data["openai_api_key"] == ""
        # Custom key should be fully redacted
        assert data["custom_llm_api_key"] == "****"
        # Non-sensitive values preserved
        assert data["app_name"] == "Guard Proxy"


# --- Metrics ---


class TestMetricsRouter:
    def test_metrics_returns_prometheus_format(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        text = resp.text
        assert "guard_proxy_uptime_seconds" in text
        assert "guard_proxy_requests_total" in text
        assert "guard_proxy_scans_total" in text
        assert 'guard_proxy_scan_verdicts_total{verdict="allow"}' in text
        assert 'guard_proxy_cache_total{result="hit"}' in text


# --- Audit ---


class TestAuditRouter:
    def test_recent_audit(self, client, mock_audit_service):
        resp = client.get("/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["package"] == "express"
        mock_audit_service.recent.assert_awaited_once_with(limit=50)

    def test_recent_audit_with_limit(self, client, mock_audit_service):
        resp = client.get("/audit?limit=5")
        assert resp.status_code == 200
        mock_audit_service.recent.assert_awaited_once_with(limit=5)


# --- SBOM ---


class TestSbomRouter:
    def test_recent_sboms(self, client, mock_audit_service):
        resp = client.get("/sbom/recent")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        mock_audit_service.recent.assert_awaited_once_with(limit=10)

    def test_recent_sboms_with_limit(self, client, mock_audit_service):
        resp = client.get("/sbom/recent?limit=25")
        assert resp.status_code == 200
        mock_audit_service.recent.assert_awaited_once_with(limit=25)
