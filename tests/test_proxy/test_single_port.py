"""Tests for multi-registry single-port routing via path prefixes."""

from unittest.mock import MagicMock

from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient


def _make_mock_proxy(registry_name: str):
    """Create a mock proxy with a simple GET endpoint."""
    router = APIRouter()

    @router.get("/test-endpoint")
    async def test_route():
        return {"registry": registry_name}

    mock = MagicMock()
    mock.get_router.return_value = router
    return mock


def test_prefixed_npm_route():
    app = FastAPI()
    proxy = _make_mock_proxy("npm")
    app.include_router(proxy.get_router(), prefix="/npm")

    client = TestClient(app)
    resp = client.get("/npm/test-endpoint")
    assert resp.status_code == 200
    assert resp.json()["registry"] == "npm"


def test_prefixed_pypi_route():
    app = FastAPI()
    proxy = _make_mock_proxy("pypi")
    app.include_router(proxy.get_router(), prefix="/pypi")

    client = TestClient(app)
    resp = client.get("/pypi/test-endpoint")
    assert resp.status_code == 200
    assert resp.json()["registry"] == "pypi"


def test_prefixed_gems_route():
    app = FastAPI()
    proxy = _make_mock_proxy("rubygems")
    app.include_router(proxy.get_router(), prefix="/gems")

    client = TestClient(app)
    resp = client.get("/gems/test-endpoint")
    assert resp.status_code == 200
    assert resp.json()["registry"] == "rubygems"


def test_prefixed_go_route():
    app = FastAPI()
    proxy = _make_mock_proxy("go")
    app.include_router(proxy.get_router(), prefix="/go")

    client = TestClient(app)
    resp = client.get("/go/test-endpoint")
    assert resp.status_code == 200
    assert resp.json()["registry"] == "go"


def test_legacy_non_prefixed_still_works():
    """Backward compatibility: non-prefixed routes still respond."""
    app = FastAPI()
    proxy = _make_mock_proxy("npm")
    app.include_router(proxy.get_router(), prefix="/npm")
    app.include_router(proxy.get_router())  # legacy

    client = TestClient(app)
    # Both should work
    assert client.get("/npm/test-endpoint").status_code == 200
    assert client.get("/test-endpoint").status_code == 200


def test_prefixed_route_404_without_prefix():
    """Prefixed-only route should not respond at root."""
    app = FastAPI()
    proxy = _make_mock_proxy("npm")
    app.include_router(proxy.get_router(), prefix="/npm")

    client = TestClient(app)
    resp = client.get("/test-endpoint")
    assert resp.status_code == 404
