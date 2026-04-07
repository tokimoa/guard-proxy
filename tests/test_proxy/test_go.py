"""Tests for Go module proxy."""

import io
import zipfile
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.proxy.go import GoProxy
from app.registry.go_client import GoRegistryClient
from app.schemas.decision import DecisionResult
from app.schemas.scan import ScanResult


def _make_settings() -> Settings:
    return Settings()


def _make_decision(verdict: str = "allow", score: float = 0.1) -> DecisionResult:
    return DecisionResult(
        verdict=verdict,
        final_score=score,
        scan_results=[ScanResult(scanner_name="test", verdict="pass", confidence=0.9, details="ok")],
        reason="test",
        mode="warn",
    )


def _make_go_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("example.com/mod@v1.0.0/main.go", 'package main\nimport "fmt"\nfunc main() { fmt.Println("hi") }')
        zf.writestr("example.com/mod@v1.0.0/go.mod", "module example.com/mod\n\ngo 1.21\n")
    return buf.getvalue()


def _make_proxy(cache=None, audit=None, notification=None):
    settings = _make_settings()
    registry = MagicMock(spec=GoRegistryClient)
    registry.download_zip = AsyncMock(return_value=_make_go_zip())
    registry._client = AsyncMock()
    registry.upstream_url = "https://proxy.golang.org"

    pipeline = AsyncMock()
    pipeline.run = AsyncMock(
        return_value=[ScanResult(scanner_name="test", verdict="pass", confidence=0.9, details="ok")]
    )

    engine = MagicMock(spec=DecisionEngine)
    engine.decide = MagicMock(return_value=_make_decision())

    return GoProxy(
        settings=settings,
        registry_client=registry,
        scan_pipeline=pipeline,
        decision_engine=engine,
        cache_service=cache,
        audit_service=audit,
        notification_service=notification,
    )


class TestGoProxyZipDownload:
    async def test_scan_and_allow(self):
        proxy = _make_proxy()
        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        response = await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        assert response.status_code == 200
        assert response.media_type == "application/zip"

    async def test_deny_in_enforce_mode(self):
        proxy = _make_proxy()
        proxy._engine.decide.return_value = _make_decision("deny", 0.9).model_copy(update={"mode": "enforce"})

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        from app.core.exceptions import PackageBlockedError

        with pytest.raises(PackageBlockedError):
            await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")

    async def test_cache_hit_returns_without_scanning(self):
        cache = AsyncMock()
        cache.get = AsyncMock(return_value=_make_decision())
        proxy = _make_proxy(cache=cache)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        response = await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        assert response.status_code == 200
        # Pipeline should not have been called since cache hit
        proxy._pipeline.run.assert_not_called()

    async def test_cache_miss_runs_pipeline(self):
        cache = AsyncMock()
        cache.get = AsyncMock(return_value=None)
        cache.put = AsyncMock()
        proxy = _make_proxy(cache=cache)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        response = await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        assert response.status_code == 200
        proxy._pipeline.run.assert_called_once()
        cache.put.assert_called_once()

    async def test_quarantine_warns_but_serves(self):
        proxy = _make_proxy()
        proxy._engine.decide.return_value = _make_decision("quarantine", 0.5)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        response = await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        assert response.status_code == 200

    async def test_audit_logged(self):
        audit = AsyncMock()
        audit.log_decision = AsyncMock()
        proxy = _make_proxy(audit=audit)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        audit.log_decision.assert_called_once()
        assert audit.log_decision.call_args[0][0] == "go"

    async def test_notification_called_on_deny(self):
        notification = AsyncMock()
        notification.notify_decision = AsyncMock()
        proxy = _make_proxy(notification=notification)
        proxy._engine.decide.return_value = _make_decision("deny", 0.9)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/v1.0.0.zip"

        await proxy.handle_zip_download(request, "example.com/mod", "v1.0.0")
        notification.notify_decision.assert_called_once()


class TestGoProxyPassthrough:
    async def test_passthrough_forwards_request(self):
        proxy = _make_proxy()
        mock_response = MagicMock()
        mock_response.content = b"v1.0.0\nv1.1.0\n"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/plain"}
        proxy._registry.forward_request = AsyncMock(return_value=mock_response)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@v/list"

        response = await proxy.handle_passthrough(request, "example.com/mod")
        assert response.status_code == 200
        assert response.body == b"v1.0.0\nv1.1.0\n"

    async def test_passthrough_handles_upstream_error(self):
        proxy = _make_proxy()
        proxy._registry.forward_request = AsyncMock(side_effect=Exception("connection refused"))

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/example.com/mod/@latest"

        response = await proxy.handle_passthrough(request, "example.com/mod")
        assert response.status_code == 502

    async def test_passthrough_encodes_module_path(self):
        proxy = _make_proxy()
        mock_response = MagicMock()
        mock_response.content = b"{}"
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "application/json"}
        proxy._registry.forward_request = AsyncMock(return_value=mock_response)

        request = MagicMock()
        request.url = MagicMock()
        request.url.path = "/github.com/Azure/azure-sdk/@latest"

        await proxy.handle_passthrough(request, "github.com/Azure/azure-sdk")
        call_path = proxy._registry.forward_request.call_args[0][0]
        assert "!azure" in call_path
