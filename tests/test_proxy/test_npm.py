"""Tests for npm proxy."""

from datetime import UTC
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.proxy.npm import NpmProxy
from app.registry.npm_client import NpmRegistryClient
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.static_analysis import StaticAnalysisScanner
from app.schemas.package import NpmDistInfo, NpmPackageMetadata


@pytest.fixture
def npm_proxy(settings: Settings) -> NpmProxy:
    registry_client = NpmRegistryClient(settings)
    pipeline = ScanPipeline([CooldownScanner(settings), StaticAnalysisScanner(settings)])
    engine = DecisionEngine(settings)
    return NpmProxy(settings, registry_client, pipeline, engine)


@pytest.fixture
def app(npm_proxy: NpmProxy) -> FastAPI:
    app = FastAPI()
    app.include_router(npm_proxy.get_router())
    return app


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_metadata_passthrough_with_url_rewrite(
    client: TestClient,
    npm_proxy: NpmProxy,
    npm_registry_metadata: dict,
) -> None:
    with patch.object(
        npm_proxy._registry,
        "get_package_metadata",
        new_callable=AsyncMock,
        return_value=npm_registry_metadata,
    ):
        response = client.get("/test-package")

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "test-package"

    # Verify tarball URLs were rewritten to proxy
    for ver_data in data["versions"].values():
        tarball_url = ver_data["dist"]["tarball"]
        assert "registry.npmjs.org" not in tarball_url
        assert "testserver" in tarball_url or "localhost" in tarball_url


def test_tarball_scan_allow(
    client: TestClient,
    npm_proxy: NpmProxy,
    safe_tarball: bytes,
) -> None:
    mock_meta = NpmPackageMetadata(
        name="safe-package",
        version="1.0.0",
        publish_date=None,
        dist=NpmDistInfo(tarball="https://registry.npmjs.org/safe-package/-/safe-package-1.0.0.tgz", shasum="abc"),
        install_scripts={},
    )
    with (
        patch.object(
            npm_proxy._registry,
            "get_version_metadata",
            new_callable=AsyncMock,
            return_value=mock_meta,
        ),
        patch.object(
            npm_proxy._registry,
            "download_tarball",
            new_callable=AsyncMock,
            return_value=safe_tarball,
        ),
    ):
        response = client.get("/safe-package/-/safe-package-1.0.0.tgz")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"


def test_tarball_scan_block_enforce_mode(
    safe_tarball: bytes,
    malicious_tarball: bytes,
) -> None:
    """In enforce mode with malicious content, should return 403."""
    settings = Settings(decision_mode="enforce", cooldown_action="deny", cooldown_days=7)
    registry_client = NpmRegistryClient(settings)
    pipeline = ScanPipeline([CooldownScanner(settings), StaticAnalysisScanner(settings)])
    engine = DecisionEngine(settings)
    proxy = NpmProxy(settings, registry_client, pipeline, engine)

    from app.core.exception_handlers import package_blocked_handler
    from app.core.exceptions import PackageBlockedError

    app = FastAPI()
    app.include_router(proxy.get_router())
    app.add_exception_handler(PackageBlockedError, package_blocked_handler)  # type: ignore[arg-type]

    from datetime import datetime, timedelta

    mock_meta = NpmPackageMetadata(
        name="evil-package",
        version="1.0.0",
        publish_date=datetime.now(UTC) - timedelta(seconds=10),
        dist=NpmDistInfo(tarball="https://registry.npmjs.org/evil-package/-/evil-package-1.0.0.tgz", shasum="abc"),
        install_scripts={"postinstall": "node scripts/setup.js"},
    )

    client = TestClient(app)
    with (
        patch.object(proxy._registry, "get_version_metadata", new_callable=AsyncMock, return_value=mock_meta),
        patch.object(proxy._registry, "download_tarball", new_callable=AsyncMock, return_value=malicious_tarball),
    ):
        response = client.get("/evil-package/-/evil-package-1.0.0.tgz")

    assert response.status_code == 403
    data = response.json()
    assert data["error"] == "package_blocked"


def test_version_extraction() -> None:
    assert NpmProxy._extract_version_from_tarball("express", "express-4.18.2.tgz") == "4.18.2"
    assert NpmProxy._extract_version_from_tarball("lodash", "lodash-4.17.21.tgz") == "4.17.21"


def test_version_extraction_scoped() -> None:
    # For scoped packages, tarball name doesn't include scope
    assert NpmProxy._extract_version_from_tarball("types__node", "types__node-20.0.0.tgz") == "20.0.0"
