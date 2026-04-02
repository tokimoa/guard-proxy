"""Tests for npm registry client."""

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError
from app.registry.npm_client import NpmRegistryClient


@pytest.fixture
def client(settings: Settings) -> NpmRegistryClient:
    return NpmRegistryClient(settings)


@pytest.fixture
def mock_response(npm_registry_metadata: dict) -> httpx.Response:
    return httpx.Response(200, json=npm_registry_metadata)


async def test_get_package_metadata(client: NpmRegistryClient, mock_response: httpx.Response) -> None:
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_response):
        data = await client.get_package_metadata("test-package")
    assert data["name"] == "test-package"
    assert "1.0.0" in data["versions"]


async def test_get_version_metadata(
    client: NpmRegistryClient,
    npm_registry_metadata: dict,
) -> None:
    mock_resp = httpx.Response(200, json=npm_registry_metadata)
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        meta = await client.get_version_metadata("test-package", "1.0.0")
    assert meta.name == "test-package"
    assert meta.version == "1.0.0"
    assert meta.publish_date is not None
    assert meta.publish_date.year == 2025
    assert meta.dist is not None
    assert "test-package-1.0.0.tgz" in meta.dist.tarball


async def test_version_not_found(client: NpmRegistryClient, npm_registry_metadata: dict) -> None:
    mock_resp = httpx.Response(200, json=npm_registry_metadata)
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        with pytest.raises(PackageNotFoundError):
            await client.get_version_metadata("test-package", "99.99.99")


async def test_package_not_found_404(client: NpmRegistryClient) -> None:
    mock_resp = httpx.Response(404, text="Not Found")
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        with pytest.raises(PackageNotFoundError):
            await client.get_package_metadata("nonexistent-pkg")


async def test_upstream_error_500(client: NpmRegistryClient) -> None:
    mock_resp = httpx.Response(500, text="Internal Server Error")
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        with pytest.raises(UpstreamRegistryError):
            await client.get_package_metadata("test-package")


async def test_extract_publish_date() -> None:
    metadata = {"time": {"1.0.0": "2025-06-01T12:00:00.000Z"}}
    date = NpmRegistryClient._extract_publish_date(metadata, "1.0.0")
    assert date is not None
    assert date.year == 2025
    assert date.month == 6


async def test_extract_publish_date_missing() -> None:
    date = NpmRegistryClient._extract_publish_date({}, "1.0.0")
    assert date is None


async def test_extract_install_scripts() -> None:
    version_data = {
        "scripts": {
            "test": "jest",
            "postinstall": "node setup.js",
            "build": "tsc",
        }
    }
    scripts = NpmRegistryClient._extract_install_scripts(version_data)
    assert scripts == {"postinstall": "node setup.js"}
    assert "test" not in scripts
    assert "build" not in scripts


async def test_close(client: NpmRegistryClient) -> None:
    with patch.object(client._client, "aclose", new_callable=AsyncMock) as mock_close:
        await client.close()
    mock_close.assert_called_once()
