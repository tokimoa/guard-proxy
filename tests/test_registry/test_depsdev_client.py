"""Tests for deps.dev API client."""

from unittest.mock import AsyncMock, patch

import httpx

from app.registry.depsdev_client import DepsDevClient


async def test_get_version_info_success():
    client = DepsDevClient()
    mock_resp = httpx.Response(200, json={"versionKey": {"system": "npm", "name": "express", "version": "4.21.2"}})
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.get_version_info("npm", "express", "4.21.2")
    assert result is not None
    assert result["versionKey"]["name"] == "express"


async def test_get_version_info_404():
    client = DepsDevClient()
    mock_resp = httpx.Response(404)
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.get_version_info("npm", "nonexistent", "1.0.0")
    assert result is None


async def test_get_dependencies_success():
    client = DepsDevClient()
    mock_resp = httpx.Response(
        200,
        json={
            "nodes": [
                {"versionKey": {"system": "npm", "name": "express", "version": "4.21.2"}, "relation": "SELF"},
                {"versionKey": {"system": "npm", "name": "body-parser", "version": "1.20.3"}, "relation": "DIRECT"},
                {"versionKey": {"system": "npm", "name": "bytes", "version": "3.1.2"}, "relation": "INDIRECT"},
            ]
        },
    )
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.get_dependencies("npm", "express", "4.21.2")
    assert result is not None
    assert len(result) == 2  # SELF excluded
    assert result[0]["name"] == "body-parser"


async def test_get_package_versions_success():
    client = DepsDevClient()
    mock_resp = httpx.Response(
        200,
        json={
            "versions": [
                {"versionKey": {"version": "4.21.0"}},
                {"versionKey": {"version": "4.21.1"}},
                {"versionKey": {"version": "4.21.2"}},
            ]
        },
    )
    with patch.object(client._client, "get", new_callable=AsyncMock, return_value=mock_resp):
        result = await client.get_package_versions("npm", "express")
    assert result == ["4.21.0", "4.21.1", "4.21.2"]


async def test_timeout_returns_none():
    client = DepsDevClient(timeout=0.001)
    with patch.object(client._client, "get", new_callable=AsyncMock, side_effect=httpx.TimeoutException("timeout")):
        result = await client.get_version_info("npm", "express", "4.21.2")
    assert result is None
