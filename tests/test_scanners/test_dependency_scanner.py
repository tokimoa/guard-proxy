"""Tests for dependency scanner."""

from unittest.mock import AsyncMock

from app.core.config import Settings
from app.registry.depsdev_client import DepsDevClient
from app.scanners.dependency_scanner import DependencyScanner
from app.schemas.package import PackageInfo


def _pkg(name="express", version="4.21.2", registry="npm", **meta):
    return PackageInfo(name=name, version=version, registry=registry, metadata=meta)


def _mock_depsdev():
    client = AsyncMock(spec=DepsDevClient)
    client.get_dependencies = AsyncMock(return_value=None)
    client.get_package_versions = AsyncMock(return_value=None)
    client.get_version_info = AsyncMock(return_value=None)
    return client


async def test_no_deps_info_pass():
    scanner = DependencyScanner(_mock_depsdev(), Settings())
    result = await scanner.scan(_pkg(), [])
    assert result.verdict == "pass"


async def test_npm_no_new_deps_pass():
    client = _mock_depsdev()
    scanner = DependencyScanner(client, Settings())

    pkg = _pkg(
        dependencies={"follow-redirects": "^1.15.0", "form-data": "^4.0.0"},
        version_times={"4.21.1": "2025-01-01T00:00:00Z", "4.21.2": "2025-06-01T00:00:00Z"},
    )

    # Previous version has same deps
    client.get_dependencies.return_value = [
        {"name": "follow-redirects", "version": "1.15.0", "relation": "DIRECT"},
        {"name": "form-data", "version": "4.0.0", "relation": "DIRECT"},
    ]

    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
    assert "no new" in result.details.lower()


async def test_new_dep_warns():
    client = _mock_depsdev()
    scanner = DependencyScanner(client, Settings())

    pkg = _pkg(
        dependencies={
            "follow-redirects": "^1.15.0",
            "form-data": "^4.0.0",
            "plain-crypto-js": "^4.2.1",  # NEW malicious dep
        },
        version_times={"4.21.1": "2025-01-01T00:00:00Z", "4.21.2": "2025-06-01T00:00:00Z"},
    )

    # Previous version didn't have plain-crypto-js
    client.get_dependencies.return_value = [
        {"name": "follow-redirects", "version": "1.15.0", "relation": "DIRECT"},
        {"name": "form-data", "version": "4.0.0", "relation": "DIRECT"},
    ]

    # plain-crypto-js not found on deps.dev (very new/suspicious)
    client.get_version_info.return_value = None

    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"
    assert "plain-crypto-js" in result.details


async def test_no_previous_version_pass():
    client = _mock_depsdev()
    client.get_package_versions.return_value = ["1.0.0"]

    scanner = DependencyScanner(client, Settings())
    pkg = _pkg(name="brand-new-pkg", version="1.0.0", registry="pypi")

    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_depsdev_failure_graceful():
    client = _mock_depsdev()
    client.get_dependencies.side_effect = Exception("Network error")

    scanner = DependencyScanner(client, Settings())
    pkg = _pkg(registry="pypi")

    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
    assert result.confidence <= 0.7


async def test_version_time_ordering():
    """Test _find_previous_from_times correctly finds the previous version."""
    result = DependencyScanner._find_previous_from_times(
        "4.21.2",
        {
            "created": "2020-01-01T00:00:00Z",
            "modified": "2025-06-01T00:00:00Z",
            "4.21.0": "2025-03-01T00:00:00Z",
            "4.21.1": "2025-05-01T00:00:00Z",
            "4.21.2": "2025-06-01T00:00:00Z",
        },
    )
    assert result == "4.21.1"
