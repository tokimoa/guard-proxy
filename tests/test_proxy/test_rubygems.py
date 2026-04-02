"""Tests for RubyGems proxy."""

import gzip
import io
import tarfile
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.proxy.rubygems import RubyGemsProxy
from app.registry.rubygems_client import RubyGemsRegistryClient
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner


def _make_gem(gemspec_yaml: str, files: dict[str, str]) -> bytes:
    """Create a minimal .gem file (plain tar with metadata.gz + data.tar.gz)."""
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w:") as tar:
        # metadata.gz
        meta_bytes = gzip.compress(gemspec_yaml.encode())
        info = tarfile.TarInfo("metadata.gz")
        info.size = len(meta_bytes)
        tar.addfile(info, io.BytesIO(meta_bytes))

        # data.tar.gz
        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:gz") as inner:
            for name, content in files.items():
                content_bytes = content.encode()
                finfo = tarfile.TarInfo(name)
                finfo.size = len(content_bytes)
                inner.addfile(finfo, io.BytesIO(content_bytes))
        data_bytes = data_buf.getvalue()
        dinfo = tarfile.TarInfo("data.tar.gz")
        dinfo.size = len(data_bytes)
        tar.addfile(dinfo, io.BytesIO(data_bytes))

    return outer.getvalue()


def _make_settings() -> Settings:
    return Settings(
        rubygems_upstream_url="https://rubygems.org",
        decision_mode="warn",
        cooldown_days=7,
    )


def _make_proxy() -> RubyGemsProxy:
    settings = _make_settings()
    client = RubyGemsRegistryClient(settings)
    scanners = [CooldownScanner(settings), RubyGemsStaticAnalysisScanner(settings)]
    pipeline = ScanPipeline(scanners)
    engine = DecisionEngine(settings)
    return RubyGemsProxy(settings, client, pipeline, engine)


def test_gem_download_scan_allow():
    proxy = _make_proxy()
    app = FastAPI()
    app.include_router(proxy.get_router())
    client = TestClient(app)

    safe_gem = _make_gem(
        "--- !ruby/object:Gem::Specification\nname: safe-gem\nversion: !ruby/object:Gem::Version\n  version: '1.0.0'\n",
        {"lib/safe.rb": "module Safe; end"},
    )

    mock_versions = [{"number": "1.0.0", "created_at": "2025-01-01T00:00:00Z"}]

    with (
        patch.object(proxy._registry, "download_gem", new_callable=AsyncMock, return_value=safe_gem),
        patch.object(proxy._registry, "get_gem_versions", new_callable=AsyncMock, return_value=mock_versions),
    ):
        response = client.get("/gems/safe-gem-1.0.0.gem")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/octet-stream"


def test_name_version_extraction():
    assert RubyGemsProxy._extract_name_version("nokogiri-1.16.0.gem") == ("nokogiri", "1.16.0")
    assert RubyGemsProxy._extract_name_version("activerecord-7.1.0.gem") == ("activerecord", "7.1.0")
    assert RubyGemsProxy._extract_name_version("net-http-0.4.0.gem") == ("net-http", "0.4.0")


def test_compact_index_passthrough():
    proxy = _make_proxy()
    app = FastAPI()
    app.include_router(proxy.get_router())
    client = TestClient(app)

    import httpx

    mock_resp = httpx.Response(200, content=b"compact index data", headers={"content-type": "text/plain"})
    with patch.object(proxy._registry, "forward_request", new_callable=AsyncMock, return_value=mock_resp):
        response = client.get("/info/rails")

    assert response.status_code == 200
    assert b"compact index data" in response.content


def test_versions_passthrough():
    proxy = _make_proxy()
    app = FastAPI()
    app.include_router(proxy.get_router())
    client = TestClient(app)

    import httpx

    mock_resp = httpx.Response(200, content=b"versions data", headers={"content-type": "text/plain"})
    with patch.object(proxy._registry, "forward_request", new_callable=AsyncMock, return_value=mock_resp):
        response = client.get("/versions")

    assert response.status_code == 200
