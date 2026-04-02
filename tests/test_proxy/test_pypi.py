"""Tests for PyPI proxy."""

import io
import zipfile
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.proxy.pypi import PyPIProxy
from app.registry.pypi_client import PyPIRegistryClient
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner


def _make_whl(files: dict[str, str]) -> bytes:
    """Create a minimal whl (zip) file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(f"package/{name}", content)
    return buf.getvalue()


def _make_settings() -> Settings:
    return Settings(
        pypi_upstream_url="https://pypi.org",
        decision_mode="warn",
        cooldown_days=7,
    )


def _make_proxy() -> PyPIProxy:
    settings = _make_settings()
    client = PyPIRegistryClient(settings)
    scanners = [CooldownScanner(settings), PyPIStaticAnalysisScanner(settings)]
    pipeline = ScanPipeline(scanners)
    engine = DecisionEngine(settings)
    return PyPIProxy(settings, client, pipeline, engine)


def test_simple_index_rewrite():
    proxy = _make_proxy()
    app = FastAPI()
    app.include_router(proxy.get_router())
    client = TestClient(app)

    sample_html = """
    <a href="https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0.whl#sha256=abc">
        requests-2.31.0.whl</a>
    """

    with patch.object(proxy._registry, "get_simple_index", new_callable=AsyncMock, return_value=sample_html):
        response = client.get("/simple/requests/")

    assert response.status_code == 200
    assert "files.pythonhosted.org" not in response.text
    assert "/packages/" in response.text


def test_package_download_scan_allow():
    proxy = _make_proxy()
    app = FastAPI()
    app.include_router(proxy.get_router())
    client = TestClient(app)

    safe_whl = _make_whl(
        {
            "setup.py": "from setuptools import setup\nsetup(name='safe')",
            "__init__.py": "VERSION = '1.0.0'",
        }
    )

    mock_meta = {
        "info": {"version": "1.0.0"},
        "releases": {"1.0.0": [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}]},
    }

    with (
        patch.object(proxy._registry, "download_artifact", new_callable=AsyncMock, return_value=safe_whl),
        patch.object(proxy._registry, "get_version_metadata", new_callable=AsyncMock, return_value=mock_meta),
    ):
        response = client.get("/packages/ab/cd/safe_pkg-1.0.0-py3-none-any.whl")

    assert response.status_code == 200


def test_name_version_extraction():
    assert PyPIProxy._extract_name_version("requests-2.31.0-py3-none-any.whl") == ("requests", "2.31.0")
    assert PyPIProxy._extract_name_version("numpy-1.26.4.tar.gz") == ("numpy", "1.26.4")
    assert PyPIProxy._extract_name_version("my_package-0.1.0.zip") == ("my-package", "0.1.0")


def test_url_rewriting():
    html = '<a href="https://files.pythonhosted.org/packages/ab/cd/foo-1.0.whl">foo</a>'
    result = PyPIProxy._rewrite_download_urls(html, "http://localhost:4874")
    assert "http://localhost:4874/packages/" in result
    assert "files.pythonhosted.org" not in result
