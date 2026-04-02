"""Tests for metadata scanner (typosquatting detection)."""

from app.scanners.metadata_scanner import MetadataScanner
from app.schemas.package import PackageInfo


def _scanner() -> MetadataScanner:
    return MetadataScanner()


async def test_pass_popular_package():
    """Known popular packages should not be flagged."""
    scanner = _scanner()
    pkg = PackageInfo(name="requests", version="2.31.0", registry="pypi")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_detect_typosquat_distance_1():
    """Package 1 character away from popular one should be flagged."""
    scanner = _scanner()
    pkg = PackageInfo(name="reqeusts", version="1.0.0", registry="pypi")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"
    assert "typosquat" in result.details.lower()
    assert "requests" in result.details


async def test_detect_typosquat_distance_2():
    scanner = _scanner()
    pkg = PackageInfo(name="requsets", version="1.0.0", registry="pypi")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"


async def test_pass_unique_name():
    """Unique name far from any popular package should pass."""
    scanner = _scanner()
    pkg = PackageInfo(name="my-unique-internal-tool-xyz", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_pass_short_name():
    """Short names (<5 chars) should be skipped for typosquatting."""
    scanner = _scanner()
    pkg = PackageInfo(name="abcd", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_npm_typosquat():
    scanner = _scanner()
    pkg = PackageInfo(name="expreess", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"
    assert "express" in result.details


async def test_rubygems_typosquat():
    scanner = _scanner()
    pkg = PackageInfo(name="nokogri", version="1.0.0", registry="rubygems")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"
    assert "nokogiri" in result.details
