"""Tests for maintainer scanner."""

import pytest

from app.core.config import Settings
from app.db.session import Database
from app.scanners.maintainer_scanner import MaintainerScanner
from app.schemas.package import PackageInfo


@pytest.fixture
async def db(tmp_path):
    settings = Settings(db_path=str(tmp_path / "test.db"))
    database = Database(settings)
    await database.create_tables()
    yield database
    await database.close()


def _pkg(name="express", version="4.18.2", registry="npm", **meta):
    return PackageInfo(name=name, version=version, registry=registry, metadata=meta)


async def test_first_scan_records_snapshot(db):
    scanner = MaintainerScanner(db)
    pkg = _pkg(maintainers=["author1"])
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
    assert result.metadata.get("first_scan") is True


async def test_unchanged_maintainers_pass(db):
    scanner = MaintainerScanner(db)
    # First scan
    await scanner.scan(_pkg(version="4.18.1", maintainers=["author1"]), [])
    # Second scan — same maintainer
    result = await scanner.scan(_pkg(version="4.18.2", maintainers=["author1"]), [])
    assert result.verdict == "pass"
    assert "unchanged" in result.details.lower()


async def test_maintainer_added_warns(db):
    scanner = MaintainerScanner(db)
    await scanner.scan(_pkg(version="1.0.0", maintainers=["alice"]), [])
    result = await scanner.scan(_pkg(version="1.0.1", maintainers=["alice", "bob"]), [])
    assert result.verdict == "warn"
    assert "bob" in result.details


async def test_maintainer_removed_warns(db):
    scanner = MaintainerScanner(db)
    await scanner.scan(_pkg(version="1.0.0", maintainers=["alice", "bob"]), [])
    result = await scanner.scan(_pkg(version="1.0.1", maintainers=["alice"]), [])
    assert result.verdict == "warn"
    assert "bob" in result.details


async def test_complete_replacement_high_confidence(db):
    scanner = MaintainerScanner(db)
    await scanner.scan(_pkg(version="1.0.0", maintainers=["alice"]), [])
    result = await scanner.scan(_pkg(version="1.0.1", maintainers=["evil_hacker"]), [])
    assert result.verdict == "warn"
    assert result.confidence >= 0.8  # complete replacement gets higher confidence


async def test_publisher_changed_npm(db):
    scanner = MaintainerScanner(db)
    await scanner.scan(_pkg(version="1.0.0", maintainers=["alice"], _npmUser="alice"), [])
    result = await scanner.scan(_pkg(version="1.0.1", maintainers=["alice"], _npmUser="bob"), [])
    assert result.verdict == "warn"
    assert "publisher" in result.details.lower()


async def test_pypi_author_extraction(db):
    scanner = MaintainerScanner(db)
    pkg = _pkg(name="requests", registry="pypi", author="Kenneth Reitz")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
    assert result.metadata.get("first_scan") is True


async def test_rubygems_authors_extraction(db):
    scanner = MaintainerScanner(db)
    pkg = _pkg(name="rails", registry="rubygems", authors="DHH, Rafael França")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_missing_metadata_graceful(db):
    scanner = MaintainerScanner(db)
    pkg = PackageInfo(name="bare-pkg", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
