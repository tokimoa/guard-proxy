"""Tests for advisory scanner."""

import json

import pytest

from app.core.config import Settings
from app.db.models.advisory import Advisory
from app.db.session import Database
from app.scanners.advisory_scanner import AdvisoryScanner
from app.schemas.package import PackageInfo


@pytest.fixture
async def db(tmp_path):
    settings = Settings(db_path=str(tmp_path / "test.db"))
    database = Database(settings)
    await database.create_tables()
    yield database
    await database.close()


async def _insert_advisory(db, advisory_id, ecosystem, package_name, severity, ranges):
    async with db.session() as session:
        session.add(
            Advisory(
                advisory_id=advisory_id,
                source="osv",
                ecosystem=ecosystem,
                package_name=package_name,
                severity=severity,
                summary=f"Test advisory {advisory_id}",
                affected_ranges_json=json.dumps(ranges),
            )
        )
        await session.commit()


async def test_no_advisories_pass(db):
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="safe-pkg", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_matching_advisory_fails(db):
    await _insert_advisory(db, "GHSA-1234", "npm", "vuln-pkg", "HIGH", [{"introduced": "1.0.0", "fixed": "1.0.5"}])
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="vuln-pkg", version="1.0.3", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "fail"
    assert "GHSA-1234" in result.details


async def test_fixed_version_passes(db):
    await _insert_advisory(db, "GHSA-5678", "PyPI", "vuln-pkg", "HIGH", [{"introduced": "1.0.0", "fixed": "1.0.5"}])
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="vuln-pkg", version="1.0.5", registry="pypi")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"


async def test_critical_severity(db):
    await _insert_advisory(db, "GHSA-9999", "RubyGems", "bad-gem", "CRITICAL", [{"introduced": "0.1.0"}])
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="bad-gem", version="2.0.0", registry="rubygems")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "fail"
    assert result.confidence == 1.0


async def test_medium_severity_warns(db):
    await _insert_advisory(db, "OSV-2024-001", "npm", "pkg", "MEDIUM", [{"introduced": "1.0.0"}])
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="pkg", version="1.5.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "warn"


async def test_empty_db_passes(db):
    """Advisory DB is empty (never synced) — should pass gracefully."""
    scanner = AdvisoryScanner(db)
    pkg = PackageInfo(name="anything", version="1.0.0", registry="npm")
    result = await scanner.scan(pkg, [])
    assert result.verdict == "pass"
