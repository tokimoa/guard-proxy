"""Tests for cooldown scanner."""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.scanners.cooldown import CooldownScanner
from app.schemas.package import PackageInfo


@pytest.fixture
def scanner(settings: Settings) -> CooldownScanner:
    return CooldownScanner(settings)


@pytest.fixture
def deny_scanner() -> CooldownScanner:
    return CooldownScanner(Settings(cooldown_days=7, cooldown_action="deny"))


def _make_package(days_ago: float | None) -> PackageInfo:
    publish_date = datetime.now(UTC) - timedelta(days=days_ago) if days_ago is not None else None
    return PackageInfo(name="test-pkg", version="1.0.0", publish_date=publish_date)


async def test_pass_old_package(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(30), [])
    assert result.verdict == "pass"
    assert result.confidence == 1.0


async def test_warn_recent_package(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(2), [])
    assert result.verdict == "warn"
    assert result.confidence >= 0.6


async def test_fail_recent_package_deny_mode(deny_scanner: CooldownScanner) -> None:
    result = await deny_scanner.scan(_make_package(2), [])
    assert result.verdict == "fail"
    assert result.confidence >= 0.6


async def test_boundary_exact_cooldown(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(7), [])
    assert result.verdict == "pass"


async def test_boundary_just_under_cooldown(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(6.9), [])
    assert result.verdict == "warn"


async def test_missing_publish_date(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(None), [])
    assert result.verdict == "warn"
    assert result.confidence == 0.5
    assert "missing_date" in result.metadata.get("reason", "")


async def test_very_recent_package_high_confidence(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(0.1), [])
    assert result.verdict == "warn"
    assert result.confidence > 0.9


async def test_scanner_name(scanner: CooldownScanner) -> None:
    result = await scanner.scan(_make_package(30), [])
    assert result.scanner_name == "cooldown"
