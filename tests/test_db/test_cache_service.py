"""Tests for cache service."""

import pytest

from app.core.config import Settings
from app.db.cache_service import CacheService
from app.db.session import Database
from app.schemas.decision import DecisionResult
from app.schemas.scan import ScanResult


@pytest.fixture
async def db(tmp_path):
    settings = Settings(db_path=str(tmp_path / "test.db"))
    database = Database(settings)
    await database.create_tables()
    yield database
    await database.close()


@pytest.fixture
async def cache(db, settings):
    settings_with_db = Settings(db_path=str(db._engine.url).replace("sqlite+aiosqlite:///", ""))
    return CacheService(settings_with_db, db)


def _make_decision(verdict: str = "allow") -> DecisionResult:
    return DecisionResult(
        verdict=verdict,
        final_score=0.1,
        scan_results=[
            ScanResult(scanner_name="cooldown", verdict="pass", confidence=1.0, details="ok"),
        ],
        reason="test",
        mode="warn",
    )


async def test_cache_miss(db, settings):
    cache = CacheService(settings, db)
    result = await cache.get("npm", "express", "4.18.2", "abc123")
    assert result is None


async def test_cache_put_and_get(db, settings):
    cache = CacheService(settings, db)
    decision = _make_decision()
    await cache.put("npm", "express", "4.18.2", "abc123", decision)

    cached = await cache.get("npm", "express", "4.18.2", "abc123")
    assert cached is not None
    assert cached.verdict == "allow"
    assert cached.final_score == 0.1
    assert len(cached.scan_results) == 1


async def test_cache_different_hash_misses(db, settings):
    cache = CacheService(settings, db)
    await cache.put("npm", "express", "4.18.2", "abc123", _make_decision())

    cached = await cache.get("npm", "express", "4.18.2", "different_hash")
    assert cached is None


async def test_cache_clear(db, settings):
    cache = CacheService(settings, db)
    await cache.put("npm", "a", "1.0", "h1", _make_decision())
    await cache.put("npm", "b", "2.0", "h2", _make_decision())

    deleted = await cache.clear()
    assert deleted == 2

    cached = await cache.get("npm", "a", "1.0", "h1")
    assert cached is None


async def test_cache_stats(db, settings):
    cache = CacheService(settings, db)
    await cache.put("npm", "a", "1.0", "h1", _make_decision())

    stats = await cache.stats()
    assert stats["total_entries"] == 1
    assert stats["active_entries"] == 1
