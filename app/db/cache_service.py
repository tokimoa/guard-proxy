"""Scan result caching service."""

import json
from datetime import UTC, datetime, timedelta

from loguru import logger
from sqlalchemy import delete, select

from app.core.config import Settings
from app.db.models.scan_cache import ScanCache
from app.db.session import Database
from app.schemas.decision import DecisionResult
from app.schemas.scan import ScanResult


class CacheService:
    """Cache scan results in SQLite to avoid re-scanning known packages."""

    def __init__(self, settings: Settings, database: Database) -> None:
        self._ttl_hours = settings.cache_ttl_hours
        self._db = database

    def make_cache_key(self, registry: str, name: str, version: str, content_hash: str) -> str:
        return f"{registry}:{name}:{version}:{content_hash}"

    async def get(self, registry: str, name: str, version: str, content_hash: str) -> DecisionResult | None:
        """Look up cached decision. Returns None on miss."""
        key = self.make_cache_key(registry, name, version, content_hash)
        now = datetime.now(UTC)

        async with self._db.session() as session:
            stmt = select(ScanCache).where(ScanCache.cache_key == key, ScanCache.expires_at > now)
            row = (await session.execute(stmt)).scalar_one_or_none()

        if row is None:
            return None

        logger.debug("Cache hit: {key}", key=key)
        scan_results = [ScanResult.model_validate(r) for r in json.loads(row.scan_results_json)]
        return DecisionResult(
            verdict=row.verdict,
            final_score=row.final_score,
            scan_results=scan_results,
            reason=row.reason,
            mode="warn",  # mode is applied at request time, not cached
        )

    async def put(
        self,
        registry: str,
        name: str,
        version: str,
        content_hash: str,
        decision: DecisionResult,
    ) -> None:
        """Store a decision in the cache."""
        key = self.make_cache_key(registry, name, version, content_hash)
        now = datetime.now(UTC)
        expires = now + timedelta(hours=self._ttl_hours)

        scan_json = json.dumps([r.model_dump() for r in decision.scan_results])

        async with self._db.session() as session:
            # Upsert: delete old entry if exists
            await session.execute(delete(ScanCache).where(ScanCache.cache_key == key))
            session.add(
                ScanCache(
                    cache_key=key,
                    registry=registry,
                    package_name=name,
                    version=version,
                    content_hash=content_hash,
                    verdict=decision.verdict,
                    final_score=decision.final_score,
                    scan_results_json=scan_json,
                    reason=decision.reason,
                    created_at=now,
                    expires_at=expires,
                )
            )
            await session.commit()
        logger.debug("Cache stored: {key}", key=key)

    async def clear(self) -> int:
        """Clear all cache entries. Returns count deleted."""
        async with self._db.session() as session:
            result = await session.execute(delete(ScanCache))
            await session.commit()
            return result.rowcount  # type: ignore[return-value]

    async def evict_expired(self) -> int:
        """Remove expired entries. Returns count evicted."""
        now = datetime.now(UTC)
        async with self._db.session() as session:
            result = await session.execute(delete(ScanCache).where(ScanCache.expires_at <= now))
            await session.commit()
            return result.rowcount  # type: ignore[return-value]

    async def stats(self) -> dict:
        """Return cache statistics."""
        from sqlalchemy import func

        async with self._db.session() as session:
            total = (await session.execute(select(func.count(ScanCache.id)))).scalar() or 0
            now = datetime.now(UTC)
            active = (
                await session.execute(select(func.count(ScanCache.id)).where(ScanCache.expires_at > now))
            ).scalar() or 0
        return {"total_entries": total, "active_entries": active, "expired_entries": total - active}
