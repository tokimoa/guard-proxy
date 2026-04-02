"""Background sync service for OSV/GHSA advisory data."""

import asyncio
import json
from datetime import UTC, datetime

import httpx
from loguru import logger
from sqlalchemy import func, select

from app.db.models.advisory import Advisory, AdvisorySyncState
from app.db.session import Database

_OSV_API = "https://api.osv.dev/v1/query"
_ECOSYSTEMS = ["npm", "PyPI", "RubyGems"]

# Well-known vulnerable packages to seed the advisory DB
_SEED_PACKAGES = {
    "npm": ["lodash", "express", "axios", "node-fetch", "minimist", "qs", "jsonwebtoken"],
    "PyPI": ["requests", "django", "flask", "pillow", "numpy", "jinja2", "cryptography"],
    "RubyGems": ["rails", "nokogiri", "rack", "devise", "puma", "sinatra", "activerecord"],
}


class AdvisorySyncService:
    """Periodically sync vulnerability advisories from OSV.dev to local SQLite."""

    def __init__(self, database: Database, sync_interval_hours: int = 6) -> None:
        self._db = database
        self._interval = sync_interval_hours * 3600
        self._task: asyncio.Task | None = None  # type: ignore[type-arg]

    async def start(self) -> None:
        """Start background sync loop."""
        self._task = asyncio.create_task(self._sync_loop())
        logger.info("Advisory sync service started (interval: {h}h)", h=self._interval // 3600)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _sync_loop(self) -> None:
        # Initial sync on startup
        await self._sync_all()

        while True:
            await asyncio.sleep(self._interval)
            await self._sync_all()

    async def _sync_all(self) -> None:
        """Sync advisories for all ecosystems."""
        logger.info("Starting advisory sync...")
        total = 0

        async with httpx.AsyncClient(timeout=30.0) as client:
            for ecosystem in _ECOSYSTEMS:
                packages = _SEED_PACKAGES.get(ecosystem, [])
                for pkg_name in packages:
                    try:
                        count = await self._sync_package(client, ecosystem, pkg_name)
                        total += count
                    except Exception:
                        logger.warning("Failed to sync advisories for {eco}/{pkg}", eco=ecosystem, pkg=pkg_name)

        # Update sync state
        async with self._db.session() as session:
            stmt = select(AdvisorySyncState).where(AdvisorySyncState.source == "osv")
            state = (await session.execute(stmt)).scalar_one_or_none()
            if state:
                state.last_sync_at = datetime.now(UTC)
                state.total_advisories = total
            else:
                session.add(AdvisorySyncState(source="osv", last_sync_at=datetime.now(UTC), total_advisories=total))
            await session.commit()

        logger.info("Advisory sync complete: {total} advisories", total=total)

    async def _sync_package(self, client: httpx.AsyncClient, ecosystem: str, package_name: str) -> int:
        """Query OSV API for a specific package and upsert advisories (with pagination)."""
        payload: dict = {"package": {"ecosystem": ecosystem, "name": package_name}}

        # Fetch all pages
        vulns: list[dict] = []
        while True:
            resp = await client.post(_OSV_API, json=payload)
            if resp.status_code != 200:
                break

            data = resp.json()
            vulns.extend(data.get("vulns", []))

            # Handle pagination
            next_token = data.get("next_page_token")
            if next_token:
                payload["page_token"] = next_token
            else:
                break

        count = 0
        async with self._db.session() as session:
            for vuln in vulns:
                advisory_id = vuln.get("id", "")
                if not advisory_id:
                    continue

                # Extract affected ranges
                affected_ranges = []
                for affected in vuln.get("affected", []):
                    for r in affected.get("ranges", []):
                        if r.get("type") == "ECOSYSTEM":
                            for event in r.get("events", []):
                                if "introduced" in event:
                                    range_entry = {"introduced": event["introduced"]}
                                elif "fixed" in event and affected_ranges:
                                    affected_ranges[-1]["fixed"] = event["fixed"]
                                    continue
                                else:
                                    continue
                                affected_ranges.append(range_entry)

                # Determine severity
                severity = "UNKNOWN"
                db_specific = vuln.get("database_specific", {})
                if "severity" in db_specific:
                    severity = db_specific["severity"]
                elif vuln.get("severity"):
                    for s in vuln["severity"]:
                        if s.get("type") == "CVSS_V3":
                            score = s.get("score", "")
                            if ":" in str(score):
                                pass  # CVSS vector, skip
                            else:
                                try:
                                    score_f = float(score)
                                    if score_f >= 9.0:
                                        severity = "CRITICAL"
                                    elif score_f >= 7.0:
                                        severity = "HIGH"
                                    elif score_f >= 4.0:
                                        severity = "MEDIUM"
                                    else:
                                        severity = "LOW"
                                except (ValueError, TypeError):
                                    pass

                aliases = ",".join(vuln.get("aliases", []))
                summary = vuln.get("summary", vuln.get("details", ""))[:500]

                # Upsert
                existing = (
                    await session.execute(select(Advisory).where(Advisory.advisory_id == advisory_id))
                ).scalar_one_or_none()

                if existing:
                    existing.severity = severity
                    existing.summary = summary
                    existing.affected_ranges_json = json.dumps(affected_ranges)
                    existing.aliases = aliases
                    existing.synced_at = datetime.now(UTC)
                else:
                    session.add(
                        Advisory(
                            advisory_id=advisory_id,
                            source="osv",
                            ecosystem=ecosystem,
                            package_name=package_name,
                            severity=severity,
                            summary=summary,
                            affected_ranges_json=json.dumps(affected_ranges),
                            aliases=aliases,
                        )
                    )
                count += 1

            await session.commit()

        return count

    async def advisory_count(self) -> int:
        """Get total number of cached advisories."""
        async with self._db.session() as session:
            result = await session.execute(select(func.count(Advisory.id)))
            return result.scalar() or 0
