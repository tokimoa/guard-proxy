"""Maintainer verification scanner.

Detects maintainer changes between package versions by building
a local snapshot database over time.
"""

import json
from pathlib import Path

from sqlalchemy import select

from app.db.models.maintainer_snapshot import MaintainerSnapshot
from app.db.session import Database
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


class MaintainerScanner:
    """Detect maintainer changes by comparing against historical snapshots."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        current_maintainers = self._extract_maintainers(package)
        current_publisher = package.metadata.get("_npmUser", "")

        # Query DB for previous snapshots of this package
        async with self._db.session() as session:
            stmt = (
                select(MaintainerSnapshot)
                .where(
                    MaintainerSnapshot.registry == package.registry,
                    MaintainerSnapshot.package_name == package.name,
                )
                .order_by(MaintainerSnapshot.scanned_at.desc())
                .limit(5)
            )
            previous = list((await session.execute(stmt)).scalars().all())

        # Compare with previous snapshots
        result = self._compare(package, current_maintainers, current_publisher, previous)

        # Record new snapshot
        await self._record_snapshot(package, current_maintainers, current_publisher)

        return result

    def _compare(
        self,
        package: PackageInfo,
        current: list[str],
        publisher: str,
        previous: list[MaintainerSnapshot],
    ) -> ScanResult:
        if not previous:
            return ScanResult(
                scanner_name="maintainer_check",
                verdict="pass",
                confidence=0.7,
                details=f"First scan of {package.name} — maintainer snapshot recorded",
                metadata={"first_scan": True, "maintainers": current},
            )

        latest = previous[0]
        prev_maintainers = json.loads(latest.maintainers_json)
        prev_set = set(prev_maintainers)
        curr_set = set(current)

        added = curr_set - prev_set
        removed = prev_set - curr_set

        # No maintainer change — check publisher (npm only)
        if not added and not removed:
            if publisher and latest.publisher and publisher != latest.publisher:
                return ScanResult(
                    scanner_name="maintainer_check",
                    verdict="warn",
                    confidence=0.7,
                    details=(
                        f"Publisher changed: {latest.publisher} → {publisher} (v{latest.version} → v{package.version})"
                    ),
                    metadata={
                        "previous_publisher": latest.publisher,
                        "current_publisher": publisher,
                        "previous_version": latest.version,
                    },
                )
            return ScanResult(
                scanner_name="maintainer_check",
                verdict="pass",
                confidence=0.95,
                details="Maintainers unchanged from previous version",
            )

        # Maintainers changed
        # Complete replacement is more suspicious than partial change
        if removed and not (prev_set & curr_set):
            confidence = 0.85  # all maintainers replaced
        elif added and removed:
            confidence = 0.7  # both additions and removals
        else:
            confidence = 0.6  # only additions or only removals

        changes = []
        if added:
            changes.append(f"added: {', '.join(sorted(added))}")
        if removed:
            changes.append(f"removed: {', '.join(sorted(removed))}")

        return ScanResult(
            scanner_name="maintainer_check",
            verdict="warn",
            confidence=confidence,
            details=f"Maintainers changed (v{latest.version} → v{package.version}): {'; '.join(changes)}",
            metadata={
                "added": sorted(added),
                "removed": sorted(removed),
                "previous_version": latest.version,
            },
        )

    async def _record_snapshot(self, package: PackageInfo, maintainers: list[str], publisher: str) -> None:
        """Record current maintainers to DB for future comparison."""
        async with self._db.session() as session:
            session.add(
                MaintainerSnapshot(
                    registry=package.registry,
                    package_name=package.name,
                    version=package.version,
                    maintainers_json=json.dumps(sorted(maintainers)),
                    publisher=publisher,
                )
            )
            await session.commit()

    @staticmethod
    def _extract_maintainers(package: PackageInfo) -> list[str]:
        """Extract maintainer identifiers from package metadata."""
        meta = package.metadata

        if package.registry == "npm":
            return meta.get("maintainers", [])

        if package.registry == "pypi":
            maintainers = []
            for field in ("author", "maintainer"):
                val = meta.get(field, "")
                if val:
                    maintainers.append(val)
            return maintainers

        if package.registry == "rubygems":
            authors = meta.get("authors", "")
            if authors:
                return [a.strip() for a in authors.split(",")]
            return []

        return []
