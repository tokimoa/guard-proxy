"""Advisory scanner — checks packages against locally-cached OSV/GHSA advisories."""

import json
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version
from sqlalchemy import select

from app.db.models.advisory import Advisory
from app.db.session import Database
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

# Map Guard Proxy registry names to OSV ecosystem names
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "PyPI",
    "rubygems": "RubyGems",
}

_SEVERITY_SCORES = {
    "CRITICAL": ("fail", 1.0),
    "HIGH": ("fail", 0.9),
    "MEDIUM": ("warn", 0.7),
    "LOW": ("warn", 0.5),
    "UNKNOWN": ("warn", 0.5),
}


class AdvisoryScanner:
    """Check packages against locally-cached vulnerability advisories."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        ecosystem = _ECOSYSTEM_MAP.get(package.registry, package.registry)

        async with self._db.session() as session:
            stmt = select(Advisory).where(
                Advisory.ecosystem == ecosystem,
                Advisory.package_name == package.name,
            )
            advisories = (await session.execute(stmt)).scalars().all()

        if not advisories:
            return ScanResult(
                scanner_name="advisory_check",
                verdict="pass",
                confidence=0.95,
                details="No known advisories for this package version",
            )

        # Check version ranges
        matching: list[Advisory] = []
        for adv in advisories:
            if self._version_matches(package.version, adv.affected_ranges_json):
                matching.append(adv)

        if not matching:
            return ScanResult(
                scanner_name="advisory_check",
                verdict="pass",
                confidence=0.95,
                details=f"{len(advisories)} advisory(ies) found but none affect version {package.version}",
            )

        # Determine worst severity
        worst_severity = "LOW"
        severity_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3, "UNKNOWN": 1}
        for adv in matching:
            if severity_order.get(adv.severity, 0) > severity_order.get(worst_severity, 0):
                worst_severity = adv.severity

        verdict, confidence = _SEVERITY_SCORES.get(worst_severity, ("warn", 0.5))
        summaries = [f"[{a.advisory_id}] {a.summary[:100]}" for a in matching[:3]]
        details = f"{len(matching)} advisory(ies) affect {package.name}@{package.version}: " + "; ".join(summaries)

        return ScanResult(
            scanner_name="advisory_check",
            verdict=verdict,
            confidence=confidence,
            details=details,
            metadata={
                "advisory_count": len(matching),
                "advisories": [a.advisory_id for a in matching],
                "worst_severity": worst_severity,
            },
        )

    @staticmethod
    def _version_matches(version: str, ranges_json: str) -> bool:
        """Check if version falls within any affected range."""
        try:
            ranges = json.loads(ranges_json)
        except json.JSONDecodeError:
            return False

        try:
            ver = Version(version)
        except InvalidVersion:
            return False

        for r in ranges:
            introduced = r.get("introduced", "0")
            fixed = r.get("fixed")

            try:
                if fixed:
                    spec = SpecifierSet(f">={introduced},<{fixed}")
                else:
                    spec = SpecifierSet(f">={introduced}")
                if ver in spec:
                    return True
            except Exception:
                continue

        return False
