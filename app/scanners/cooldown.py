"""Cooldown gate scanner.

Blocks or warns on packages published within the cooldown window.
"""

from datetime import UTC, datetime
from pathlib import Path

from app.core.config import Settings
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


class CooldownScanner:
    """Check if a package version was published within the cooldown window."""

    def __init__(self, settings: Settings) -> None:
        self._cooldown_days = settings.cooldown_days
        self._action = settings.cooldown_action

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        if package.publish_date is None:
            return ScanResult(
                scanner_name="cooldown",
                verdict="warn",
                confidence=0.5,
                details=f"No publish date available for {package.name}@{package.version}",
                metadata={"reason": "missing_date"},
            )

        now = datetime.now(UTC)
        if package.publish_date.tzinfo is None:
            publish_date = package.publish_date.replace(tzinfo=UTC)
        else:
            publish_date = package.publish_date
        age_days = (now - publish_date).total_seconds() / 86400

        if age_days >= self._cooldown_days:
            return ScanResult(
                scanner_name="cooldown",
                verdict="pass",
                confidence=1.0,
                details=f"Published {age_days:.1f} days ago (cooldown: {self._cooldown_days} days)",
                metadata={"age_days": round(age_days, 1), "cooldown_days": self._cooldown_days},
            )

        # Within cooldown window
        # Confidence is higher the more recently the package was published
        confidence = max(0.6, 1.0 - (age_days / self._cooldown_days))
        verdict = "fail" if self._action == "deny" else "warn"

        return ScanResult(
            scanner_name="cooldown",
            verdict=verdict,
            confidence=round(confidence, 2),
            details=(
                f"Published {age_days:.1f} days ago, within {self._cooldown_days}-day cooldown. Action: {self._action}"
            ),
            metadata={
                "age_days": round(age_days, 1),
                "cooldown_days": self._cooldown_days,
                "publish_date": publish_date.isoformat(),
            },
        )
