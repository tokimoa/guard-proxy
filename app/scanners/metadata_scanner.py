"""Package metadata scanner: typosquatting detection and metadata anomalies."""

import json
from pathlib import Path

from loguru import logger

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_POPULAR_PACKAGES_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "popular_packages.json"

_MIN_NAME_LENGTH = 5
_MAX_LEVENSHTEIN_DISTANCE = 2


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr_row.append(min(curr_row[j] + 1, prev_row[j + 1] + 1, prev_row[j] + cost))
        prev_row = curr_row

    return prev_row[-1]


class MetadataScanner:
    """Detect typosquatting and metadata anomalies."""

    def __init__(self) -> None:
        self._popular: dict[str, set[str]] = {}
        self._load_popular_packages()

    def _load_popular_packages(self) -> None:
        if not _POPULAR_PACKAGES_FILE.exists():
            logger.warning("Popular packages file not found: {path}", path=_POPULAR_PACKAGES_FILE)
            return

        try:
            data = json.loads(_POPULAR_PACKAGES_FILE.read_text())
            for eco, names in data.items():
                self._popular[eco] = set(names)
            total = sum(len(v) for v in self._popular.values())
            logger.info("Popular packages loaded: {total} across {n} ecosystems", total=total, n=len(self._popular))
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load popular packages: {err}", err=str(e))

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        findings: list[str] = []
        max_confidence = 0.0

        # Typosquatting check
        typo_result = self._check_typosquatting(package.name, package.registry)
        if typo_result:
            similar_name, distance = typo_result
            confidence = 0.8 if distance == 1 else 0.6
            max_confidence = max(max_confidence, confidence)
            findings.append(f"Potential typosquat of '{similar_name}' (distance={distance})")

        if not findings:
            return ScanResult(
                scanner_name="metadata_check",
                verdict="pass",
                confidence=0.9,
                details="No metadata anomalies detected",
            )

        return ScanResult(
            scanner_name="metadata_check",
            verdict="warn",
            confidence=round(max_confidence, 2),
            details="; ".join(findings),
            metadata={"findings": findings},
        )

    def _check_typosquatting(self, name: str, registry: str) -> tuple[str, int] | None:
        """Check if package name is suspiciously similar to a popular package."""
        eco_key = registry
        popular = self._popular.get(eco_key, set())
        if not popular:
            return None

        # If it IS a popular package, no typosquat
        if name in popular:
            return None

        # Only check names long enough to be meaningful
        if len(name) < _MIN_NAME_LENGTH:
            return None

        # Normalize for comparison
        normalized = name.lower().replace("_", "-")

        best_match: str | None = None
        best_distance = _MAX_LEVENSHTEIN_DISTANCE + 1

        for pop_name in popular:
            if len(pop_name) < _MIN_NAME_LENGTH:
                continue

            pop_normalized = pop_name.lower().replace("_", "-")

            # Quick length filter (distance can't be less than length difference)
            if abs(len(normalized) - len(pop_normalized)) > _MAX_LEVENSHTEIN_DISTANCE:
                continue

            dist = _levenshtein(normalized, pop_normalized)
            if 0 < dist <= _MAX_LEVENSHTEIN_DISTANCE and dist < best_distance:
                best_distance = dist
                best_match = pop_name

        if best_match:
            return best_match, best_distance
        return None
