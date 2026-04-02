"""Dependency graph analysis scanner.

Detects suspicious dependency changes between package versions
using deps.dev API and existing registry data.
"""

from pathlib import Path

from loguru import logger
from packaging.version import InvalidVersion, Version

from app.core.config import Settings
from app.registry.depsdev_client import DepsDevClient
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


class DependencyScanner:
    """Detect suspicious dependency changes between versions."""

    def __init__(self, depsdev_client: DepsDevClient, settings: Settings) -> None:
        self._depsdev = depsdev_client
        self._cooldown_days = settings.cooldown_days

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        try:
            return await self._scan_impl(package)
        except Exception:
            logger.warning("Dependency scanner error for {pkg}@{ver}", pkg=package.name, ver=package.version)
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.3,
                details="Dependency analysis failed — degraded mode",
            )

    async def _scan_impl(self, package: PackageInfo) -> ScanResult:
        # Get current dependencies
        current_deps = await self._get_current_deps(package)
        if current_deps is None:
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.5,
                details="Could not retrieve dependency information",
            )

        # Find previous version
        prev_version = await self._get_previous_version(package)
        if not prev_version:
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.7,
                details="No previous version found for dependency comparison",
            )

        # Get previous version dependencies
        prev_deps = await self._get_deps_for_version(package.registry, package.name, prev_version)
        if prev_deps is None:
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.5,
                details=f"Could not fetch dependencies for previous version {prev_version}",
            )

        # Compare
        return await self._analyze_diff(package, current_deps, prev_deps, prev_version)

    async def _get_current_deps(self, package: PackageInfo) -> dict[str, str] | None:
        """Get current version dependencies."""
        # npm: already in metadata (most reliable)
        if package.registry == "npm" and package.metadata.get("dependencies"):
            return package.metadata["dependencies"]

        # PyPI: try requires_dist from metadata
        if package.registry == "pypi" and package.metadata.get("requires_dist"):
            return self._parse_requires_dist(package.metadata["requires_dist"])

        # Fallback: use deps.dev
        deps = await self._depsdev.get_dependencies(package.registry, package.name, package.version)
        if deps:
            return {d["name"]: d.get("version", "*") for d in deps if d.get("relation") == "DIRECT"}

        return None

    async def _get_previous_version(self, package: PackageInfo) -> str | None:
        """Find the version published immediately before the current one."""
        # npm: use version_times from metadata
        if package.registry == "npm":
            version_times = package.metadata.get("version_times", {})
            if version_times:
                return self._find_previous_from_times(package.version, version_times)

        # Fallback: use deps.dev version list
        versions = await self._depsdev.get_package_versions(package.registry, package.name)
        if versions:
            return self._find_previous_from_list(package.version, versions)

        return None

    async def _get_deps_for_version(self, registry: str, name: str, version: str) -> dict[str, str] | None:
        """Get dependencies for a specific version via deps.dev."""
        deps = await self._depsdev.get_dependencies(registry, name, version)
        if deps:
            return {d["name"]: d.get("version", "*") for d in deps if d.get("relation") == "DIRECT"}
        return None

    async def _analyze_diff(
        self,
        package: PackageInfo,
        current: dict[str, str],
        previous: dict[str, str],
        prev_version: str,
    ) -> ScanResult:
        new_deps = {k: v for k, v in current.items() if k not in previous}

        if not new_deps:
            # Check for wildcard version ranges
            widened = self._check_widened_ranges(current, previous)
            if widened:
                return ScanResult(
                    scanner_name="dependency_check",
                    verdict="warn",
                    confidence=0.5,
                    details=f"Dependency ranges widened: {', '.join(widened)}",
                    metadata={"widened": widened, "prev_version": prev_version},
                )
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.9,
                details=f"No new dependencies added (compared to v{prev_version})",
            )

        # Analyze each new dependency — only flag if ALL are unknown on deps.dev
        unknown_deps: list[str] = []
        known_deps: list[str] = []
        for dep_name in new_deps:
            ver_str = new_deps[dep_name].lstrip("^~>=< ")
            info = await self._depsdev.get_version_info(package.registry, dep_name, ver_str)
            if info is None:
                unknown_deps.append(dep_name)
            else:
                known_deps.append(dep_name)

        # All new deps are established on deps.dev → pass with info
        if not unknown_deps:
            return ScanResult(
                scanner_name="dependency_check",
                verdict="pass",
                confidence=0.8,
                details=f"{len(new_deps)} new dep(s) added vs v{prev_version}: {', '.join(new_deps.keys())}",
                metadata={"new_deps": list(new_deps.keys()), "prev_version": prev_version},
            )

        # Some new deps are unknown — warn only if they form the majority
        if len(unknown_deps) > len(known_deps):
            confidence = min(0.7, 0.4 + len(unknown_deps) * 0.1)
            return ScanResult(
                scanner_name="dependency_check",
                verdict="warn",
                confidence=round(confidence, 2),
                details=f"New deps not found on deps.dev: {', '.join(unknown_deps)}",
                metadata={
                    "new_deps": list(new_deps.keys()),
                    "unknown_deps": unknown_deps,
                    "prev_version": prev_version,
                },
            )

        # Mix of known and unknown — informational pass
        return ScanResult(
            scanner_name="dependency_check",
            verdict="pass",
            confidence=0.7,
            details=f"{len(new_deps)} new dep(s) added vs v{prev_version}; {len(unknown_deps)} not on deps.dev",
            metadata={"new_deps": list(new_deps.keys()), "unknown_deps": unknown_deps, "prev_version": prev_version},
        )

    @staticmethod
    def _find_previous_from_times(current: str, version_times: dict[str, str]) -> str | None:
        """Find previous version using npm's time field."""
        # Filter out non-version keys like "created", "modified"
        versions_with_time = []
        for ver, ts in version_times.items():
            if ver in ("created", "modified"):
                continue
            versions_with_time.append((ver, ts))

        # Sort by timestamp
        versions_with_time.sort(key=lambda x: x[1])

        # Find current version and return the one before it
        for i, (ver, _) in enumerate(versions_with_time):
            if ver == current and i > 0:
                return versions_with_time[i - 1][0]

        return None

    @staticmethod
    def _find_previous_from_list(current: str, versions: list[str]) -> str | None:
        """Find previous version from ordered version list."""
        try:
            current_ver = Version(current)
        except InvalidVersion:
            return None

        # Filter valid versions and sort
        valid = []
        for v in versions:
            try:
                valid.append(Version(v))
            except InvalidVersion:
                continue

        valid.sort()

        # Find the version just before current
        for i, v in enumerate(valid):
            if v == current_ver and i > 0:
                return str(valid[i - 1])

        return None

    @staticmethod
    def _parse_requires_dist(requires: list[str]) -> dict[str, str]:
        """Parse PyPI requires_dist list into dep name->version dict."""
        deps: dict[str, str] = {}
        for req in requires:
            # Format: "requests (>=2.20)" or "requests>=2.20" or "requests ; extra == 'test'"
            if ";" in req and "extra" in req:
                continue  # skip optional/extra deps
            name = req.split("(")[0].split(">")[0].split("<")[0].split("=")[0].split("!")[0].split(";")[0].strip()
            if name:
                deps[name] = req
        return deps

    @staticmethod
    def _check_widened_ranges(current: dict[str, str], previous: dict[str, str]) -> list[str]:
        """Detect deps whose version range was widened suspiciously."""
        widened = []
        for name, cur_range in current.items():
            if name in previous:
                prev_range = previous[name]
                if cur_range != prev_range:
                    # Detect obvious widenings: specific -> * or >= 0
                    if cur_range in ("*", ">=0", ">=0.0.0", "latest") and prev_range not in ("*", ">=0"):
                        widened.append(f"{name}: {prev_range} → {cur_range}")
        return widened
