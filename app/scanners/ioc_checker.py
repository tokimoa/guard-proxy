"""IOC (Indicator of Compromise) checker scanner.

Checks packages against the known malicious package database and scans
artifact content for known C2 domains/IPs.
"""

import json
import re
from pathlib import Path

from loguru import logger

from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_IOC_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "known_malicious.json"


class IOCDatabase:
    """In-memory IOC database loaded from known_malicious.json."""

    def __init__(self) -> None:
        self._npm_packages: dict[str, set[str]] = {}
        self._pypi_packages: dict[str, set[str]] = {}
        self._rubygems_packages: dict[str, set[str]] = {}
        self._c2_domains: list[tuple[str, re.Pattern[str]]] = []
        self._c2_domain_suffixes: list[str] = []
        self._c2_ips: list[tuple[str, re.Pattern[str]]] = []
        self._malicious_hashes: set[str] = set()
        self._load()

    def _load(self) -> None:
        if not _IOC_FILE.exists():
            logger.warning("IOC database not found: {path}", path=_IOC_FILE)
            return

        try:
            data = json.loads(_IOC_FILE.read_text())
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Failed to load IOC database: {err}", err=str(e))
            return

        for entry in data.get("malicious_packages", {}).get("npm", []):
            self._npm_packages[entry["name"]] = set(entry.get("versions", []))

        for entry in data.get("malicious_packages", {}).get("pypi", []):
            self._pypi_packages[entry["name"]] = set(entry.get("versions", []))

        for entry in data.get("malicious_packages", {}).get("rubygems", []):
            self._rubygems_packages[entry["name"]] = set(entry.get("versions", []))

        self._c2_domains = [
            (domain, re.compile(r"(?<![a-zA-Z0-9.-])" + re.escape(domain.lower()) + r"(?![a-zA-Z0-9.-])"))
            for domain in data.get("c2_domains", [])
        ]
        self._c2_domain_suffixes = data.get("c2_domain_suffixes", [])
        self._c2_ips = [(ip, re.compile(r"(?<!\d)" + re.escape(ip) + r"(?!\d)")) for ip in data.get("c2_ips", [])]
        self._malicious_hashes = set(data.get("malicious_hashes", {}).get("sha256", []))

        total_pkgs = len(self._npm_packages) + len(self._pypi_packages) + len(self._rubygems_packages)
        logger.info(
            "IOC database loaded: {pkgs} packages, {domains} C2 domains, {ips} C2 IPs",
            pkgs=total_pkgs,
            domains=len(self._c2_domains),
            ips=len(self._c2_ips),
        )

    def is_known_malicious(self, registry: str, name: str, version: str) -> str | None:
        """Check if package@version is in the known malicious list.
        Returns description if found, None otherwise.
        """
        registry_map = {"npm": self._npm_packages, "pypi": self._pypi_packages, "rubygems": self._rubygems_packages}
        db = registry_map.get(registry, {})
        known_versions = db.get(name)
        if known_versions is not None and version in known_versions:
            return f"Known malicious package: {name}@{version}"
        return None

    def check_content_for_iocs(self, content: str) -> list[str]:
        """Scan content for known C2 domains, domain suffixes, and IPs."""
        findings: list[str] = []
        content_lower = content.lower()
        for domain, pattern in self._c2_domains:
            if pattern.search(content_lower):
                findings.append(f"Known C2 domain: {domain}")
        for suffix in self._c2_domain_suffixes:
            if suffix.lower() in content_lower:
                findings.append(f"Known C2 domain suffix: *{suffix}")
        for ip, pattern in self._c2_ips:
            if pattern.search(content):
                findings.append(f"Known C2 IP: {ip}")
        return findings


# Singleton
_ioc_db: IOCDatabase | None = None


def get_ioc_database() -> IOCDatabase:
    global _ioc_db
    if _ioc_db is None:
        _ioc_db = IOCDatabase()
    return _ioc_db


class IOCScanner:
    """Scanner that checks against the IOC database."""

    def __init__(self) -> None:
        self._db = get_ioc_database()

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        # Check if package itself is known malicious
        known = self._db.is_known_malicious(package.registry, package.name, package.version)
        if known:
            return ScanResult(
                scanner_name="ioc_check",
                verdict="fail",
                confidence=1.0,
                details=known,
                metadata={"known_malicious": True},
            )

        # Check artifact content for IOCs
        all_findings: list[str] = []
        for path in artifacts:
            if path.exists() and path.is_file():
                try:
                    content = path.read_text(errors="replace")
                    findings = self._db.check_content_for_iocs(content)
                    all_findings.extend(findings)
                except OSError:
                    continue

        if all_findings:
            return ScanResult(
                scanner_name="ioc_check",
                verdict="fail",
                confidence=0.95,
                details="IOC matches found: " + "; ".join(all_findings[:5]),
                metadata={"ioc_findings": all_findings},
            )

        return ScanResult(
            scanner_name="ioc_check",
            verdict="pass",
            confidence=1.0,
            details="No known IOCs detected",
        )
