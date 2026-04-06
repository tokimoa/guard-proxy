"""License compliance scanner.

Checks package licenses against configurable allow/deny policies.
Extracts license info from package metadata and validates against
SPDX identifiers.
"""

import re
from pathlib import Path

from loguru import logger

from app.core.config import Settings
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

# Common SPDX license identifiers (subset for validation)
_KNOWN_SPDX: set[str] = {
    "0BSD",
    "AAL",
    "AFL-3.0",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "Apache-1.1",
    "Apache-2.0",
    "APSL-2.0",
    "Artistic-2.0",
    "BlueOak-1.0.0",
    "BSD-1-Clause",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-3-Clause-LBNL",
    "BSL-1.0",
    "CAL-1.0",
    "CAL-1.0-Combined-Work-Exception",
    "CDDL-1.0",
    "CECILL-2.1",
    "CPAL-1.0",
    "CPL-1.0",
    "CUA-OPL-1.0",
    "ECL-2.0",
    "EFL-2.0",
    "EPL-1.0",
    "EPL-2.0",
    "EUDatagrid",
    "EUPL-1.1",
    "EUPL-1.2",
    "FSFAP",
    "FTPL",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "HPND",
    "Intel",
    "IPA",
    "IPL-1.0",
    "ISC",
    "JSON",
    "LAL-1.2",
    "LAL-1.3",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "LiLiQ-P-1.1",
    "LiLiQ-R-1.1",
    "LiLiQ-Rplus-1.1",
    "LPL-1.0",
    "LPL-1.02",
    "LPPL-1.3c",
    "MirOS",
    "MIT",
    "MIT-0",
    "Motosoto",
    "MPL-1.1",
    "MPL-2.0",
    "MPL-2.0-no-copyleft-exception",
    "MS-PL",
    "MS-RL",
    "MulanPSL-2.0",
    "Multics",
    "NASA-1.3",
    "NCSA",
    "NGPL",
    "Nokia",
    "NPOSL-3.0",
    "NTP",
    "OCLC-2.0",
    "OFL-1.1",
    "OGTSL",
    "OLDAP-2.8",
    "OSET-PL-2.1",
    "OSL-3.0",
    "PHP-3.01",
    "PostgreSQL",
    "PSF-2.0",
    "QPL-1.0",
    "RPL-1.1",
    "RPL-1.5",
    "RPSL-1.0",
    "RSCPL",
    "SimPL-2.0",
    "SISSL",
    "Sleepycat",
    "SPL-1.0",
    "UCL-1.0",
    "Unicode-DFS-2016",
    "Unlicense",
    "UPL-1.0",
    "VSL-1.0",
    "W3C",
    "Watcom-1.0",
    "WTFPL",
    "Xnet",
    "Zlib",
    "ZPL-2.0",
    "ZPL-2.1",
}

# Mapping of common non-SPDX license strings to SPDX identifiers
_LICENSE_ALIASES: dict[str, str] = {
    "mit": "MIT",
    "isc": "ISC",
    "bsd": "BSD-3-Clause",
    "bsd-2-clause": "BSD-2-Clause",
    "bsd-3-clause": "BSD-3-Clause",
    "apache 2.0": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "apache license 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license": "Apache-2.0",
    "gpl-2.0": "GPL-2.0-only",
    "gpl-3.0": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only",
    "gplv3": "GPL-3.0-only",
    "gnu general public license v2": "GPL-2.0-only",
    "gnu general public license v3": "GPL-3.0-only",
    "lgpl-2.1": "LGPL-2.1-only",
    "lgpl-3.0": "LGPL-3.0-only",
    "lgplv2.1": "LGPL-2.1-only",
    "lgplv3": "LGPL-3.0-only",
    "agpl-3.0": "AGPL-3.0-only",
    "mpl-2.0": "MPL-2.0",
    "unlicense": "Unlicense",
    "public domain": "Unlicense",
    "wtfpl": "WTFPL",
    "artistic-2.0": "Artistic-2.0",
    "zlib": "Zlib",
    "postgresql": "PostgreSQL",
    "0bsd": "0BSD",
    "cc0-1.0": "CC0-1.0",
}

# Pattern to split SPDX expressions: "MIT OR Apache-2.0", "Apache-2.0 AND MIT"
_SPDX_SPLIT = re.compile(r"\s+(?:OR|AND|WITH)\s+", re.IGNORECASE)

# Copyleft license families (commonly restricted in commercial use)
_COPYLEFT_FAMILIES: set[str] = {
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "LGPL-2.0-only",
    "LGPL-2.0-or-later",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "EUPL-1.1",
    "EUPL-1.2",
    "OSL-3.0",
    "CPAL-1.0",
    "CPL-1.0",
    "EPL-1.0",
    "EPL-2.0",
    "CECILL-2.1",
    "RPL-1.1",
    "RPL-1.5",
    "Sleepycat",
}


def normalize_license(raw: str) -> list[str]:
    """Normalize a raw license string into a list of SPDX identifiers.

    Handles SPDX expressions (OR/AND), common aliases, and strips
    parentheses/whitespace.
    """
    if not raw or not raw.strip():
        return []

    raw = raw.strip().strip("()")

    # Split SPDX expression
    parts = _SPDX_SPLIT.split(raw)

    result: list[str] = []
    for part in parts:
        part = part.strip().strip("()")
        if not part:
            continue
        # Check exact SPDX match (case-sensitive)
        if part in _KNOWN_SPDX:
            result.append(part)
            continue
        # Check alias (case-insensitive)
        alias = _LICENSE_ALIASES.get(part.lower())
        if alias:
            result.append(alias)
            continue
        # Not recognized — keep as-is for reporting
        result.append(part)

    return result


def extract_license_from_metadata(registry: str, metadata: dict) -> str:
    """Extract license string from package metadata based on registry type."""
    license_str = metadata.get("license", "")
    if license_str:
        return str(license_str)

    # PyPI: try classifiers
    if registry == "pypi":
        classifiers = metadata.get("classifiers", [])
        for c in classifiers:
            if isinstance(c, str) and c.startswith("License :: OSI Approved :: "):
                return c.split(" :: ")[-1]

    return ""


class LicenseScanner:
    """Check package license against configurable policy.

    Extracts license from package metadata and checks against
    denied/allowed license lists. Supports SPDX expressions.
    """

    def __init__(self, settings: Settings) -> None:
        self._denied = {s.strip() for s in settings.license_denied_list if s.strip()}
        self._allowed = {s.strip() for s in settings.license_allowed_list if s.strip()}
        self._action = settings.license_check_action
        self._copyleft_action = settings.license_copyleft_action

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        raw_license = extract_license_from_metadata(package.registry, package.metadata)

        if not raw_license:
            return ScanResult(
                scanner_name="license_check",
                verdict="pass",
                confidence=0.3,
                details="No license metadata found",
                metadata={"license": "", "normalized": []},
            )

        normalized = normalize_license(raw_license)

        if not normalized:
            return ScanResult(
                scanner_name="license_check",
                verdict="pass",
                confidence=0.3,
                details=f"Could not parse license: {raw_license}",
                metadata={"license": raw_license, "normalized": []},
            )

        # Check denied list
        denied_matches = [lic for lic in normalized if lic in self._denied]
        if denied_matches:
            verdict = "fail" if self._action == "deny" else "warn"
            return ScanResult(
                scanner_name="license_check",
                verdict=verdict,
                confidence=0.95,
                details=f"Denied license(s): {', '.join(denied_matches)}",
                metadata={"license": raw_license, "normalized": normalized, "denied": denied_matches},
            )

        # Check allowed list (if configured, anything not in allowed is flagged)
        if self._allowed:
            not_allowed = [lic for lic in normalized if lic not in self._allowed]
            if not_allowed:
                verdict = "fail" if self._action == "deny" else "warn"
                return ScanResult(
                    scanner_name="license_check",
                    verdict=verdict,
                    confidence=0.9,
                    details=f"License(s) not in allowed list: {', '.join(not_allowed)}",
                    metadata={"license": raw_license, "normalized": normalized, "not_allowed": not_allowed},
                )

        # Check copyleft
        copyleft_matches = [lic for lic in normalized if lic in _COPYLEFT_FAMILIES]
        if copyleft_matches and self._copyleft_action != "allow":
            verdict = "fail" if self._copyleft_action == "deny" else "warn"
            return ScanResult(
                scanner_name="license_check",
                verdict=verdict,
                confidence=0.85,
                details=f"Copyleft license(s) detected: {', '.join(copyleft_matches)}",
                metadata={"license": raw_license, "normalized": normalized, "copyleft": copyleft_matches},
            )

        logger.debug(
            "License OK for {pkg}: {lic}",
            pkg=package.name,
            lic=", ".join(normalized),
        )

        return ScanResult(
            scanner_name="license_check",
            verdict="pass",
            confidence=0.9,
            details=f"License: {', '.join(normalized)}",
            metadata={"license": raw_license, "normalized": normalized},
        )
