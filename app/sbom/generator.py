"""CycloneDX SBOM generator.

Generates Software Bill of Materials in CycloneDX 1.6 JSON format
from Guard Proxy scan results. No external dependencies required.
"""

import json
from datetime import UTC, datetime

from app.core.version import VERSION
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo

# PURL ecosystem mapping
_PURL_ECOSYSTEM = {"npm": "npm", "pypi": "pypi", "rubygems": "gem", "go": "golang", "cargo": "cargo"}


def generate_sbom(
    package: PackageInfo,
    decision: DecisionResult,
    content_hash: str = "",
) -> dict:
    """Generate a CycloneDX 1.6 SBOM for a scanned package.

    Returns a dict that can be serialized to JSON.
    """
    purl_eco = _PURL_ECOSYSTEM.get(package.registry, package.registry)
    purl = f"pkg:{purl_eco}/{package.name}@{package.version}"

    # Build component
    component: dict = {
        "type": "library",
        "name": package.name,
        "version": package.version,
        "purl": purl,
    }

    if content_hash:
        component["hashes"] = [{"alg": "SHA-256", "content": content_hash}]

    # Add license info from scan results
    license_info = _extract_license_from_decision(decision)
    if license_info:
        component["licenses"] = [{"license": {"name": lic}} for lic in license_info]

    # Add Guard Proxy scan properties
    properties = [
        {"name": "guard-proxy:verdict", "value": decision.verdict},
        {"name": "guard-proxy:score", "value": str(round(decision.final_score, 4))},
        {"name": "guard-proxy:mode", "value": decision.mode},
        {"name": "guard-proxy:registry", "value": package.registry},
    ]

    # Add individual scanner results
    for sr in decision.scan_results:
        properties.append(
            {
                "name": f"guard-proxy:scanner:{sr.scanner_name}",
                "value": f"{sr.verdict} (confidence={sr.confidence:.2f})",
            }
        )

    component["properties"] = properties

    # Build full SBOM
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "serialNumber": f"urn:uuid:{_generate_uuid()}",
        "metadata": {
            "timestamp": datetime.now(UTC).isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "guard-proxy",
                        "version": VERSION,
                    }
                ]
            },
        },
        "components": [component],
    }

    return sbom


def sbom_to_json(sbom: dict, pretty: bool = True) -> str:
    """Serialize SBOM dict to JSON string."""
    if pretty:
        return json.dumps(sbom, indent=2, ensure_ascii=False)
    return json.dumps(sbom, separators=(",", ":"), ensure_ascii=False)


def _extract_license_from_decision(decision: DecisionResult) -> list[str]:
    """Extract normalized license list from scanner results."""
    for sr in decision.scan_results:
        if sr.scanner_name == "license_check":
            return sr.metadata.get("normalized", [])
    return []


def _generate_uuid() -> str:
    """Generate a simple UUID v4."""
    import uuid

    return str(uuid.uuid4())
