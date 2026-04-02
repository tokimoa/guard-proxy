"""DataDog malicious-software-packages-dataset sync.

Downloads manifest.json files from DataDog's public GitHub repository
and imports package names into the local IOC database.

Source: https://github.com/DataDog/malicious-software-packages-dataset
"""

import json

import httpx
from loguru import logger

_BASE_URL = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples"
_ECOSYSTEMS = {
    "npm": f"{_BASE_URL}/npm/manifest.json",
    "pypi": f"{_BASE_URL}/pypi/manifest.json",
}


async def fetch_datadog_manifests(timeout: float = 30.0) -> dict[str, dict[str, list[str] | None]]:
    """Fetch manifest.json files from DataDog's GitHub repository.

    Returns:
        Dict of {ecosystem: {package_name: [versions] or None}}.
        None means all versions are malicious.
    """
    result: dict[str, dict[str, list[str] | None]] = {}

    async with httpx.AsyncClient(timeout=timeout) as client:
        for eco, url in _ECOSYSTEMS.items():
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    result[eco] = data
                    logger.info(
                        "DataDog manifest fetched: {eco} = {count} packages",
                        eco=eco,
                        count=len(data),
                    )
                else:
                    logger.warning(
                        "DataDog manifest fetch failed: {eco} HTTP {status}",
                        eco=eco,
                        status=resp.status_code,
                    )
            except Exception:
                logger.exception("DataDog manifest fetch error: {eco}", eco=eco)

    return result


def merge_into_known_malicious(
    current_data: dict,
    datadog_manifests: dict[str, dict[str, list[str] | None]],
) -> dict:
    """Merge DataDog manifest data into known_malicious.json format.

    Returns updated data dict (does not write to file).
    """
    malicious = current_data.get("malicious_packages", {})

    for eco, manifest in datadog_manifests.items():
        eco_key = eco  # "npm" or "pypi"
        existing = {e["name"]: e for e in malicious.get(eco_key, [])}

        for pkg_name, versions in manifest.items():
            if pkg_name in existing:
                # Merge versions
                if versions is not None:
                    old_versions = set(existing[pkg_name].get("versions", []))
                    old_versions.update(versions)
                    existing[pkg_name]["versions"] = sorted(old_versions)
            else:
                entry = {
                    "name": pkg_name,
                    "versions": sorted(versions) if versions else [],
                    "type": "datadog_dataset",
                    "description": "From DataDog malicious-software-packages-dataset",
                }
                existing[pkg_name] = entry

        malicious[eco_key] = list(existing.values())

    current_data["malicious_packages"] = malicious

    # Update stats
    total = sum(len(v) for v in malicious.values())
    logger.info("IOC database updated: {total} total entries", total=total)

    return current_data


async def check_high_impact_new_entries(
    new_entries: list[dict],
    ecosystem: str,
    download_threshold: int = 10000,
) -> list[dict]:
    """Check if newly added IOC entries have high download counts.

    High download counts on a malicious package = widespread compromise.
    Returns list of high-impact entries with download data.
    """
    if not new_entries:
        return []

    high_impact: list[dict] = []

    async with httpx.AsyncClient(timeout=10.0) as client:
        for entry in new_entries[:50]:  # Check max 50 new entries
            name = entry["name"]
            downloads = 0

            try:
                if ecosystem == "npm":
                    resp = await client.get(f"https://api.npmjs.org/downloads/point/last-week/{name}")
                    if resp.status_code == 200:
                        downloads = resp.json().get("downloads", 0)
                elif ecosystem == "pypi":
                    resp = await client.get(f"https://pypistats.org/api/packages/{name}/recent")
                    if resp.status_code == 200:
                        data = resp.json().get("data", {})
                        downloads = data.get("last_week", 0)
            except Exception:
                continue

            if downloads >= download_threshold:
                high_impact.append(
                    {
                        "name": name,
                        "ecosystem": ecosystem,
                        "weekly_downloads": downloads,
                        "severity": "CRITICAL" if downloads >= 100000 else "HIGH",
                    }
                )
                logger.warning(
                    "HIGH-IMPACT malicious package: {eco}/{name} ({downloads:,} downloads/week)",
                    eco=ecosystem,
                    name=name,
                    downloads=downloads,
                )

    return high_impact


async def sync_datadog_to_file(ioc_file_path: str) -> dict:
    """Full sync: fetch DataDog manifests and merge into IOC file.

    Returns the updated data dict.
    """
    import pathlib

    ioc_path = pathlib.Path(ioc_file_path)

    # Load current IOC data
    if ioc_path.exists():
        current = json.loads(ioc_path.read_text())
    else:
        current = {"malicious_packages": {"npm": [], "pypi": [], "rubygems": []}, "c2_domains": [], "c2_ips": []}

    # Fetch DataDog manifests
    manifests = await fetch_datadog_manifests()
    if not manifests:
        logger.warning("No DataDog manifests fetched — skipping sync")
        return current

    # Track new entries before merge
    old_names: dict[str, set[str]] = {}
    for eco, entries in current.get("malicious_packages", {}).items():
        old_names[eco] = {e["name"] for e in entries}

    # Merge
    updated = merge_into_known_malicious(current, manifests)

    # Identify newly added entries
    all_high_impact: list[dict] = []
    for eco, entries in updated.get("malicious_packages", {}).items():
        new_entries = [e for e in entries if e["name"] not in old_names.get(eco, set())]
        if new_entries:
            logger.info("{count} new {eco} IOC entries", count=len(new_entries), eco=eco)
            # Check download counts for new entries
            high_impact = await check_high_impact_new_entries(new_entries, eco)
            all_high_impact.extend(high_impact)

    if all_high_impact:
        logger.warning(
            "⚠ {count} HIGH-IMPACT malicious packages detected!",
            count=len(all_high_impact),
        )
        updated["_high_impact_alerts"] = all_high_impact

    # Write back
    ioc_path.write_text(json.dumps(updated, indent=2, ensure_ascii=False) + "\n")
    logger.info("IOC file updated: {path}", path=ioc_path)

    return updated
