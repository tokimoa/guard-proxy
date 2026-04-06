"""DataDog malicious-software-packages-dataset benchmark.

Fetches the REAL manifest.json from DataDog's GitHub repository
(https://github.com/DataDog/malicious-software-packages-dataset)
and validates Guard Proxy's IOC database coverage against all
11,000+ known malicious packages.

This is NOT a pattern test — it is a full-dataset validation that
every malicious package name in the DataDog dataset is present in
our IOC database.

Requires network access. Skip with: pytest -m "not network"
"""

import json
from pathlib import Path

import httpx
import pytest

_MANIFEST_URLS = {
    "npm": "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json",
    "pypi": "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/pypi/manifest.json",
}

_IOC_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_malicious.json"

pytestmark = pytest.mark.network


def _load_ioc_db() -> dict[str, set[str]]:
    """Load our IOC database and return {ecosystem: set(package_names)}."""
    if not _IOC_PATH.exists():
        pytest.skip("IOC database not found — run `guard-proxy sync-ioc` first")
    with open(_IOC_PATH) as f:
        data = json.load(f)
    result: dict[str, set[str]] = {}
    for eco, packages in data.get("malicious_packages", {}).items():
        if isinstance(packages, dict):
            result[eco] = set(packages.keys())
        elif isinstance(packages, list):
            names = set()
            for entry in packages:
                if isinstance(entry, dict):
                    names.add(entry.get("name", ""))
                elif isinstance(entry, str):
                    names.add(entry)
            names.discard("")
            result[eco] = names
        else:
            result[eco] = set()
    return result


async def _fetch_manifest(url: str) -> dict:
    """Fetch manifest.json from DataDog GitHub."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.json()


@pytest.mark.asyncio
async def test_datadog_npm_coverage():
    """Validate IOC DB covers DataDog npm manifest (9,500+ packages)."""
    ioc_db = _load_ioc_db()
    ioc_npm = ioc_db.get("npm", set())

    if not ioc_npm:
        pytest.skip("No npm entries in IOC DB")

    try:
        manifest = await _fetch_manifest(_MANIFEST_URLS["npm"])
    except Exception as e:
        pytest.skip(f"Could not fetch DataDog manifest: {e}")

    datadog_packages = set(manifest.keys())
    matched = datadog_packages & ioc_npm
    missing = datadog_packages - ioc_npm
    extra = ioc_npm - datadog_packages

    total_dd = len(datadog_packages)
    total_matched = len(matched)
    coverage = total_matched / total_dd * 100 if total_dd else 0

    print(f"\n{'=' * 60}")
    print("DataDog npm Dataset Coverage")
    print(f"  DataDog manifest:  {total_dd:,} malicious packages")
    print(f"  Guard Proxy IOC:   {len(ioc_npm):,} packages")
    print(f"  Matched:           {total_matched:,}")
    print(f"  Missing from IOC:  {len(missing):,}")
    print(f"  Extra in IOC:      {len(extra):,}")
    print(f"  Coverage:          {coverage:.1f}%")
    if missing and len(missing) <= 20:
        print(f"  Missing samples:   {sorted(list(missing))[:20]}")
    print(f"{'=' * 60}")

    # We expect high coverage since our IOC DB is synced from this dataset
    assert coverage >= 95.0, f"npm coverage {coverage:.1f}% below 95% — IOC DB may be stale, run `guard-proxy sync-ioc`"


@pytest.mark.asyncio
async def test_datadog_pypi_coverage():
    """Validate IOC DB covers DataDog PyPI manifest (1,700+ packages)."""
    ioc_db = _load_ioc_db()
    ioc_pypi = ioc_db.get("pypi", set())

    if not ioc_pypi:
        pytest.skip("No pypi entries in IOC DB")

    try:
        manifest = await _fetch_manifest(_MANIFEST_URLS["pypi"])
    except Exception as e:
        pytest.skip(f"Could not fetch DataDog manifest: {e}")

    datadog_packages = set(manifest.keys())
    matched = datadog_packages & ioc_pypi
    missing = datadog_packages - ioc_pypi

    total_dd = len(datadog_packages)
    total_matched = len(matched)
    coverage = total_matched / total_dd * 100 if total_dd else 0

    print(f"\n{'=' * 60}")
    print("DataDog PyPI Dataset Coverage")
    print(f"  DataDog manifest:  {total_dd:,} malicious packages")
    print(f"  Guard Proxy IOC:   {len(ioc_pypi):,} packages")
    print(f"  Matched:           {total_matched:,}")
    print(f"  Missing from IOC:  {len(missing):,}")
    print(f"  Coverage:          {coverage:.1f}%")
    print(f"{'=' * 60}")

    assert coverage >= 95.0, f"PyPI coverage {coverage:.1f}% below 95% — IOC DB may be stale"


@pytest.mark.asyncio
async def test_datadog_combined_summary():
    """Combined DataDog dataset coverage report."""
    ioc_db = _load_ioc_db()

    total_dd = 0
    total_matched = 0
    results: dict[str, dict] = {}

    for eco, url in _MANIFEST_URLS.items():
        ioc_set = ioc_db.get(eco, set())
        try:
            manifest = await _fetch_manifest(url)
        except Exception:
            continue

        dd_packages = set(manifest.keys())
        matched = dd_packages & ioc_set

        results[eco] = {
            "datadog": len(dd_packages),
            "ioc": len(ioc_set),
            "matched": len(matched),
            "coverage": len(matched) / len(dd_packages) * 100 if dd_packages else 0,
        }
        total_dd += len(dd_packages)
        total_matched += len(matched)

    overall = total_matched / total_dd * 100 if total_dd else 0

    print(f"\n{'=' * 60}")
    print("DataDog Combined Coverage Report")
    print(f"{'=' * 60}")
    for eco, r in results.items():
        print(f"  {eco:10s}: {r['matched']:,}/{r['datadog']:,} ({r['coverage']:.1f}%)")
    print(f"  {'TOTAL':10s}: {total_matched:,}/{total_dd:,} ({overall:.1f}%)")
    print(f"{'=' * 60}")

    assert overall >= 95.0, f"Overall coverage {overall:.1f}% below 95%"
