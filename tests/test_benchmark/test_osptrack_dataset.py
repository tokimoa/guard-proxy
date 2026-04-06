"""OSPTrack dataset benchmark (Zenodo DOI: 10.5281/zenodo.14197378).

Validates Guard Proxy's IOC database coverage against the OSPTrack dataset,
which contains 9,461 packages (7,499 benign + 1,962 malicious) across
npm, PyPI, RubyGems, crates.io, and Packagist.

Since the full labeled dataset (3.2GB) requires manual download, this test:
1. Downloads the metadata ZIP (4.3MB) from Zenodo
2. Extracts package names from the simulation log (simu_run.log)
3. Cross-references with our IOC database
4. Reports coverage (malicious packages detected / total in dataset)

The simulation log contains ALL packages (both malicious and benign) that
were analyzed by OSSF package-analysis. Our IOC DB should match the
malicious subset. Per the paper: ~20% of packages are malicious.

References:
- Paper: https://arxiv.org/html/2411.14829v1
- Dataset: https://zenodo.org/records/14197378
- Source: BKC + OSSF malicious-packages combined

Requires network access. Skip with: pytest -m "not network"
"""

import io
import json
import re
import zipfile
from pathlib import Path

import httpx
import pytest

_META_ZIP_URL = (
    "https://zenodo.org/api/records/14197378/files/Wapiti08/OSPTrack-v1.0.0.zip/content"
)
_IOC_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_malicious.json"
_VER_PATTERN = re.compile(r"-(\d+\.\d+[\.\d]*|nan)$")

pytestmark = pytest.mark.network


def _load_ioc_db() -> dict[str, set[str]]:
    if not _IOC_PATH.exists():
        pytest.skip("IOC database not found")
    with open(_IOC_PATH) as f:
        data = json.load(f)
    result: dict[str, set[str]] = {}
    for eco, packages in data.get("malicious_packages", {}).items():
        if isinstance(packages, list):
            names = set()
            for entry in packages:
                if isinstance(entry, dict):
                    names.add(entry.get("name", ""))
                elif isinstance(entry, str):
                    names.add(entry)
            names.discard("")
            result[eco] = names
        elif isinstance(packages, dict):
            result[eco] = set(packages.keys())
    return result


def _extract_packages_from_log(log_content: str) -> dict[str, set[str]]:
    """Parse simu_run.log to extract unique package names per ecosystem."""
    packages: dict[str, set[str]] = {}
    for line in log_content.splitlines():
        if "analyse " not in line:
            continue
        entry = line.strip().split("analyse ")[-1]
        dash = entry.find("-")
        if dash < 0:
            continue
        eco = entry[:dash]
        name_ver = entry[dash + 1 :]
        # Strip version suffix
        m = _VER_PATTERN.search(name_ver)
        name = name_ver[: m.start()] if m else name_ver
        packages.setdefault(eco, set()).add(name)
    return packages


async def _download_meta_zip() -> bytes:
    """Download the OSPTrack metadata ZIP from Zenodo."""
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(_META_ZIP_URL)
        resp.raise_for_status()
        return resp.content


def _extract_log_from_zip(zip_bytes: bytes) -> str:
    """Extract simu_run.log from the metadata ZIP."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for name in zf.namelist():
            if name.endswith("simu_run.log"):
                return zf.read(name).decode("utf-8", errors="replace")
    raise FileNotFoundError("simu_run.log not found in ZIP")


@pytest.mark.asyncio
async def test_osptrack_pypi_coverage():
    """OSPTrack PyPI: cross-reference package names with IOC DB.

    OSPTrack's PyPI subset has ~8,100 unique packages (mix of malicious + benign).
    Per the paper, ~20% are malicious. Our IOC DB should cover most of the
    malicious ones since both datasets source from OSSF/DataDog.
    """
    ioc_db = _load_ioc_db()
    ioc_pypi = ioc_db.get("pypi", set())

    try:
        zip_bytes = await _download_meta_zip()
        log = _extract_log_from_zip(zip_bytes)
    except Exception as e:
        pytest.skip(f"Could not fetch OSPTrack data: {e}")

    packages = _extract_packages_from_log(log)
    pypi_packages = packages.get("pypi", set())

    matched = pypi_packages & ioc_pypi
    total = len(pypi_packages)
    match_count = len(matched)
    match_rate = match_count / total * 100 if total else 0

    # Estimate: paper says ~20% of dataset is malicious
    # So expected malicious count ≈ total * 0.20
    estimated_malicious = int(total * 0.20)
    estimated_coverage = match_count / estimated_malicious * 100 if estimated_malicious else 0

    print(f"\n{'='*60}")
    print("OSPTrack PyPI Coverage")
    print(f"  Total packages in log:     {total:,}")
    print(f"  Matched in IOC DB:         {match_count:,}")
    print(f"  Match rate (all):          {match_rate:.1f}%")
    print(f"  Estimated malicious (~20%): {estimated_malicious:,}")
    print(f"  Estimated mal. coverage:   {estimated_coverage:.1f}%")
    print(f"{'='*60}")

    # Should match a significant portion of the malicious subset
    assert match_count >= 500, f"Only {match_count} PyPI packages matched — expected 500+"


@pytest.mark.asyncio
async def test_osptrack_npm_coverage():
    """OSPTrack npm: cross-reference with IOC DB."""
    ioc_db = _load_ioc_db()
    ioc_npm = ioc_db.get("npm", set())

    try:
        zip_bytes = await _download_meta_zip()
        log = _extract_log_from_zip(zip_bytes)
    except Exception as e:
        pytest.skip(f"Could not fetch OSPTrack data: {e}")

    packages = _extract_packages_from_log(log)
    npm_packages = packages.get("npm", set())

    matched = npm_packages & ioc_npm
    total = len(npm_packages)
    match_count = len(matched)

    estimated_malicious = int(total * 0.20)
    estimated_coverage = match_count / estimated_malicious * 100 if estimated_malicious else 0

    print(f"\n{'='*60}")
    print("OSPTrack npm Coverage")
    print(f"  Total packages in log:     {total:,}")
    print(f"  Matched in IOC DB:         {match_count:,}")
    print(f"  Estimated malicious (~20%): {estimated_malicious:,}")
    print(f"  Estimated mal. coverage:   {estimated_coverage:.1f}%")
    print(f"{'='*60}")

    # npm has fewer OSPTrack entries than PyPI
    assert match_count >= 5, f"Only {match_count} npm packages matched"


@pytest.mark.asyncio
async def test_osptrack_combined_summary():
    """OSPTrack combined summary across all ecosystems."""
    ioc_db = _load_ioc_db()

    try:
        zip_bytes = await _download_meta_zip()
        log = _extract_log_from_zip(zip_bytes)
    except Exception as e:
        pytest.skip(f"Could not fetch OSPTrack data: {e}")

    packages = _extract_packages_from_log(log)
    eco_map = {"pypi": "pypi", "npm": "npm", "rubygems": "rubygems"}

    total_packages = 0
    total_matched = 0

    print(f"\n{'='*60}")
    print("OSPTrack Combined Coverage Report")
    print(f"{'='*60}")

    for osp_eco, ioc_eco in eco_map.items():
        pkg_set = packages.get(osp_eco, set())
        ioc_set = ioc_db.get(ioc_eco, set())
        matched = pkg_set & ioc_set
        total_packages += len(pkg_set)
        total_matched += len(matched)

        est_mal = int(len(pkg_set) * 0.20)
        est_cov = len(matched) / est_mal * 100 if est_mal else 0

        print(
            f"  {osp_eco:10s}: {len(matched):5d} matched / {len(pkg_set):5d} total "
            f"(est. {est_cov:.0f}% of malicious)"
        )

    est_total_mal = int(total_packages * 0.20)
    est_overall = total_matched / est_total_mal * 100 if est_total_mal else 0

    print(f"  {'TOTAL':10s}: {total_matched:5d} matched / {total_packages:5d} total")
    print(f"  Estimated malicious coverage: {est_overall:.0f}%")
    print(f"{'='*60}")

    assert total_matched >= 500, f"Only {total_matched} total matched across all ecosystems"
