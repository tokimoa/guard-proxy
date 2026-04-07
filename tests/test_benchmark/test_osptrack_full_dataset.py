"""OSPTrack full labeled dataset benchmark.

Uses the REAL label_data.csv from the OSPTrack Zenodo dataset
(DOI: 10.5281/zenodo.14197378) containing 9,461 packages with
ground-truth labels (1,962 malicious + 7,499 benign).

This test validates:
1. IOC DB recall: how many malicious packages are in our IOC database
2. False positive rate: how many benign packages are incorrectly flagged
3. Ecosystem breakdown: per-registry detection performance

The OSPTrack dataset uses OSSF package-analysis (dynamic execution)
to label packages. Detection via our IOC DB (name-based) represents
one layer of our multi-layer defense. Static analysis, YARA, AST,
heuristics, and LLM tiers provide additional coverage at scan time.

Requires: data/OSPtrack/data/label_data.csv (from Zenodo download)
"""

import csv
import sys
from collections import Counter
from pathlib import Path

import pytest

_LABEL_DATA_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "OSPtrack" / "data" / "label_data.csv"
_IOC_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_malicious.json"

_ECO_MAP = {"pypi": "pypi", "npm": "npm", "rubygems": "rubygems", "crates.io": "cargo"}


def _load_ioc_db() -> dict[str, set[str]]:
    import json

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


def _load_osptrack_labels() -> list[dict]:
    """Load labeled data from OSPTrack CSV."""
    if not _LABEL_DATA_PATH.exists():
        pytest.skip("OSPTrack label_data.csv not found — download from https://zenodo.org/records/14197378")

    csv.field_size_limit(sys.maxsize)
    rows = []
    with open(_LABEL_DATA_PATH, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            eco = row.get("Ecosystem", "")
            if eco not in _ECO_MAP:
                continue
            rows.append(
                {
                    "ecosystem": eco,
                    "name": row.get("Name", ""),
                    "version": row.get("Version", ""),
                    "label": int(row.get("Label", "0")),
                    "sub_label": row.get("Sub_Label", ""),
                }
            )
    return rows


def test_osptrack_full_dataset_summary():
    """OSPTrack full dataset: label distribution."""
    rows = _load_osptrack_labels()

    eco_counts: dict[str, Counter] = {}
    for row in rows:
        eco = row["ecosystem"]
        eco_counts.setdefault(eco, Counter())
        eco_counts[eco]["total"] += 1
        if row["label"] == 1:
            eco_counts[eco]["malicious"] += 1
        else:
            eco_counts[eco]["benign"] += 1

    total = sum(c["total"] for c in eco_counts.values())
    total_mal = sum(c["malicious"] for c in eco_counts.values())

    print(f"\n{'=' * 60}")
    print("OSPTrack Dataset Summary")
    print(f"{'=' * 60}")
    print(f"  {'Ecosystem':12s} {'Total':>7s} {'Malicious':>10s} {'Benign':>7s}")
    print(f"  {'-' * 40}")
    for eco in sorted(eco_counts):
        c = eco_counts[eco]
        print(f"  {eco:12s} {c['total']:7d} {c['malicious']:10d} {c['benign']:7d}")
    print(f"  {'-' * 40}")
    print(f"  {'TOTAL':12s} {total:7d} {total_mal:10d} {total - total_mal:7d}")
    print(f"{'=' * 60}")

    assert total >= 9000, f"Expected 9000+ rows, got {total}"
    assert total_mal >= 1900, f"Expected 1900+ malicious, got {total_mal}"


def test_osptrack_ioc_recall():
    """OSPTrack: IOC database recall against 1,962 malicious packages."""
    rows = _load_osptrack_labels()
    ioc_db = _load_ioc_db()

    matched = Counter()
    total_mal = Counter()
    false_positives = Counter()

    for row in rows:
        eco_raw = row["ecosystem"]
        ioc_eco = _ECO_MAP.get(eco_raw, "")
        ioc_set = ioc_db.get(ioc_eco, set())
        name = row["name"]
        in_ioc = name in ioc_set

        if row["label"] == 1:
            total_mal[eco_raw] += 1
            if in_ioc:
                matched[eco_raw] += 1
        else:
            if in_ioc:
                false_positives[eco_raw] += 1

    total_m = sum(total_mal.values())
    total_mt = sum(matched.values())
    total_fp = sum(false_positives.values())
    recall = total_mt / total_m * 100 if total_m else 0

    print(f"\n{'=' * 60}")
    print("OSPTrack IOC Recall (name-based detection layer)")
    print(f"{'=' * 60}")
    print(f"  {'Ecosystem':12s} {'Malicious':>10s} {'Detected':>9s} {'Recall':>8s} {'FP':>5s}")
    print(f"  {'-' * 48}")
    for eco in ["npm", "pypi", "rubygems", "crates.io"]:
        m = total_mal[eco]
        mt = matched[eco]
        fp = false_positives[eco]
        r = mt / m * 100 if m else 0
        print(f"  {eco:12s} {m:10d} {mt:9d} {r:7.1f}% {fp:5d}")
    print(f"  {'-' * 48}")
    print(f"  {'TOTAL':12s} {total_m:10d} {total_mt:9d} {recall:7.1f}% {total_fp:5d}")
    print(f"{'=' * 60}")
    print()
    print("  Note: IOC is ONE layer of multi-layer defense.")
    print("  At scan time, Static Analysis + YARA + AST + Heuristics +")
    print("  Reachability + LLM provide additional detection coverage.")
    print("  OSPTrack uses dynamic analysis labels; many malicious packages")
    print("  have names not present in the DataDog IOC dataset.")

    # IOC alone won't catch everything — this is expected
    # The important metric is that FP rate is very low
    assert total_fp <= 20, f"Too many false positives: {total_fp}"


def test_osptrack_false_positive_rate():
    """OSPTrack: verify benign packages are NOT flagged by IOC DB."""
    rows = _load_osptrack_labels()
    ioc_db = _load_ioc_db()

    benign_total = 0
    benign_flagged = 0
    flagged_details = []

    for row in rows:
        if row["label"] != 0:
            continue
        eco_raw = row["ecosystem"]
        ioc_eco = _ECO_MAP.get(eco_raw, "")
        ioc_set = ioc_db.get(ioc_eco, set())
        name = row["name"]
        benign_total += 1
        if name in ioc_set:
            benign_flagged += 1
            flagged_details.append(f"{eco_raw}/{name}")

    fp_rate = benign_flagged / benign_total * 100 if benign_total else 0

    print(f"\n{'=' * 60}")
    print("OSPTrack False Positive Analysis")
    print(f"{'=' * 60}")
    print(f"  Benign packages:  {benign_total:,}")
    print(f"  Incorrectly flagged: {benign_flagged}")
    print(f"  FP rate:          {fp_rate:.3f}%")
    if flagged_details:
        print(f"  Flagged packages: {flagged_details[:10]}")
    print(f"{'=' * 60}")

    # FP rate should be extremely low
    assert fp_rate < 0.5, f"FP rate {fp_rate:.3f}% exceeds 0.5% threshold"


def test_osptrack_sublabel_coverage():
    """OSPTrack: detection by attack sub-label category."""
    rows = _load_osptrack_labels()
    ioc_db = _load_ioc_db()

    sublabel_total = Counter()
    sublabel_matched = Counter()

    for row in rows:
        if row["label"] != 1:
            continue
        sl = row["sub_label"]
        if not sl:
            sl = "unknown"
        eco_raw = row["ecosystem"]
        ioc_eco = _ECO_MAP.get(eco_raw, "")
        ioc_set = ioc_db.get(ioc_eco, set())

        sublabel_total[sl] += 1
        if row["name"] in ioc_set:
            sublabel_matched[sl] += 1

    print(f"\n{'=' * 60}")
    print("OSPTrack Detection by Attack Sub-Label")
    print(f"{'=' * 60}")
    for sl in sorted(sublabel_total, key=sublabel_total.get, reverse=True):
        t = sublabel_total[sl]
        m = sublabel_matched[sl]
        r = m / t * 100 if t else 0
        print(f"  {sl:40s}: {m:4d}/{t:4d} ({r:5.1f}%)")
    print(f"{'=' * 60}")
