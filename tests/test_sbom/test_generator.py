"""Tests for SBOM generator."""

import json

from app.sbom.generator import generate_sbom, sbom_to_json
from app.schemas.decision import DecisionResult
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult


def _make_decision():
    return DecisionResult(
        verdict="allow",
        final_score=0.0,
        scan_results=[
            ScanResult(scanner_name="ioc_check", verdict="pass", confidence=1.0, details="ok"),
            ScanResult(scanner_name="static_analysis", verdict="pass", confidence=0.9, details="ok"),
        ],
        reason="test",
        mode="warn",
    )


def test_generate_sbom_basic():
    pkg = PackageInfo(name="express", version="4.21.2", registry="npm")
    decision = _make_decision()
    sbom = generate_sbom(pkg, decision, content_hash="abc123")

    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.6"
    assert len(sbom["components"]) == 1

    comp = sbom["components"][0]
    assert comp["name"] == "express"
    assert comp["version"] == "4.21.2"
    assert comp["purl"] == "pkg:npm/express@4.21.2"
    assert comp["hashes"][0]["alg"] == "SHA-256"
    assert comp["hashes"][0]["content"] == "abc123"


def test_sbom_contains_scan_properties():
    pkg = PackageInfo(name="flask", version="3.1.1", registry="pypi")
    decision = _make_decision()
    sbom = generate_sbom(pkg, decision)

    comp = sbom["components"][0]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["guard-proxy:verdict"] == "allow"
    assert props["guard-proxy:score"] == "0.0"
    assert props["guard-proxy:mode"] == "warn"
    assert props["guard-proxy:registry"] == "pypi"
    assert "guard-proxy:scanner:ioc_check" in props
    assert "guard-proxy:scanner:static_analysis" in props


def test_sbom_purl_pypi():
    pkg = PackageInfo(name="requests", version="2.32.3", registry="pypi")
    sbom = generate_sbom(pkg, _make_decision())
    assert sbom["components"][0]["purl"] == "pkg:pypi/requests@2.32.3"


def test_sbom_purl_rubygems():
    pkg = PackageInfo(name="rails", version="7.1.0", registry="rubygems")
    sbom = generate_sbom(pkg, _make_decision())
    assert sbom["components"][0]["purl"] == "pkg:gem/rails@7.1.0"


def test_sbom_to_json():
    pkg = PackageInfo(name="test", version="1.0.0", registry="npm")
    sbom = generate_sbom(pkg, _make_decision())
    json_str = sbom_to_json(sbom)
    parsed = json.loads(json_str)
    assert parsed["bomFormat"] == "CycloneDX"


def test_sbom_metadata_contains_tool():
    pkg = PackageInfo(name="test", version="1.0.0", registry="npm")
    sbom = generate_sbom(pkg, _make_decision())
    tools = sbom["metadata"]["tools"]["components"]
    assert any(t["name"] == "guard-proxy" for t in tools)


def test_sbom_has_serial_number():
    pkg = PackageInfo(name="test", version="1.0.0", registry="npm")
    sbom = generate_sbom(pkg, _make_decision())
    assert sbom["serialNumber"].startswith("urn:uuid:")
