"""Tests for heuristics scanner."""

import os
import tempfile
from pathlib import Path

from app.scanners.heuristics_scanner import HeuristicsScanner
from app.schemas.package import PackageInfo


def _scanner() -> HeuristicsScanner:
    return HeuristicsScanner()


def _pkg() -> PackageInfo:
    return PackageInfo(name="test", version="1.0.0")


def _write(content: str | bytes, suffix: str = ".js") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    if isinstance(content, bytes):
        p.write_bytes(content)
    else:
        p.write_text(content)
    return p


async def test_pass_clean_code():
    f = _write("console.log('hello world');")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_elf_binary():
    f = _write(b"\x7fELF" + b"\x00" * 100, suffix=".node")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "ELF" in result.details or "binary" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_detect_exe_extension():
    f = _write(b"MZ" + b"\x00" * 100, suffix=".exe")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_high_entropy():
    # Generate high-entropy random data
    random_data = os.urandom(1000).hex()
    f = _write(random_data)
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_pass_normal_entropy():
    normal_code = "\n".join([f"var x{i} = 'hello world {i}';" for i in range(50)])
    f = _write(normal_code)
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_suspicious_keywords():
    f = _write("function steal() { exfiltrate(credential); backdoor.connect(); }")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "warn"
        assert "exfiltrat" in result.details.lower() or "credential" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_detect_ci_conditional():
    code = "if (process.env.GITHUB_ACTIONS) { steal_secrets(); }"
    f = _write(code)
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "warn"
        assert "ci" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_empty_artifacts():
    result = await _scanner().scan(_pkg(), [])
    assert result.verdict == "pass"


async def test_skip_min_js():
    f = _write("a" * 1000, suffix=".min.js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        # .min.js should not trigger minified detection
        assert "minified" not in result.details.lower()
    finally:
        f.unlink(missing_ok=True)
