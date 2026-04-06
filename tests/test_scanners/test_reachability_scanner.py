"""Tests for reachability analysis scanner."""

import tempfile
from pathlib import Path

import pytest

from app.scanners.reachability_scanner import ReachabilityScanner
from app.schemas.package import PackageInfo


def _pkg() -> PackageInfo:
    return PackageInfo(name="test", version="1.0.0")


def _write(content: str, suffix: str = ".py") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_text(content)
    return p


@pytest.fixture
def scanner():
    return ReachabilityScanner()


# -- Python reachability --


class TestPythonReachability:
    @pytest.mark.asyncio
    async def test_reachable_eval_in_module_level(self, scanner):
        f = _write("eval('malicious')")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_unreachable_eval_in_dead_function(self, scanner):
        code = """\
def helper():
    print("safe")

def never_called():
    eval("dangerous")

helper()
"""
        f = _write(code)
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "pass"
            assert result.metadata.get("unreachable_count", 0) >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_reachable_via_call_chain(self, scanner):
        code = """\
def inner():
    exec("payload")

def outer():
    inner()

outer()
"""
        f = _write(code)
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_entry_point_init(self, scanner):
        code = """\
def __init__(self):
    os.system("cmd")

def unreachable():
    eval("x")
"""
        f = _write(code)
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_clean_code_passes(self, scanner):
        code = """\
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b

result = add(1, 2)
"""
        f = _write(code)
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "pass"
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_subprocess_reachable(self, scanner):
        code = """\
import subprocess

def run_cmd():
    subprocess.run(["ls"])

run_cmd()
"""
        f = _write(code)
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_empty_artifacts(self, scanner):
        result = await scanner.scan(_pkg(), [])
        assert result.verdict == "pass"


# -- JavaScript reachability --


class TestJavaScriptReachability:
    @pytest.mark.asyncio
    async def test_reachable_eval_module_level(self, scanner):
        f = _write("eval('payload');", suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_exported_function_reachable(self, scanner):
        code = """\
function danger() {
    eval("payload");
}
exports.danger = danger;
"""
        f = _write(code, suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_unexported_function_unreachable(self, scanner):
        code = """\
function safe() {
    return 1;
}
function hidden() {
    eval("payload");
}
exports.safe = safe;
"""
        f = _write(code, suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.metadata.get("unreachable_count", 0) >= 1
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_clean_js_passes(self, scanner):
        code = """\
function add(a, b) {
    return a + b;
}
exports.add = add;
"""
        f = _write(code, suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "pass"
        finally:
            f.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_syntax_error_handled(self, scanner):
        f = _write("function { broken syntax", suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [f])
            assert result.verdict == "pass"
        finally:
            f.unlink(missing_ok=True)


# -- Mixed file analysis --


class TestMixedFiles:
    @pytest.mark.asyncio
    async def test_multiple_files(self, scanner):
        py_file = _write("eval('x')")
        js_file = _write("var x = 1 + 2;", suffix=".js")
        try:
            result = await scanner.scan(_pkg(), [py_file, js_file])
            assert result.verdict == "warn"
            assert result.metadata["reachable_count"] >= 1
        finally:
            py_file.unlink(missing_ok=True)
            js_file.unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_nonexistent_file(self, scanner):
        result = await scanner.scan(_pkg(), [Path("/nonexistent/file.py")])
        assert result.verdict == "pass"
