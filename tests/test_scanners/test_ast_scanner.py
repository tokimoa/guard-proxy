"""Tests for AST-based semantic analysis scanner."""

import tempfile
from pathlib import Path

from app.scanners.ast_scanner import ASTScanner
from app.schemas.package import PackageInfo


def _scanner() -> ASTScanner:
    return ASTScanner()


def _pkg() -> PackageInfo:
    return PackageInfo(name="test", version="1.0.0")


def _write(content: str, suffix: str = ".py") -> Path:
    p = Path(tempfile.mktemp(suffix=suffix))
    p.write_text(content)
    return p


# ===== Python: Variable indirection =====


async def test_py_eval_alias():
    """x = eval; x(code) should be detected."""
    f = _write("x = eval\nx('print(1)')")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "alias" in result.details.lower() or "tainted" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_py_exec_alias():
    """fn = exec; fn(code) should be detected."""
    f = _write("fn = exec\nfn('import os')")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_py_getattr_exec():
    """getattr(__builtins__, 'exec') should be detected."""
    f = _write("x = getattr(__builtins__, 'exec')\nx('import os')")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "getattr" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_py_getattr_eval():
    """getattr(__builtins__, 'eval') should be detected."""
    f = _write("e = getattr(__builtins__, 'eval')\ne('1+1')")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_py_credential_file_access():
    """open('~/.ssh/id_rsa') should be detected."""
    f = _write("data = open('/home/user/.ssh/id_rsa').read()")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "credential" in result.details.lower() or "ssh" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_py_safe_code_passes():
    """Normal Python code should not be flagged."""
    f = _write("import json\ndata = json.loads('{}')\nprint(data)")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_py_syntax_error_graceful():
    """Invalid Python should not crash."""
    f = _write("def broken(:\n  pass")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"  # can't parse, return pass
    finally:
        f.unlink(missing_ok=True)


# ===== JavaScript: Variable indirection =====


async def test_js_eval_alias():
    """const e = eval; e(code) should be detected."""
    f = _write("const e = eval;\ne('alert(1)');", suffix=".js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "alias" in result.details.lower() or "tainted" in result.details.lower()
    finally:
        f.unlink(missing_ok=True)


async def test_js_function_alias():
    """const F = Function; F(code) should be detected."""
    f = _write("const F = Function;\nF('return 1')();", suffix=".js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
    finally:
        f.unlink(missing_ok=True)


async def test_js_dynamic_require():
    """String concat to build 'child_process' should be detected."""
    f = _write("const m = 'child_' + 'process';\nconst c = require(m);", suffix=".js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict in ("warn", "fail")
        assert "child_process" in result.details
    finally:
        f.unlink(missing_ok=True)


async def test_js_safe_code_passes():
    """Normal JavaScript should not be flagged."""
    f = _write("const express = require('express');\nconst app = express();\napp.listen(3000);", suffix=".js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_js_syntax_error_graceful():
    """Invalid JavaScript should not crash."""
    f = _write("function broken{ }", suffix=".js")
    try:
        result = await _scanner().scan(_pkg(), [f])
        assert result.verdict == "pass"
    finally:
        f.unlink(missing_ok=True)


async def test_empty_artifacts():
    """No artifacts should return pass."""
    result = await _scanner().scan(_pkg(), [])
    assert result.verdict == "pass"
