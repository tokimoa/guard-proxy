"""Tests for Go module zip extraction."""

import io
import shutil
import zipfile

from app.utils.tarball import extract_go_module_zip


def _make_go_zip(files: dict[str, str], module: str = "example.com/mod@v1.0.0") -> bytes:
    """Create a Go module zip with given files."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(f"{module}/{name}", content)
    return buf.getvalue()


def test_extracts_go_files():
    content = _make_go_zip({"main.go": "package main", "go.mod": "module example.com/mod"})
    extracted, tmp_dir = extract_go_module_zip(content)
    try:
        assert len(extracted) == 2
        names = {f.name for f in extracted}
        assert "main.go" in names
        assert "go.mod" in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extracts_c_files():
    content = _make_go_zip({"cgo.go": "package main", "helper.c": "int x;", "helper.h": "int x;"})
    extracted, tmp_dir = extract_go_module_zip(content)
    try:
        assert len(extracted) == 3
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_skips_non_target_files():
    content = _make_go_zip(
        {
            "main.go": "package main",
            "README.md": "# Hello",
            "data.json": "{}",
            "go.sum": "hash",
        }
    )
    extracted, tmp_dir = extract_go_module_zip(content)
    try:
        assert len(extracted) == 1
        assert extracted[0].name == "main.go"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_handles_nested_directories():
    content = _make_go_zip(
        {
            "cmd/server/main.go": "package main",
            "internal/handler.go": "package internal",
        }
    )
    extracted, tmp_dir = extract_go_module_zip(content)
    try:
        assert len(extracted) == 2
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_empty_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w"):
        pass
    extracted, tmp_dir = extract_go_module_zip(buf.getvalue())
    try:
        assert len(extracted) == 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
