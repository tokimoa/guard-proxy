"""Tests for Cargo .crate extraction."""

import io
import shutil
import tarfile

from app.utils.tarball import extract_cargo_crate


def _make_crate(files: dict[str, str], prefix: str = "my-crate-0.1.0") -> bytes:
    """Create a .crate (tar.gz) with given files."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{prefix}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extracts_rs_files():
    content = _make_crate({"src/main.rs": "fn main() {}", "src/lib.rs": "pub fn hello() {}"})
    extracted, tmp_dir = extract_cargo_crate(content)
    try:
        assert len(extracted) == 2
        names = {f.name for f in extracted}
        assert "main.rs" in names
        assert "lib.rs" in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extracts_build_rs():
    content = _make_crate({"build.rs": "fn main() {}", "src/lib.rs": "pub fn x() {}"})
    extracted, tmp_dir = extract_cargo_crate(content)
    try:
        assert len(extracted) == 2
        names = {f.name for f in extracted}
        assert "build.rs" in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extracts_cargo_toml():
    content = _make_crate({"Cargo.toml": '[package]\nname = "test"', "src/lib.rs": ""})
    extracted, tmp_dir = extract_cargo_crate(content)
    try:
        names = {f.name for f in extracted}
        assert "Cargo.toml" in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_skips_non_target_files():
    content = _make_crate(
        {
            "src/lib.rs": "fn x() {}",
            "README.md": "# Hello",
            "LICENSE": "MIT",
            "Cargo.lock": "lockfile",
        }
    )
    extracted, tmp_dir = extract_cargo_crate(content)
    try:
        assert len(extracted) == 1
        assert extracted[0].name == "lib.rs"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_empty_crate():
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    extracted, tmp_dir = extract_cargo_crate(buf.getvalue())
    try:
        assert len(extracted) == 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
