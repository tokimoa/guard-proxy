"""Tests for tarball extraction utilities."""

import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from app.core.exceptions import TarballExtractionError
from app.utils.tarball import extract_npm_install_scripts, parse_install_scripts


def _make_tarball(files: dict[str, str], prefix: str = "package") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{prefix}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_extract_package_json() -> None:
    pkg_json = json.dumps({"name": "test", "version": "1.0.0", "scripts": {}})
    tarball = _make_tarball({"package.json": pkg_json})
    artifacts, tmp_dir = extract_npm_install_scripts(tarball)
    try:
        assert any(a.name == "package.json" for a in artifacts)
        pkg_path = next(a for a in artifacts if a.name == "package.json")
        data = json.loads(pkg_path.read_text())
        assert data["name"] == "test"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extract_script_files() -> None:
    pkg_json = json.dumps(
        {
            "name": "test",
            "version": "1.0.0",
            "scripts": {"postinstall": "node scripts/setup.js"},
        }
    )
    tarball = _make_tarball(
        {
            "package.json": pkg_json,
            "scripts/setup.js": "console.log('setup');",
            "lib/index.js": "module.exports = {};",
        }
    )
    artifacts, tmp_dir = extract_npm_install_scripts(tarball)
    try:
        names = [a.name for a in artifacts]
        assert "package.json" in names
        assert "setup.js" in names
        # lib/index.js should NOT be extracted
        assert "index.js" not in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_zip_slip_protection() -> None:
    """Paths with '..' should be skipped."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Normal file
        pkg_json = json.dumps({"name": "test", "scripts": {}}).encode()
        info = tarfile.TarInfo(name="package/package.json")
        info.size = len(pkg_json)
        tar.addfile(info, io.BytesIO(pkg_json))
        # Malicious path
        evil = b"evil content"
        info2 = tarfile.TarInfo(name="package/../../etc/passwd")
        info2.size = len(evil)
        tar.addfile(info2, io.BytesIO(evil))

    artifacts, tmp_dir = extract_npm_install_scripts(buf.getvalue())
    try:
        # Only package.json should be extracted, not the evil file
        assert len(artifacts) == 1
        assert artifacts[0].name == "package.json"
        # Verify no file was written outside tmp_dir
        assert not Path("/etc/passwd_test").exists()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_empty_tarball() -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    artifacts, tmp_dir = extract_npm_install_scripts(buf.getvalue())
    try:
        assert len(artifacts) == 0
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_corrupt_tarball() -> None:
    with pytest.raises(TarballExtractionError):
        extract_npm_install_scripts(b"not a tarball")


def test_parse_install_scripts(tmp_path: Path) -> None:
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps(
            {
                "name": "test",
                "scripts": {
                    "preinstall": "echo pre",
                    "install": "node-gyp rebuild",
                    "postinstall": "node setup.js",
                    "test": "jest",
                    "build": "tsc",
                },
            }
        )
    )
    scripts = parse_install_scripts(pkg_json)
    assert scripts == {
        "preinstall": "echo pre",
        "install": "node-gyp rebuild",
        "postinstall": "node setup.js",
    }


def test_parse_install_scripts_no_scripts(tmp_path: Path) -> None:
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({"name": "test"}))
    scripts = parse_install_scripts(pkg_json)
    assert scripts == {}
