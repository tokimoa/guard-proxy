"""Tests for .gem file extraction."""

import gzip
import io
import shutil
import tarfile

from app.utils.tarball import extract_gem_files, parse_gemspec_extensions


def _make_gem(gemspec_yaml: str, files: dict[str, str]) -> bytes:
    """Create a minimal .gem file."""
    outer = io.BytesIO()
    with tarfile.open(fileobj=outer, mode="w:") as tar:
        meta_bytes = gzip.compress(gemspec_yaml.encode())
        info = tarfile.TarInfo("metadata.gz")
        info.size = len(meta_bytes)
        tar.addfile(info, io.BytesIO(meta_bytes))

        data_buf = io.BytesIO()
        with tarfile.open(fileobj=data_buf, mode="w:gz") as inner:
            for name, content in files.items():
                content_bytes = content.encode()
                finfo = tarfile.TarInfo(name)
                finfo.size = len(content_bytes)
                inner.addfile(finfo, io.BytesIO(content_bytes))
        data_bytes = data_buf.getvalue()
        dinfo = tarfile.TarInfo("data.tar.gz")
        dinfo.size = len(data_bytes)
        tar.addfile(dinfo, io.BytesIO(data_bytes))

    return outer.getvalue()


def test_extract_metadata():
    gemspec = "--- !ruby/object:Gem::Specification\nname: test-gem\nversion: '1.0.0'\n"
    gem = _make_gem(gemspec, {"lib/test.rb": "module Test; end"})
    artifacts, tmp_dir = extract_gem_files(gem, "test-gem-1.0.0.gem")
    try:
        names = [a.name for a in artifacts]
        assert "metadata.yaml" in names
        meta = next(a for a in artifacts if a.name == "metadata.yaml")
        assert "test-gem" in meta.read_text()
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extract_extconf():
    gemspec = "--- !ruby/object:Gem::Specification\nname: native\nextensions:\n- ext/extconf.rb\n"
    gem = _make_gem(
        gemspec,
        {
            "ext/extconf.rb": "require 'mkmf'\ncreate_makefile('native')",
            "lib/native.rb": "require 'native/native'",
        },
    )
    artifacts, tmp_dir = extract_gem_files(gem, "native-1.0.0.gem")
    try:
        names = [a.name for a in artifacts]
        assert "metadata.yaml" in names
        assert "extconf.rb" in names
        # lib/native.rb should NOT be extracted (not a target file)
        assert "native.rb" not in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_extract_rubygems_plugin():
    gemspec = "--- !ruby/object:Gem::Specification\nname: plugin-gem\n"
    gem = _make_gem(
        gemspec,
        {
            "lib/rubygems_plugin.rb": "Gem.post_install { puts 'installed!' }",
            "lib/plugin.rb": "module Plugin; end",
        },
    )
    artifacts, tmp_dir = extract_gem_files(gem, "plugin-gem-1.0.0.gem")
    try:
        names = [a.name for a in artifacts]
        assert "rubygems_plugin.rb" in names
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def test_parse_gemspec_extensions_present(tmp_path):
    meta = tmp_path / "metadata.yaml"
    meta.write_text(
        "--- !ruby/object:Gem::Specification\nname: native\nextensions:\n- ext/extconf.rb\n- ext/other.rb\n"
    )
    exts = parse_gemspec_extensions(meta)
    assert exts == ["ext/extconf.rb", "ext/other.rb"]


def test_parse_gemspec_extensions_absent(tmp_path):
    meta = tmp_path / "metadata.yaml"
    meta.write_text("--- !ruby/object:Gem::Specification\nname: pure-gem\nversion: '1.0'\n")
    exts = parse_gemspec_extensions(meta)
    assert exts == []


def test_parse_gemspec_extensions_missing_file():
    from pathlib import Path

    exts = parse_gemspec_extensions(Path("/nonexistent/metadata.yaml"))
    assert exts == []
