"""Tests for install hook detection."""

import tempfile
from pathlib import Path
from unittest.mock import patch

from app.utils.install_hooks import detect_install_hooks


class TestNpmHooks:
    def test_npm_with_install_script(self):
        """Returns True for npm package with malicious install script."""
        result = detect_install_hooks(
            registry="npm",
            filename="evil-pkg-1.0.0.tgz",
            artifacts=[],
            install_scripts={"install": "node malicious.js"},
        )
        assert result is True

    def test_npm_without_scripts(self):
        """Returns False when no install scripts present."""
        result = detect_install_hooks(
            registry="npm",
            filename="safe-pkg-1.0.0.tgz",
            artifacts=[],
            install_scripts={},
        )
        assert result is False

    def test_npm_safe_command(self):
        """Returns False for known safe install commands like node-gyp rebuild."""
        result = detect_install_hooks(
            registry="npm",
            filename="native-pkg-1.0.0.tgz",
            artifacts=[],
            install_scripts={"install": "node-gyp rebuild"},
        )
        assert result is False


class TestPyPIHooks:
    def test_pypi_sdist(self):
        """Returns True for sdist (.tar.gz) -- always has install hooks."""
        result = detect_install_hooks(
            registry="pypi",
            filename="evil-pkg-1.0.0.tar.gz",
            artifacts=[],
            install_scripts={},
        )
        assert result is True

    def test_pypi_wheel_no_pth(self):
        """Returns False for wheel without .pth files."""
        tmp = Path(tempfile.mkdtemp())
        init_file = tmp / "__init__.py"
        init_file.write_text("# init")
        try:
            result = detect_install_hooks(
                registry="pypi",
                filename="safe-pkg-1.0.0-py3-none-any.whl",
                artifacts=[init_file],
                install_scripts={},
            )
            assert result is False
        finally:
            import shutil

            shutil.rmtree(tmp)

    def test_pypi_wheel_with_pth(self):
        """Returns True for wheel with .pth file."""
        tmp = Path(tempfile.mkdtemp())
        pth_file = tmp / "evil.pth"
        pth_file.write_text("import evil")
        try:
            result = detect_install_hooks(
                registry="pypi",
                filename="evil-pkg-1.0.0-py3-none-any.whl",
                artifacts=[pth_file],
                install_scripts={},
            )
            assert result is True
        finally:
            import shutil

            shutil.rmtree(tmp)


class TestRubyGemsHooks:
    def test_rubygems_with_extconf(self):
        """Returns True when metadata.yaml has extensions."""
        tmp = Path(tempfile.mkdtemp())
        metadata = tmp / "metadata.yaml"
        metadata.write_text("extensions:\n  - ext/extconf.rb\n")
        try:
            with patch("app.utils.tarball.parse_gemspec_extensions", return_value=["ext/extconf.rb"]):
                result = detect_install_hooks(
                    registry="rubygems",
                    filename="evil-gem-1.0.0.gem",
                    artifacts=[metadata],
                    install_scripts={},
                )
            assert result is True
        finally:
            import shutil

            shutil.rmtree(tmp)

    def test_rubygems_plugin(self):
        """Returns True when rubygems_plugin.rb is in artifacts."""
        tmp = Path(tempfile.mkdtemp())
        plugin = tmp / "rubygems_plugin.rb"
        plugin.write_text("puts 'loaded'")
        try:
            result = detect_install_hooks(
                registry="rubygems",
                filename="plugin-gem-1.0.0.gem",
                artifacts=[plugin],
                install_scripts={},
            )
            assert result is True
        finally:
            import shutil

            shutil.rmtree(tmp)

    def test_rubygems_no_hooks(self):
        """Returns False for normal gem without hooks."""
        tmp = Path(tempfile.mkdtemp())
        lib = tmp / "lib.rb"
        lib.write_text("class Foo; end")
        try:
            result = detect_install_hooks(
                registry="rubygems",
                filename="safe-gem-1.0.0.gem",
                artifacts=[lib],
                install_scripts={},
            )
            assert result is False
        finally:
            import shutil

            shutil.rmtree(tmp)


class TestGoHooks:
    def test_go_with_init(self):
        """Returns True when .go file contains init() function."""
        tmp = Path(tempfile.mkdtemp())
        gofile = tmp / "main.go"
        gofile.write_text("""package main

func init() {
    // runs at import
}
""")
        try:
            result = detect_install_hooks(
                registry="go",
                filename="",
                artifacts=[gofile],
                install_scripts={},
            )
            assert result is True
        finally:
            import shutil

            shutil.rmtree(tmp)

    def test_go_without_init(self):
        """Returns False for normal Go files without init()."""
        tmp = Path(tempfile.mkdtemp())
        gofile = tmp / "main.go"
        gofile.write_text("""package main

func main() {
    fmt.Println("hello")
}
""")
        try:
            result = detect_install_hooks(
                registry="go",
                filename="",
                artifacts=[gofile],
                install_scripts={},
            )
            assert result is False
        finally:
            import shutil

            shutil.rmtree(tmp)


class TestCargoHooks:
    def test_cargo_with_build_rs(self):
        """Returns True when build.rs exists in artifacts."""
        tmp = Path(tempfile.mkdtemp())
        build_rs = tmp / "build.rs"
        build_rs.write_text("fn main() {}")
        try:
            result = detect_install_hooks(
                registry="cargo",
                filename="",
                artifacts=[build_rs],
                install_scripts={},
            )
            assert result is True
        finally:
            import shutil

            shutil.rmtree(tmp)

    def test_cargo_without_build_rs(self):
        """Returns False when no build.rs in artifacts."""
        tmp = Path(tempfile.mkdtemp())
        lib = tmp / "lib.rs"
        lib.write_text("pub fn hello() {}")
        try:
            result = detect_install_hooks(
                registry="cargo",
                filename="",
                artifacts=[lib],
                install_scripts={},
            )
            assert result is False
        finally:
            import shutil

            shutil.rmtree(tmp)


class TestUnknownRegistry:
    def test_unknown_registry(self):
        """Returns False for unknown registry."""
        result = detect_install_hooks(
            registry="unknown",
            filename="pkg-1.0.0.tar.gz",
            artifacts=[],
            install_scripts={},
        )
        assert result is False
