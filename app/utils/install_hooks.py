"""Detect install-time code execution hooks in packages."""

from pathlib import Path

from app.scanners.patterns.npm_patterns import FALSE_POSITIVE_COMMANDS


def detect_install_hooks(
    registry: str,
    filename: str,
    artifacts: list[Path],
    install_scripts: dict[str, str],
) -> bool:
    """Determine if a package has install-time code execution hooks.

    Returns True if the package may execute code during install,
    meaning it MUST be fully scanned (including LLM) before serving.
    """
    if registry == "npm":
        return _detect_npm_hooks(install_scripts)
    if registry == "pypi":
        return _detect_pypi_hooks(filename, artifacts)
    if registry == "rubygems":
        return _detect_rubygems_hooks(artifacts)
    return False


def _detect_npm_hooks(install_scripts: dict[str, str]) -> bool:
    """npm: check if install scripts are present and not known-safe."""
    if not install_scripts:
        return False
    for cmd in install_scripts.values():
        stripped = cmd.strip()
        if not any(stripped == safe or stripped.startswith(safe + " ") for safe in FALSE_POSITIVE_COMMANDS):
            return True
    return False


def _detect_pypi_hooks(filename: str, artifacts: list[Path]) -> bool:
    """PyPI: sdists always have hooks; wheels only if .pth files present."""
    # sdists run setup.py during install
    if not filename.endswith(".whl"):
        return True

    # wheels: check for .pth files (auto-executed by Python)
    return any(a.suffix == ".pth" for a in artifacts)


def _detect_rubygems_hooks(artifacts: list[Path]) -> bool:
    """RubyGems: check for native extensions (extconf.rb) or rubygems_plugin.rb."""
    for a in artifacts:
        # metadata.yaml with extensions array
        if a.name == "metadata.yaml":
            from app.utils.tarball import parse_gemspec_extensions

            if parse_gemspec_extensions(a):
                return True
        # rubygems_plugin.rb is auto-loaded by RubyGems
        if a.name == "rubygems_plugin.rb":
            return True
    return False
