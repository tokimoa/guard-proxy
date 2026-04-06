"""Package archive extraction utilities for npm, PyPI, and RubyGems.

Per DD-07: only extract install-script-relevant files, not the full package.
Includes zip-slip protection.
"""

import gzip
import io
import json
import tarfile
import tempfile
import zipfile
from pathlib import Path

from loguru import logger

from app.core.exceptions import TarballExtractionError

# Files always extracted from npm tarballs
_ALWAYS_EXTRACT = {"package.json"}

# Maximum individual file size to extract (2MB)
_MAX_FILE_SIZE = 2 * 1024 * 1024

# Maximum total extracted bytes (50MB)
_MAX_TOTAL_SIZE = 50 * 1024 * 1024

# Maximum number of files to extract
_MAX_FILE_COUNT = 1000


def _is_safe_path(base: Path, target: Path) -> bool:
    """Zip-slip protection: ensure target is within base directory."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def extract_npm_install_scripts(tarball_content: bytes) -> tuple[list[Path], Path]:
    """Extract install-script-relevant files from an npm tarball.

    Returns:
        Tuple of (list of extracted file paths, temp directory path).
        Caller is responsible for cleaning up the temp directory.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="guard-proxy-"))
    extracted: list[Path] = []

    try:
        buf = io.BytesIO(tarball_content)

        # First pass: extract package.json to find install scripts
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            package_json = _extract_package_json(tar, tmp_dir)
            if package_json:
                extracted.append(package_json)

        # Parse install scripts from package.json
        script_files = _find_script_files(package_json)

        # Second pass: extract referenced script files (iterate, don't getmembers)
        total_bytes = 0
        buf.seek(0)
        with tarfile.open(fileobj=buf, mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or member.size > _MAX_FILE_SIZE:
                    continue

                relative = _normalize_member_path(member.name)
                if relative is None:
                    continue

                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    logger.warning("Skipping unsafe path: {path}", path=member.name)
                    continue

                if relative in script_files:
                    if len(extracted) >= _MAX_FILE_COUNT:
                        logger.warning("File count limit reached during extraction")
                        break
                    total_bytes += member.size
                    if total_bytes > _MAX_TOTAL_SIZE:
                        logger.warning("Total size limit reached during extraction")
                        break
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with tar.extractfile(member) as src:
                        if src:
                            target.write_bytes(src.read())
                            extracted.append(target)

    except tarfile.TarError as e:
        raise TarballExtractionError(str(e)) from e

    return extracted, tmp_dir


def _extract_package_json(tar: tarfile.TarFile, tmp_dir: Path) -> Path | None:
    """Extract package.json from the tarball."""
    for member in tar:
        relative = _normalize_member_path(member.name)
        if relative == "package.json" and member.isfile():
            if member.size > _MAX_FILE_SIZE:
                logger.warning("package.json exceeds size limit: {size}", size=member.size)
                return None
            target = tmp_dir / "package.json"
            if not _is_safe_path(tmp_dir, target):
                continue
            with tar.extractfile(member) as src:
                if src:
                    target.write_bytes(src.read())
                    return target
    return None


def _normalize_member_path(name: str) -> str | None:
    """Remove the 'package/' prefix from npm tarball member paths.

    Returns None for unsafe paths.
    """
    parts = Path(name).parts
    if not parts:
        return None

    # npm tarballs have a single top-level directory (usually "package")
    # Strip it to get the relative path within the package
    if len(parts) < 2:
        return None

    relative = str(Path(*parts[1:]))
    if ".." in relative:
        return None

    return relative


def _find_script_files(package_json_path: Path | None) -> set[str]:
    """Parse package.json to find files referenced by install scripts."""
    if not package_json_path or not package_json_path.exists():
        return set()

    try:
        data = json.loads(package_json_path.read_text())
    except (json.JSONDecodeError, OSError):
        return set()

    script_files: set[str] = set()
    scripts = data.get("scripts", {})

    for key in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(key, "")
        if not cmd:
            continue
        # Extract file references from script commands
        # e.g., "node scripts/setup.js" -> "scripts/setup.js"
        for token in cmd.split():
            if token.endswith((".js", ".mjs", ".cjs", ".sh", ".ts")):
                script_files.add(token)

    return script_files


def parse_install_scripts(package_json_path: Path) -> dict[str, str]:
    """Extract install-related scripts from package.json.

    Returns dict like {"postinstall": "node scripts/setup.js"}.
    """
    try:
        data = json.loads(package_json_path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}

    scripts = data.get("scripts", {})
    return {key: scripts[key] for key in ("preinstall", "install", "postinstall") if key in scripts}


# -- PyPI archive extraction --

# Files of interest in PyPI packages
_PYPI_TARGET_PATTERNS = {
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
}

_PYPI_TARGET_EXTENSIONS = {".pth"}


def _is_pypi_target(name: str) -> bool:
    """Check if a file is relevant for PyPI security scanning."""
    basename = Path(name).name
    if basename in _PYPI_TARGET_PATTERNS:
        return True
    if Path(name).suffix in _PYPI_TARGET_EXTENSIONS:
        return True
    # __init__.py files (import-time execution)
    if basename == "__init__.py":
        # Only top-level __init__.py (max 2 directory levels deep)
        parts = Path(name).parts
        return len(parts) <= 3
    return False


def extract_pypi_install_scripts(content: bytes, filename: str) -> tuple[list[Path], Path]:
    """Extract install-script-relevant files from a PyPI archive (whl or sdist).

    Returns:
        Tuple of (list of extracted file paths, temp directory path).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="guard-proxy-pypi-"))
    extracted: list[Path] = []

    try:
        if filename.endswith(".whl") or filename.endswith(".zip"):
            extracted = _extract_from_zip(content, tmp_dir)
        elif filename.endswith(".tar.gz") or filename.endswith(".tgz"):
            extracted = _extract_from_targz(content, tmp_dir)
        else:
            logger.warning("Unknown PyPI archive format: {name}", name=filename)
    except (zipfile.BadZipFile, tarfile.TarError) as e:
        raise TarballExtractionError(str(e)) from e

    return extracted, tmp_dir


def _extract_from_zip(content: bytes, tmp_dir: Path) -> list[Path]:
    """Extract target files from a zip/whl archive."""
    extracted: list[Path] = []
    total_bytes = 0

    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        for info in zf.infolist():
            if info.is_dir() or info.file_size > _MAX_FILE_SIZE:
                continue

            # Normalize: strip top-level directory
            parts = Path(info.filename).parts
            if len(parts) < 2:
                relative = info.filename
            else:
                relative = str(Path(*parts[1:]))

            if ".." in relative:
                continue

            if _is_pypi_target(info.filename) or _is_pypi_target(relative):
                if len(extracted) >= _MAX_FILE_COUNT:
                    logger.warning("File count limit reached during zip extraction")
                    break
                total_bytes += info.file_size
                if total_bytes > _MAX_TOTAL_SIZE:
                    logger.warning("Total size limit reached during zip extraction")
                    break
                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info.filename))
                extracted.append(target)

    return extracted


def _extract_from_targz(content: bytes, tmp_dir: Path) -> list[Path]:
    """Extract target files from a tar.gz sdist archive."""
    extracted: list[Path] = []
    total_bytes = 0

    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile() or member.size > _MAX_FILE_SIZE:
                continue

            relative = _normalize_member_path(member.name)
            if relative is None:
                continue

            if _is_pypi_target(member.name) or _is_pypi_target(relative):
                if len(extracted) >= _MAX_FILE_COUNT:
                    logger.warning("File count limit reached during tar extraction")
                    break
                total_bytes += member.size
                if total_bytes > _MAX_TOTAL_SIZE:
                    logger.warning("Total size limit reached during tar extraction")
                    break
                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src:
                    if src:
                        target.write_bytes(src.read())
                        extracted.append(target)

    return extracted


# -- RubyGems .gem extraction --

_GEM_TARGET_FILES = {"extconf.rb", "Rakefile", "rubygems_plugin.rb"}


def _is_gem_target(name: str) -> bool:
    """Check if a file is relevant for RubyGems security scanning."""
    basename = Path(name).name
    if basename in _GEM_TARGET_FILES:
        return True
    parts = Path(name).parts
    if any(p == "ext" for p in parts) and basename.endswith(".rb"):
        return True
    return False


def extract_gem_files(content: bytes, filename: str) -> tuple[list[Path], Path]:
    """Extract install-script-relevant files from a .gem archive.

    A .gem file is a plain tar containing metadata.gz + data.tar.gz.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="guard-proxy-gem-"))
    extracted: list[Path] = []

    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as outer:
            for member in outer.getmembers():
                if not member.isfile():
                    continue

                if member.name == "metadata.gz":
                    with outer.extractfile(member) as f:
                        if f:
                            yaml_bytes = gzip.decompress(f.read())
                            meta_path = tmp_dir / "metadata.yaml"
                            meta_path.write_bytes(yaml_bytes)
                            extracted.append(meta_path)

                elif member.name == "data.tar.gz":
                    with outer.extractfile(member) as f:
                        if f:
                            inner_extracted = _extract_gem_data(f.read(), tmp_dir)
                            extracted.extend(inner_extracted)

    except tarfile.TarError as e:
        raise TarballExtractionError(str(e)) from e

    return extracted, tmp_dir


def _extract_gem_data(data_bytes: bytes, tmp_dir: Path) -> list[Path]:
    """Extract target files from the nested data.tar.gz inside a .gem."""
    extracted: list[Path] = []
    total_bytes = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(data_bytes), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or member.size > _MAX_FILE_SIZE:
                    continue
                if not _is_gem_target(member.name):
                    continue

                relative = member.name.lstrip("./")
                if ".." in relative:
                    continue

                if len(extracted) >= _MAX_FILE_COUNT:
                    logger.warning("File count limit reached during gem extraction")
                    break
                total_bytes += member.size
                if total_bytes > _MAX_TOTAL_SIZE:
                    logger.warning("Total size limit reached during gem extraction")
                    break

                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    continue

                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src:
                    if src:
                        target.write_bytes(src.read())
                        extracted.append(target)
    except tarfile.TarError:
        logger.warning("Failed to extract data.tar.gz from gem")

    return extracted


# -- Cargo .crate extraction --

_CARGO_TARGET_EXTENSIONS = {".rs"}
_CARGO_TARGET_FILES = {"build.rs", "Cargo.toml"}


def _is_cargo_target(name: str) -> bool:
    """Check if a file is relevant for Cargo security scanning."""
    basename = Path(name).name
    if basename in _CARGO_TARGET_FILES:
        return True
    return Path(name).suffix in _CARGO_TARGET_EXTENSIONS


def extract_cargo_crate(content: bytes) -> tuple[list[Path], Path]:
    """Extract security-relevant files from a .crate archive (tar.gz).

    .crate files have structure: crate-name-version/src/main.rs etc.
    Returns:
        Tuple of (list of extracted file paths, temp directory path).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="guard-proxy-cargo-"))
    extracted: list[Path] = []
    total_bytes = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as tar:
            for member in tar:
                if not member.isfile() or member.size > _MAX_FILE_SIZE:
                    continue

                # Strip top-level crate-version/ directory
                parts = Path(member.name).parts
                if len(parts) < 2:
                    relative = member.name
                else:
                    relative = str(Path(*parts[1:]))

                if ".." in relative:
                    continue

                if not _is_cargo_target(member.name) and not _is_cargo_target(relative):
                    continue

                if len(extracted) >= _MAX_FILE_COUNT:
                    logger.warning("File count limit reached during crate extraction")
                    break
                total_bytes += member.size
                if total_bytes > _MAX_TOTAL_SIZE:
                    logger.warning("Total size limit reached during crate extraction")
                    break

                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src:
                    if src:
                        target.write_bytes(src.read())
                        extracted.append(target)

    except tarfile.TarError as e:
        raise TarballExtractionError(str(e)) from e

    return extracted, tmp_dir


# -- Go module zip extraction --

_GO_TARGET_EXTENSIONS = {".go", ".c", ".h", ".s"}
_GO_TARGET_FILES = {"go.mod"}


def _is_go_target(name: str) -> bool:
    """Check if a file is relevant for Go module security scanning."""
    basename = Path(name).name
    if basename in _GO_TARGET_FILES:
        return True
    return Path(name).suffix in _GO_TARGET_EXTENSIONS


def extract_go_module_zip(content: bytes) -> tuple[list[Path], Path]:
    """Extract security-relevant files from a Go module zip.

    Go module zips have structure: module@version/path/to/file.go
    Returns:
        Tuple of (list of extracted file paths, temp directory path).
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="guard-proxy-go-"))
    extracted: list[Path] = []
    total_bytes = 0

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size > _MAX_FILE_SIZE:
                    continue

                # Strip top-level module@version/ directory
                parts = Path(info.filename).parts
                if len(parts) < 2:
                    relative = info.filename
                else:
                    relative = str(Path(*parts[1:]))

                if ".." in relative:
                    continue

                if not _is_go_target(info.filename) and not _is_go_target(relative):
                    continue

                if len(extracted) >= _MAX_FILE_COUNT:
                    logger.warning("File count limit reached during Go zip extraction")
                    break
                total_bytes += info.file_size
                if total_bytes > _MAX_TOTAL_SIZE:
                    logger.warning("Total size limit reached during Go zip extraction")
                    break

                target = tmp_dir / relative
                if not _is_safe_path(tmp_dir, target):
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info.filename))
                extracted.append(target)

    except zipfile.BadZipFile as e:
        raise TarballExtractionError(str(e)) from e

    return extracted, tmp_dir


def parse_gemspec_extensions(metadata_path: Path) -> list[str]:
    """Extract extensions array from gemspec YAML without full YAML parsing."""
    if not metadata_path.exists():
        return []
    try:
        content = metadata_path.read_text(errors="replace")
    except OSError:
        return []

    extensions: list[str] = []
    in_extensions = False
    for line in content.split("\n"):
        stripped = line.strip()
        if stripped == "extensions:":
            in_extensions = True
            continue
        if in_extensions:
            if stripped.startswith("- "):
                extensions.append(stripped[2:].strip())
            elif stripped and not stripped.startswith("#"):
                break
    return extensions
