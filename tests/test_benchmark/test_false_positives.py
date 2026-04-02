"""False positive rate test for legitimate packages.

Tests that Guard Proxy does NOT flag popular, legitimate packages.
Goal: 0% false positive rate on top 100 packages.
"""

from datetime import UTC, datetime, timedelta

import pytest

from app.core.config import Settings
from app.decision.engine import DecisionEngine
from app.scanners.base import ScanPipeline
from app.scanners.cooldown import CooldownScanner
from app.scanners.ioc_checker import IOCScanner
from app.scanners.metadata_scanner import MetadataScanner
from app.schemas.package import PackageInfo

# Top 100 packages across 3 ecosystems (curated, well-known legitimate packages)
LEGITIMATE_PACKAGES = {
    "npm": [
        "lodash",
        "express",
        "react",
        "axios",
        "chalk",
        "commander",
        "debug",
        "typescript",
        "webpack",
        "jest",
        "mocha",
        "eslint",
        "prettier",
        "uuid",
        "moment",
        "dotenv",
        "cors",
        "body-parser",
        "jsonwebtoken",
        "mongoose",
        "socket.io",
        "redis",
        "pg",
        "mysql2",
        "sequelize",
        "prisma",
        "next",
        "vue",
        "svelte",
        "esbuild",
        "vite",
        "rollup",
        "tslib",
        "rxjs",
    ],
    "pypi": [
        "requests",
        "numpy",
        "pandas",
        "flask",
        "django",
        "fastapi",
        "boto3",
        "pillow",
        "scipy",
        "matplotlib",
        "pytest",
        "setuptools",
        "pip",
        "wheel",
        "pyyaml",
        "jinja2",
        "click",
        "pydantic",
        "sqlalchemy",
        "celery",
        "redis",
        "httpx",
        "uvicorn",
        "gunicorn",
        "black",
        "ruff",
        "mypy",
        "cryptography",
        "paramiko",
        "docker",
        "kubernetes",
        "transformers",
        "torch",
        "tensorflow",
    ],
    "rubygems": [
        "rails",
        "rake",
        "bundler",
        "rspec",
        "nokogiri",
        "puma",
        "sidekiq",
        "devise",
        "pg",
        "redis",
        "sinatra",
        "grape",
        "rack",
        "faraday",
        "httparty",
        "jwt",
        "omniauth",
        "pundit",
        "paper_trail",
        "rubocop",
        "simplecov",
        "factory_bot",
        "faker",
        "capybara",
        "minitest",
        "activerecord",
        "activesupport",
        "actionpack",
        "railties",
        "sprockets",
        "webpacker",
        "turbo-rails",
    ],
}


def _settings():
    return Settings(decision_mode="warn", cooldown_days=7)


async def _check_no_false_positive(name: str, registry: str):
    """Verify that a legitimate package is NOT flagged by metadata-level scanners."""
    s = _settings()
    engine = DecisionEngine(s)
    # Simulate a well-established package (published long ago)
    pkg = PackageInfo(
        name=name,
        version="1.0.0",
        registry=registry,
        publish_date=datetime.now(UTC) - timedelta(days=365),
    )
    # Run metadata-level scanners only (no artifacts = no static/heuristics findings)
    scanners = [IOCScanner(), CooldownScanner(s), MetadataScanner()]
    pipeline = ScanPipeline(scanners)
    results = await pipeline.run(pkg, [])
    decision = engine.decide(results)
    assert decision.verdict == "allow", (
        f"FALSE POSITIVE: {registry}/{name} flagged as {decision.verdict} "
        f"(score={decision.final_score:.4f}): {decision.reason[:200]}"
    )


# Generate individual test functions for each package
@pytest.mark.parametrize("name", LEGITIMATE_PACKAGES["npm"])
async def test_npm_no_false_positive(name):
    await _check_no_false_positive(name, "npm")


@pytest.mark.parametrize("name", LEGITIMATE_PACKAGES["pypi"])
async def test_pypi_no_false_positive(name):
    await _check_no_false_positive(name, "pypi")


@pytest.mark.parametrize("name", LEGITIMATE_PACKAGES["rubygems"])
async def test_rubygems_no_false_positive(name):
    await _check_no_false_positive(name, "rubygems")
