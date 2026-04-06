"""Tests for license compliance scanner."""

import pytest

from app.core.config import Settings
from app.scanners.license_scanner import (
    LicenseScanner,
    extract_license_from_metadata,
    normalize_license,
)
from app.schemas.package import PackageInfo

# -- normalize_license tests --


class TestNormalizeLicense:
    def test_spdx_passthrough(self):
        assert normalize_license("MIT") == ["MIT"]

    def test_spdx_expression_or(self):
        result = normalize_license("Apache-2.0 OR MIT")
        assert result == ["Apache-2.0", "MIT"]

    def test_spdx_expression_and(self):
        result = normalize_license("Apache-2.0 AND MIT")
        assert result == ["Apache-2.0", "MIT"]

    def test_alias_resolution(self):
        assert normalize_license("apache 2.0") == ["Apache-2.0"]

    def test_alias_case_insensitive(self):
        assert normalize_license("APACHE LICENSE 2.0") == ["Apache-2.0"]

    def test_gpl_alias(self):
        assert normalize_license("GPLv3") == ["GPL-3.0-only"]

    def test_parentheses_stripped(self):
        assert normalize_license("(MIT)") == ["MIT"]

    def test_empty_string(self):
        assert normalize_license("") == []

    def test_unknown_license_kept(self):
        result = normalize_license("MyCustomLicense")
        assert result == ["MyCustomLicense"]

    def test_cargo_dual_license(self):
        result = normalize_license("Apache-2.0 OR MIT")
        assert "Apache-2.0" in result
        assert "MIT" in result

    def test_with_expression(self):
        result = normalize_license("Apache-2.0 WITH LLVM-exception")
        assert "Apache-2.0" in result


# -- extract_license_from_metadata tests --


class TestExtractLicense:
    def test_direct_license_field(self):
        assert extract_license_from_metadata("npm", {"license": "MIT"}) == "MIT"

    def test_pypi_classifier_fallback(self):
        meta = {"classifiers": ["License :: OSI Approved :: MIT License"]}
        assert extract_license_from_metadata("pypi", meta) == "MIT License"

    def test_empty_metadata(self):
        assert extract_license_from_metadata("npm", {}) == ""

    def test_pypi_license_field_priority(self):
        meta = {
            "license": "Apache-2.0",
            "classifiers": ["License :: OSI Approved :: MIT License"],
        }
        assert extract_license_from_metadata("pypi", meta) == "Apache-2.0"


# -- LicenseScanner tests --


@pytest.fixture
def default_settings():
    return Settings(
        license_check_enabled=True,
        license_denied_list=[],
        license_allowed_list=[],
        license_check_action="warn",
        license_copyleft_action="allow",
    )


@pytest.fixture
def deny_gpl_settings():
    return Settings(
        license_check_enabled=True,
        license_denied_list=["GPL-3.0-only", "AGPL-3.0-only"],
        license_allowed_list=[],
        license_check_action="deny",
        license_copyleft_action="allow",
    )


@pytest.fixture
def allowed_only_settings():
    return Settings(
        license_check_enabled=True,
        license_denied_list=[],
        license_allowed_list=["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
        license_check_action="warn",
        license_copyleft_action="allow",
    )


@pytest.fixture
def copyleft_warn_settings():
    return Settings(
        license_check_enabled=True,
        license_denied_list=[],
        license_allowed_list=[],
        license_check_action="warn",
        license_copyleft_action="warn",
    )


def _pkg(license_str: str, registry: str = "npm") -> PackageInfo:
    return PackageInfo(
        name="test-pkg",
        version="1.0.0",
        registry=registry,
        metadata={"license": license_str},
    )


class TestLicenseScanner:
    @pytest.mark.asyncio
    async def test_pass_mit(self, default_settings):
        scanner = LicenseScanner(default_settings)
        result = await scanner.scan(_pkg("MIT"), [])
        assert result.verdict == "pass"
        assert result.scanner_name == "license_check"
        assert "MIT" in result.details

    @pytest.mark.asyncio
    async def test_pass_no_license(self, default_settings):
        scanner = LicenseScanner(default_settings)
        result = await scanner.scan(_pkg(""), [])
        assert result.verdict == "pass"
        assert result.confidence == 0.3

    @pytest.mark.asyncio
    async def test_denied_gpl(self, deny_gpl_settings):
        scanner = LicenseScanner(deny_gpl_settings)
        result = await scanner.scan(_pkg("GPL-3.0-only"), [])
        assert result.verdict == "fail"
        assert "GPL-3.0-only" in result.details

    @pytest.mark.asyncio
    async def test_denied_gpl_alias(self, deny_gpl_settings):
        scanner = LicenseScanner(deny_gpl_settings)
        result = await scanner.scan(_pkg("GPLv3"), [])
        assert result.verdict == "fail"
        assert "GPL-3.0-only" in result.metadata["denied"]

    @pytest.mark.asyncio
    async def test_allowed_list_pass(self, allowed_only_settings):
        scanner = LicenseScanner(allowed_only_settings)
        result = await scanner.scan(_pkg("MIT"), [])
        assert result.verdict == "pass"

    @pytest.mark.asyncio
    async def test_allowed_list_reject(self, allowed_only_settings):
        scanner = LicenseScanner(allowed_only_settings)
        result = await scanner.scan(_pkg("WTFPL"), [])
        assert result.verdict == "warn"
        assert "not in allowed list" in result.details

    @pytest.mark.asyncio
    async def test_copyleft_warn(self, copyleft_warn_settings):
        scanner = LicenseScanner(copyleft_warn_settings)
        result = await scanner.scan(_pkg("GPL-3.0-only"), [])
        assert result.verdict == "warn"
        assert "Copyleft" in result.details

    @pytest.mark.asyncio
    async def test_copyleft_allowed(self, default_settings):
        scanner = LicenseScanner(default_settings)
        result = await scanner.scan(_pkg("GPL-3.0-only"), [])
        assert result.verdict == "pass"

    @pytest.mark.asyncio
    async def test_dual_license_or(self, allowed_only_settings):
        scanner = LicenseScanner(allowed_only_settings)
        result = await scanner.scan(_pkg("Apache-2.0 OR MIT"), [])
        assert result.verdict == "pass"

    @pytest.mark.asyncio
    async def test_dual_license_partial_deny(self, deny_gpl_settings):
        scanner = LicenseScanner(deny_gpl_settings)
        result = await scanner.scan(_pkg("MIT OR GPL-3.0-only"), [])
        assert result.verdict == "fail"

    @pytest.mark.asyncio
    async def test_pypi_classifier_license(self, default_settings):
        scanner = LicenseScanner(default_settings)
        pkg = PackageInfo(
            name="test-pkg",
            version="1.0.0",
            registry="pypi",
            metadata={"classifiers": ["License :: OSI Approved :: MIT License"]},
        )
        result = await scanner.scan(pkg, [])
        assert result.verdict == "pass"
        assert result.metadata["license"] == "MIT License"

    @pytest.mark.asyncio
    async def test_cargo_dual_license(self, default_settings):
        scanner = LicenseScanner(default_settings)
        pkg = _pkg("Apache-2.0 OR MIT", "cargo")
        result = await scanner.scan(pkg, [])
        assert result.verdict == "pass"
        assert "Apache-2.0" in result.metadata["normalized"]
        assert "MIT" in result.metadata["normalized"]

    @pytest.mark.asyncio
    async def test_copyleft_deny_mode(self):
        settings = Settings(
            license_check_enabled=True,
            license_copyleft_action="deny",
        )
        scanner = LicenseScanner(settings)
        result = await scanner.scan(_pkg("AGPL-3.0-only"), [])
        assert result.verdict == "fail"
        assert "Copyleft" in result.details
