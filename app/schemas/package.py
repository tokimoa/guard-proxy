"""Package-related Pydantic schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel


class NpmDistInfo(BaseModel):
    """Distribution info from npm registry."""

    tarball: str
    shasum: str
    integrity: str | None = None


class PackageInfo(BaseModel):
    """Core package identification passed to scanners."""

    name: str
    version: str
    registry: Literal["npm", "pypi", "rubygems"] = "npm"
    publish_date: datetime | None = None
    install_scripts: dict[str, str] = {}
    metadata: dict[str, Any] = {}


class NpmPackageMetadata(BaseModel):
    """Metadata extracted from npm registry API response."""

    name: str
    version: str
    publish_date: datetime | None = None
    maintainers: list[str] = []
    dependencies: dict[str, str] = {}
    dev_dependencies: dict[str, str] = {}
    dist: NpmDistInfo | None = None
    install_scripts: dict[str, str] = {}
    npm_user: str = ""
    version_times: dict[str, str] = {}
