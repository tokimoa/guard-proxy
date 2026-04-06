"""Package-related Pydantic schemas."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class NpmDistInfo(BaseModel):
    """Distribution info from npm registry."""

    tarball: str
    shasum: str
    integrity: str | None = None

    @field_validator("tarball")
    @classmethod
    def tarball_must_be_http(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("tarball URL must start with http:// or https://")
        return v


class PackageInfo(BaseModel):
    """Core package identification passed to scanners."""

    name: str
    version: str
    registry: Literal["npm", "pypi", "rubygems", "go", "cargo"] = "npm"
    publish_date: datetime | None = None
    install_scripts: dict[str, str] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


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
