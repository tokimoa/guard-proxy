"""Scan-related Pydantic schemas."""

from typing import Any, Literal

from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """Result from a single scanner."""

    scanner_name: str
    verdict: Literal["pass", "warn", "fail"]
    confidence: float = Field(ge=0.0, le=1.0)
    details: str
    metadata: dict[str, Any] = {}


class ScanRequest(BaseModel):
    """Request to scan a package."""

    package_name: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=128)
    registry: Literal["npm", "pypi", "rubygems"] = "npm"
