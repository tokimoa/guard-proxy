"""Cargo (crates.io) registry API client."""

from datetime import datetime

import httpx

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError


class CargoRegistryClient:
    """Async client for the crates.io API."""

    def __init__(self, settings: Settings) -> None:
        self._upstream_url = settings.cargo_upstream_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
            headers={"User-Agent": "guard-proxy (security proxy)"},
        )

    @property
    def upstream_url(self) -> str:
        return self._upstream_url

    async def get_crate_metadata(self, crate_name: str) -> dict:
        """GET /api/v1/crates/{name} — crate metadata."""
        url = f"{self._upstream_url}/api/v1/crates/{crate_name}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(crate_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)
        return response.json()

    async def get_version_metadata(self, crate_name: str, version: str) -> dict:
        """GET /api/v1/crates/{name}/{version} — version-specific metadata."""
        url = f"{self._upstream_url}/api/v1/crates/{crate_name}/{version}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(crate_name, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)
        return response.json()

    async def forward_request(self, path: str) -> httpx.Response:
        """Forward a request to upstream with path validation."""
        if "://" in path or ".." in path:
            raise UpstreamRegistryError(url=path, detail="Invalid path in forward_request")
        url = f"{self._upstream_url}{path}"
        try:
            return await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

    async def download_crate(self, crate_name: str, version: str) -> bytes:
        """Download .crate file from crates.io CDN."""
        # Validate inputs to prevent path traversal / SSRF
        if not crate_name or "://" in crate_name or ".." in crate_name or "/" in crate_name:
            raise UpstreamRegistryError(url=crate_name, detail="Invalid crate name")
        if not version or "://" in version or ".." in version or "/" in version:
            raise UpstreamRegistryError(url=version, detail="Invalid version")
        url = f"https://static.crates.io/crates/{crate_name}/{crate_name}-{version}.crate"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(crate_name, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)
        return response.content

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def extract_publish_date(version_data: dict) -> datetime | None:
        """Extract created_at from version metadata."""
        version_info = version_data.get("version", {})
        created = version_info.get("created_at")
        if created:
            try:
                return datetime.fromisoformat(created.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                pass
        return None
