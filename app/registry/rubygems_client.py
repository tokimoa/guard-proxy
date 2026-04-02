"""RubyGems registry API client."""

from datetime import datetime

import httpx

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError


class RubyGemsRegistryClient:
    """Async client for the RubyGems.org API."""

    def __init__(self, settings: Settings) -> None:
        self._upstream_url = settings.rubygems_upstream_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
        )

    async def get_gem_metadata(self, gem_name: str) -> dict:
        """GET /api/v1/gems/<name>.json — JSON metadata."""
        url = f"{self._upstream_url}/api/v1/gems/{gem_name}.json"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(gem_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.json()

    async def get_gem_versions(self, gem_name: str) -> list[dict]:
        """GET /api/v1/versions/<name>.json — all versions."""
        url = f"{self._upstream_url}/api/v1/versions/{gem_name}.json"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(gem_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.json()

    async def download_gem(self, gem_filename: str) -> bytes:
        """Download .gem file from upstream."""
        # Validate gem filename to prevent path traversal / SSRF
        if "://" in gem_filename or ".." in gem_filename or "/" in gem_filename:
            raise UpstreamRegistryError(url=gem_filename, detail="Invalid gem filename")
        url = f"{self._upstream_url}/gems/{gem_filename}"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(gem_filename)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.content

    async def forward_request(self, path: str, headers: dict[str, str] | None = None) -> httpx.Response:
        """Forward an arbitrary request to upstream (for pass-through routes)."""
        if "://" in path:
            raise UpstreamRegistryError(url=path, detail="Absolute URLs not allowed in forward_request")
        url = f"{self._upstream_url}{path}"
        clean_headers = {}
        if headers:
            skip = {"host", "connection", "transfer-encoding", "content-length", "authorization", "cookie"}
            clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

        try:
            return await self._client.get(url, headers=clean_headers)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def extract_publish_date(versions: list[dict], version: str) -> datetime | None:
        """Extract publish date from versions API response."""
        for v in versions:
            if v.get("number") == version:
                created = v.get("created_at")
                if created:
                    try:
                        return datetime.fromisoformat(created.replace("Z", "+00:00"))
                    except (ValueError, AttributeError):
                        pass
        return None
