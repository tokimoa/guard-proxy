"""PyPI registry API client."""

from datetime import datetime

import httpx

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError


class PyPIRegistryClient:
    """Async client for PyPI JSON API and Simple API."""

    def __init__(self, settings: Settings) -> None:
        self._upstream_url = settings.pypi_upstream_url.rstrip("/")
        self._client = httpx.AsyncClient(
            timeout=30.0,
            follow_redirects=True,
        )

    @property
    def upstream_url(self) -> str:
        return self._upstream_url

    async def get(self, path: str, **kwargs: object) -> httpx.Response:
        """Send a GET request to the upstream registry."""
        url = f"{self._upstream_url}{path}"
        try:
            return await self._client.get(url, **kwargs)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

    async def get_package_metadata(self, package_name: str) -> dict:
        """GET /pypi/<package>/json — full metadata."""
        url = f"{self._upstream_url}/pypi/{package_name}/json"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(package_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.json()

    async def get_version_metadata(self, package_name: str, version: str) -> dict:
        """GET /pypi/<package>/<version>/json — specific version."""
        url = f"{self._upstream_url}/pypi/{package_name}/{version}/json"
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(package_name, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.json()

    async def get_simple_index(self, package_name: str) -> str:
        """GET /simple/<package>/ — PEP 503 simple index HTML."""
        url = f"{self._upstream_url}/simple/{package_name}/"
        try:
            response = await self._client.get(url, headers={"Accept": "text/html"})
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(package_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.text

    async def download_artifact(self, url: str) -> bytes:
        """Download a whl/sdist from the given URL."""
        self._validate_download_url(url)
        try:
            response = await self._client.get(url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=url, detail=str(e)) from e

        if response.status_code >= 400:
            raise UpstreamRegistryError(url=url, status_code=response.status_code)

        return response.content

    _ALLOWED_PYPI_HOSTS = {"files.pythonhosted.org", "pypi.org", "pypi.io"}

    def _validate_download_url(self, url: str) -> None:
        """Reject download URLs pointing to unexpected hosts (SSRF prevention)."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.scheme and parsed.scheme not in ("http", "https"):
            raise UpstreamRegistryError(url=url, detail=f"Unsupported scheme: {parsed.scheme}")
        upstream_host = urlparse(self._upstream_url).hostname
        allowed = self._ALLOWED_PYPI_HOSTS | ({upstream_host} if upstream_host else set())
        if parsed.hostname and parsed.hostname not in allowed:
            raise UpstreamRegistryError(
                url=url,
                detail=f"Download host {parsed.hostname} not in allowed list",
            )

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def extract_publish_date(metadata: dict) -> datetime | None:
        """Extract upload_time from PyPI metadata."""
        info = metadata.get("info", {})
        # Try releases for the specific version
        version = info.get("version", "")
        releases = metadata.get("releases", {})
        version_files = releases.get(version, [])

        # Fall back to urls (version-specific endpoint has urls, not releases)
        if not version_files:
            version_files = metadata.get("urls", [])

        if version_files:
            upload_time = version_files[0].get("upload_time_iso_8601")
            if upload_time:
                try:
                    return datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                except (ValueError, AttributeError):
                    pass
        return None
