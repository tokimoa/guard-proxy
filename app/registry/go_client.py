"""Go module proxy (GOPROXY protocol) client."""

import httpx

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError


class GoRegistryClient:
    """Async client for a GOPROXY-compatible upstream (e.g. proxy.golang.org)."""

    def __init__(self, settings: Settings) -> None:
        self._upstream_url = settings.go_upstream_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._upstream_url,
            timeout=30.0,
            follow_redirects=True,
        )

    @property
    def upstream_url(self) -> str:
        return self._upstream_url

    @staticmethod
    def encode_module_path(module: str) -> str:
        """Encode a Go module path per the GOPROXY case-encoding spec.

        Uppercase letters become '!' + lowercase. For example:
        'github.com/Azure/azure-sdk' -> 'github.com/!azure/azure-sdk'
        """
        result: list[str] = []
        for ch in module:
            if ch.isupper():
                result.append("!")
                result.append(ch.lower())
            else:
                result.append(ch)
        return "".join(result)

    async def list_versions(self, module: str) -> str:
        """GET /{module}/@v/list — returns plain text version list."""
        encoded = self.encode_module_path(module)
        try:
            response = await self._client.get(f"/{encoded}/@v/list")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=f"{self._upstream_url}/{encoded}/@v/list", detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(module)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{encoded}/@v/list",
                status_code=response.status_code,
            )
        return response.text

    async def get_version_info(self, module: str, version: str) -> dict:
        """GET /{module}/@v/{version}.info — returns JSON with Version and Time."""
        encoded = self.encode_module_path(module)
        try:
            response = await self._client.get(f"/{encoded}/@v/{version}.info")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=f"{self._upstream_url}/{encoded}/@v/{version}.info", detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(module, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{encoded}/@v/{version}.info",
                status_code=response.status_code,
            )
        return response.json()

    async def get_mod_file(self, module: str, version: str) -> str:
        """GET /{module}/@v/{version}.mod — returns plain text go.mod."""
        encoded = self.encode_module_path(module)
        try:
            response = await self._client.get(f"/{encoded}/@v/{version}.mod")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=f"{self._upstream_url}/{encoded}/@v/{version}.mod", detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(module, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{encoded}/@v/{version}.mod",
                status_code=response.status_code,
            )
        return response.text

    async def get_latest(self, module: str) -> dict:
        """GET /{module}/@latest — returns JSON with latest version info."""
        encoded = self.encode_module_path(module)
        try:
            response = await self._client.get(f"/{encoded}/@latest")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=f"{self._upstream_url}/{encoded}/@latest", detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(module)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{encoded}/@latest",
                status_code=response.status_code,
            )
        return response.json()

    async def download_zip(self, module: str, version: str) -> bytes:
        """GET /{module}/@v/{version}.zip — returns module zip bytes."""
        encoded = self.encode_module_path(module)
        try:
            response = await self._client.get(f"/{encoded}/@v/{version}.zip")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=f"{self._upstream_url}/{encoded}/@v/{version}.zip", detail=str(e)) from e

        if response.status_code == 404:
            raise PackageNotFoundError(module, version)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{encoded}/@v/{version}.zip",
                status_code=response.status_code,
            )
        return response.content

    async def close(self) -> None:
        await self._client.aclose()
