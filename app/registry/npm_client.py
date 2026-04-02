"""npm registry API client."""

from datetime import datetime

import httpx
from loguru import logger

from app.core.config import Settings
from app.core.exceptions import PackageNotFoundError, UpstreamRegistryError
from app.schemas.package import NpmDistInfo, NpmPackageMetadata


class NpmRegistryClient:
    """Async client for the npm registry API."""

    def __init__(self, settings: Settings) -> None:
        self._upstream_url = settings.npm_upstream_url.rstrip("/")
        self._client = httpx.AsyncClient(
            base_url=self._upstream_url,
            timeout=30.0,
            follow_redirects=True,
            headers={"Accept": "application/json"},
        )

    async def get_package_metadata(self, package_name: str) -> dict:
        """Fetch full package metadata from registry.

        GET /<package> returns all versions, maintainers, dist info, etc.
        """
        try:
            response = await self._client.get(f"/{package_name}")
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{package_name}",
                detail=str(e),
            ) from e

        if response.status_code == 404:
            raise PackageNotFoundError(package_name)
        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}/{package_name}",
                status_code=response.status_code,
                detail=response.text[:500],
            )

        return response.json()

    async def get_version_metadata(self, package_name: str, version: str) -> NpmPackageMetadata:
        """Extract metadata for a specific version."""
        full_metadata = await self.get_package_metadata(package_name)
        versions = full_metadata.get("versions", {})

        if version not in versions:
            raise PackageNotFoundError(package_name, version)

        version_data = versions[version]
        publish_date = self._extract_publish_date(full_metadata, version)
        install_scripts = self._extract_install_scripts(version_data)

        dist_data = version_data.get("dist", {})
        dist = (
            NpmDistInfo(
                tarball=dist_data.get("tarball", ""),
                shasum=dist_data.get("shasum", ""),
                integrity=dist_data.get("integrity"),
            )
            if dist_data.get("tarball")
            else None
        )

        maintainers_raw = version_data.get("maintainers", [])
        maintainers = [m.get("name", "") for m in maintainers_raw if isinstance(m, dict)]

        # Extract publisher (who published this specific version)
        npm_user_data = version_data.get("_npmUser", {})
        npm_user = npm_user_data.get("name", "") if isinstance(npm_user_data, dict) else ""

        return NpmPackageMetadata(
            name=package_name,
            version=version,
            publish_date=publish_date,
            maintainers=maintainers,
            dependencies=version_data.get("dependencies", {}),
            dev_dependencies=version_data.get("devDependencies", {}),
            dist=dist,
            install_scripts=install_scripts,
            npm_user=npm_user,
            version_times=full_metadata.get("time", {}),
        )

    async def download_tarball(self, tarball_url: str) -> bytes:
        """Download tarball content from the given URL."""
        try:
            response = await self._client.get(tarball_url)
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(url=tarball_url, detail=str(e)) from e

        if response.status_code >= 400:
            raise UpstreamRegistryError(
                url=tarball_url,
                status_code=response.status_code,
            )

        return response.content

    async def forward_request(self, method: str, path: str, headers: dict | None = None) -> httpx.Response:
        """Forward an arbitrary request to the upstream registry."""
        try:
            response = await self._client.request(
                method=method,
                url=path,
                headers=headers,
            )
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}{path}",
                detail=str(e),
            ) from e
        return response

    async def close(self) -> None:
        await self._client.aclose()

    @staticmethod
    def _extract_publish_date(metadata: dict, version: str) -> datetime | None:
        """Extract publish date from the 'time' field in npm metadata."""
        time_info = metadata.get("time", {})
        date_str = time_info.get(version)
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            logger.warning("Failed to parse publish date: {date}", date=date_str)
            return None

    @staticmethod
    def _extract_install_scripts(version_data: dict) -> dict[str, str]:
        """Extract preinstall/install/postinstall from version metadata."""
        scripts = version_data.get("scripts", {})
        return {key: scripts[key] for key in ("preinstall", "install", "postinstall") if key in scripts}
