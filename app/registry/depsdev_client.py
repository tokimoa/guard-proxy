"""deps.dev API client (Google, free, no auth required)."""

import httpx
from loguru import logger

_SYSTEM_MAP = {"npm": "npm", "pypi": "pypi", "rubygems": "rubygems"}


class DepsDevClient:
    """Client for Google's deps.dev dependency analysis API."""

    BASE_URL = "https://api.deps.dev/v3"

    def __init__(self, timeout: float = 2.0) -> None:
        self._client = httpx.AsyncClient(
            base_url=self.BASE_URL,
            timeout=timeout,
            follow_redirects=True,
        )

    async def get_version_info(self, registry: str, name: str, version: str) -> dict | None:
        """Get version metadata including publish date and advisories."""
        system = _SYSTEM_MAP.get(registry, registry)
        try:
            resp = await self._client.get(f"/systems/{system}/packages/{_encode(name)}/versions/{_encode(version)}")
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            logger.debug("deps.dev version info failed: {reg}/{name}@{ver}", reg=registry, name=name, ver=version)
        return None

    async def get_dependencies(self, registry: str, name: str, version: str) -> list[dict] | None:
        """Get dependency list for a specific version."""
        system = _SYSTEM_MAP.get(registry, registry)
        try:
            resp = await self._client.get(
                f"/systems/{system}/packages/{_encode(name)}/versions/{_encode(version)}:dependencies"
            )
            if resp.status_code == 200:
                data = resp.json()
                # Extract direct dependencies from the nodes
                nodes = data.get("nodes", [])
                deps = []
                for node in nodes[1:]:  # Skip first node (the package itself)
                    version_key = node.get("versionKey", {})
                    if version_key.get("system") and version_key.get("name"):
                        deps.append(
                            {
                                "name": version_key["name"],
                                "version": version_key.get("version", ""),
                                "relation": node.get("relation", "DIRECT"),
                            }
                        )
                return deps
        except Exception:
            logger.debug("deps.dev dependencies failed: {reg}/{name}@{ver}", reg=registry, name=name, ver=version)
        return None

    async def get_package_versions(self, registry: str, name: str) -> list[str] | None:
        """Get ordered list of versions for a package."""
        system = _SYSTEM_MAP.get(registry, registry)
        try:
            resp = await self._client.get(f"/systems/{system}/packages/{_encode(name)}")
            if resp.status_code == 200:
                data = resp.json()
                versions = []
                for v in data.get("versions", []):
                    ver_key = v.get("versionKey", {})
                    if ver_key.get("version"):
                        versions.append(ver_key["version"])
                return versions
        except Exception:
            logger.debug("deps.dev versions failed: {reg}/{name}", reg=registry, name=name)
        return None

    async def close(self) -> None:
        await self._client.aclose()


def _encode(s: str) -> str:
    """URL-encode package names (e.g., @scope/pkg)."""
    return s.replace("/", "%2F")
