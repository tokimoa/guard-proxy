"""Base proxy with common request forwarding logic."""

import httpx
from loguru import logger

from app.core.config import Settings
from app.core.exceptions import UpstreamRegistryError


class BaseProxy:
    """Abstract base for registry proxies."""

    def __init__(self, settings: Settings, upstream_url: str) -> None:
        self._settings = settings
        self._upstream_url = upstream_url.rstrip("/")
        self._client: httpx.AsyncClient | None = None

    async def startup(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=self._upstream_url,
            timeout=30.0,
            follow_redirects=True,
        )
        logger.info("Proxy connected to upstream: {url}", url=self._upstream_url)

    async def shutdown(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def forward_request(
        self,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        """Forward a request to the upstream registry."""
        if not self._client:
            raise RuntimeError("Proxy not started — call startup() first")

        # Filter out hop-by-hop headers
        clean_headers = {}
        if headers:
            skip = {"host", "connection", "transfer-encoding", "content-length"}
            clean_headers = {k: v for k, v in headers.items() if k.lower() not in skip}

        try:
            response = await self._client.request(
                method=method,
                url=path,
                headers=clean_headers,
            )
        except httpx.HTTPError as e:
            raise UpstreamRegistryError(
                url=f"{self._upstream_url}{path}",
                detail=str(e),
            ) from e

        return response
