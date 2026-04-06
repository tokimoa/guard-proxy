"""Pure ASGI request logging middleware.

Uses raw ASGI instead of BaseHTTPMiddleware to avoid buffering response bodies,
which is critical for a proxy that streams tarballs.
"""

import time

from loguru import logger
from starlette.types import ASGIApp, Receive, Scope, Send

from app.api.routers.metrics import increment


class RequestLoggingMiddleware:
    """Log all incoming requests with timing (pure ASGI, no body buffering)."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        start = time.monotonic()
        status_code = 0

        async def send_wrapper(message: dict) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        await self.app(scope, receive, send_wrapper)

        increment("requests_total")
        elapsed_ms = (time.monotonic() - start) * 1000
        method = scope.get("method", "?")
        path = scope.get("path", "?")
        logger.info(
            "{method} {path} → {status} ({elapsed:.0f}ms)",
            method=method,
            path=path,
            status=status_code,
            elapsed=elapsed_ms,
        )
