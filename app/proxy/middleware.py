"""Request logging and timeout middleware."""

import time

from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Log all incoming requests with timing."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        start = time.monotonic()
        response = await call_next(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        logger.info(
            "{method} {path} → {status} ({elapsed:.0f}ms)",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            elapsed=elapsed_ms,
        )
        return response
