"""FastAPI exception handlers."""

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.exceptions import (
    PackageBlockedError,
    PackageNotFoundError,
    ScanTimeoutError,
    UpstreamRegistryError,
)


async def package_blocked_handler(request: Request, exc: PackageBlockedError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": "package_blocked",
            "package": exc.package_name,
            "version": exc.version,
            "reason": exc.reason,
        },
    )


async def package_not_found_handler(request: Request, exc: PackageNotFoundError) -> JSONResponse:
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_found",
            "package": exc.package_name,
            "version": exc.version,
        },
    )


async def upstream_error_handler(request: Request, exc: UpstreamRegistryError) -> JSONResponse:
    from loguru import logger

    logger.error("Upstream error: {exc}", exc=str(exc))
    return JSONResponse(
        status_code=502,
        content={
            "error": "upstream_error",
            "detail": "Failed to reach upstream registry",
        },
    )


async def scan_timeout_handler(request: Request, exc: ScanTimeoutError) -> JSONResponse:
    return JSONResponse(
        status_code=504,
        content={
            "error": "scan_timeout",
            "package": exc.package_name,
            "timeout_seconds": exc.timeout_seconds,
        },
    )
