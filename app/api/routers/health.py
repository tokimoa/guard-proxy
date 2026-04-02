"""Health check endpoint."""

from fastapi import APIRouter

from app.core.version import VERSION

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "version": VERSION}
