"""Cache management API."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/cache", tags=["cache"])


@router.get("")
async def cache_stats(request: Request) -> dict:
    """Get cache statistics."""
    cache = request.app.state.cache_service
    return await cache.stats()


@router.delete("")
async def clear_cache(request: Request) -> dict:
    """Clear all cached scan results."""
    cache = request.app.state.cache_service
    deleted = await cache.clear()
    return {"cleared": deleted}


@router.post("/evict")
async def evict_expired(request: Request) -> dict:
    """Remove expired cache entries."""
    cache = request.app.state.cache_service
    evicted = await cache.evict_expired()
    return {"evicted": evicted}
