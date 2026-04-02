"""SBOM API endpoint."""

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/sbom", tags=["sbom"])


@router.get("/recent")
async def recent_sboms(request: Request, limit: int = Query(10, le=100)) -> list[dict]:
    """Get recent SBOMs from audit log."""
    audit = request.app.state.audit_service
    entries = await audit.recent(limit=limit)
    # Return entries that have SBOM data
    return entries
