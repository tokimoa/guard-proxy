"""Audit log API."""

from fastapi import APIRouter, Query, Request

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
async def recent_audit(request: Request, limit: int = Query(50, le=500)) -> list[dict]:
    """Get recent audit log entries."""
    audit = request.app.state.audit_service
    return await audit.recent(limit=limit)
