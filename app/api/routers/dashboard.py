"""Dashboard UI — serves static HTML from app/dashboard/."""

from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter(tags=["dashboard"])

_DASHBOARD_DIR = Path(__file__).resolve().parent.parent.parent / "dashboard"


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve the dashboard UI."""
    index = _DASHBOARD_DIR / "index.html"
    return HTMLResponse(content=index.read_text())
