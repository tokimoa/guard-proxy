"""Prometheus-compatible metrics endpoint."""

from datetime import UTC, datetime

from fastapi import APIRouter, Request

router = APIRouter(tags=["metrics"])

# Simple in-memory counters (for Phase 5 MVP — replace with prometheus_client later)
_counters: dict[str, int] = {
    "requests_total": 0,
    "scans_total": 0,
    "scan_allow": 0,
    "scan_quarantine": 0,
    "scan_deny": 0,
    "cache_hits": 0,
    "cache_misses": 0,
}

_start_time = datetime.now(UTC)


def increment(counter: str, amount: int = 1) -> None:
    """Increment a counter."""
    _counters[counter] = _counters.get(counter, 0) + amount


@router.get("/metrics")
async def prometheus_metrics(request: Request) -> str:
    """Return metrics in Prometheus text exposition format."""
    uptime = (datetime.now(UTC) - _start_time).total_seconds()

    lines = [
        "# HELP guard_proxy_uptime_seconds Time since proxy started",
        "# TYPE guard_proxy_uptime_seconds gauge",
        f"guard_proxy_uptime_seconds {uptime:.0f}",
        "",
        "# HELP guard_proxy_requests_total Total proxy requests",
        "# TYPE guard_proxy_requests_total counter",
        f"guard_proxy_requests_total {_counters.get('requests_total', 0)}",
        "",
        "# HELP guard_proxy_scans_total Total package scans",
        "# TYPE guard_proxy_scans_total counter",
        f"guard_proxy_scans_total {_counters.get('scans_total', 0)}",
        "",
        "# HELP guard_proxy_scan_verdicts_total Scan verdicts by type",
        "# TYPE guard_proxy_scan_verdicts_total counter",
        f'guard_proxy_scan_verdicts_total{{verdict="allow"}} {_counters.get("scan_allow", 0)}',
        f'guard_proxy_scan_verdicts_total{{verdict="quarantine"}} {_counters.get("scan_quarantine", 0)}',
        f'guard_proxy_scan_verdicts_total{{verdict="deny"}} {_counters.get("scan_deny", 0)}',
        "",
        "# HELP guard_proxy_cache_total Cache hit/miss counts",
        "# TYPE guard_proxy_cache_total counter",
        f'guard_proxy_cache_total{{result="hit"}} {_counters.get("cache_hits", 0)}',
        f'guard_proxy_cache_total{{result="miss"}} {_counters.get("cache_misses", 0)}',
        "",
    ]

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse("\n".join(lines), media_type="text/plain; version=0.0.4")
