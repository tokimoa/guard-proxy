"""Decision engine Pydantic schemas."""

from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.scan import ScanResult


class DecisionResult(BaseModel):
    """Final verdict from the decision engine."""

    verdict: Literal["allow", "quarantine", "deny"]
    final_score: float = Field(ge=0.0, le=1.0)
    scan_results: list[ScanResult]
    reason: str
    mode: Literal["warn", "enforce"]
    llm_deferred: bool = False
