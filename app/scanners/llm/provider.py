"""LLM provider protocol and result model."""

from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class SuspiciousLine(BaseModel):
    file: str
    line: int
    content: str
    reason: str


class JudgeResult(BaseModel):
    """Structured result from an LLM judge."""

    verdict: Literal["safe", "suspicious", "malicious"]
    reasons: list[str] = []
    confidence: float = Field(ge=0.0, le=1.0)
    suspicious_lines: list[SuspiciousLine] = []
    provider_name: str = ""
    latency_ms: int = 0
    token_usage: dict[str, int] = {}


# JSON schema for structured output (shared across providers)
JUDGE_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["safe", "suspicious", "malicious"]},
        "reasons": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "suspicious_lines": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "file": {"type": "string"},
                    "line": {"type": "integer"},
                    "content": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["file", "line", "content", "reason"],
            },
        },
    },
    "required": ["verdict", "reasons", "confidence", "suspicious_lines"],
}


@runtime_checkable
class LLMProvider(Protocol):
    """Interface for LLM judge providers."""

    async def judge(self, prompt: str) -> JudgeResult: ...

    async def is_available(self) -> bool: ...

    @property
    def provider_name(self) -> str: ...
