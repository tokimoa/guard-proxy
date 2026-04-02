"""LLM Judge — multi-provider router with strategy-based execution.

Strategies:
  local_first  — Local LLM → escalate to cloud if confidence < threshold
  cloud_only   — Cloud LLM only (Anthropic → OpenAI fallback)
  local_only   — Local LLM only
  consensus    — Both local + cloud, require agreement

Fallback chain: Ollama → Anthropic → OpenAI → degraded mode
"""

from pathlib import Path

from loguru import logger

from app.core.config import Settings
from app.scanners.llm.anthropic_provider import AnthropicProvider
from app.scanners.llm.deobfuscator import deobfuscate
from app.scanners.llm.ollama_provider import OllamaProvider
from app.scanners.llm.openai_provider import OpenAIProvider
from app.scanners.llm.prompt_builder import build_prompt
from app.scanners.llm.provider import JudgeResult, LLMProvider
from app.schemas.package import PackageInfo
from app.schemas.scan import ScanResult

_VERDICT_MAP = {
    "safe": "pass",
    "suspicious": "warn",
    "malicious": "fail",
}


class LLMJudgeScanner:
    """LLM-based scanner implementing ScannerProtocol."""

    def __init__(self, settings: Settings) -> None:
        self._strategy = settings.llm_strategy
        self._confidence_threshold = settings.local_confidence_threshold
        self._obfuscation_threshold = settings.obfuscation_cloud_threshold
        self._max_file_size = settings.llm_max_file_size_kb * 1024

        # Initialize providers
        self._local: LLMProvider | None = None
        self._cloud_primary: LLMProvider | None = None
        self._cloud_fallback: LLMProvider | None = None

        if settings.ollama_enabled:
            self._local = OllamaProvider(settings)
        if settings.anthropic_api_key:
            self._cloud_primary = AnthropicProvider(settings)
        if settings.openai_api_key or settings.custom_llm_base_url:
            self._cloud_fallback = OpenAIProvider(settings)

    async def scan(self, package: PackageInfo, artifacts: list[Path]) -> ScanResult:
        """Run LLM analysis on package artifacts."""
        # Read file contents (skip metadata-only files)
        _SKIP_FILES = {"metadata.yaml", "metadata.gz", "checksums.yaml.gz", "package.json"}
        files: dict[str, str] = {}
        for path in artifacts:
            if path.name in _SKIP_FILES:
                continue
            if path.exists() and path.is_file() and path.stat().st_size <= self._max_file_size:
                try:
                    files[path.name] = path.read_text(errors="replace")
                except OSError:
                    continue

        if not files:
            return ScanResult(
                scanner_name="llm_judge",
                verdict="pass",
                confidence=0.5,
                details="No files to analyze with LLM",
            )

        # Deobfuscate all content
        combined = "\n".join(files.values())
        deobfuscated, obfuscation_score = deobfuscate(combined)
        deob_content = deobfuscated if obfuscation_score > 0.1 else None

        # Build prompt
        prompt = build_prompt(package.registry, files, deob_content)

        # Execute strategy
        try:
            result = await self._execute_strategy(prompt, obfuscation_score)
        except Exception:
            logger.exception("LLM Judge failed completely, returning degraded result")
            return ScanResult(
                scanner_name="llm_judge",
                verdict="pass",
                confidence=0.3,
                details="LLM Judge unavailable — degraded mode (pass)",
                metadata={"degraded": True},
            )

        # Convert LLM verdict to scanner verdict
        scanner_verdict = _VERDICT_MAP.get(result.verdict, "warn")

        return ScanResult(
            scanner_name="llm_judge",
            verdict=scanner_verdict,
            confidence=result.confidence,
            details=f"[{result.provider_name}] " + "; ".join(result.reasons[:5]),
            metadata={
                "provider": result.provider_name,
                "latency_ms": result.latency_ms,
                "token_usage": result.token_usage,
                "suspicious_lines": [s.model_dump() for s in result.suspicious_lines[:10]],
                "obfuscation_score": round(obfuscation_score, 2),
            },
        )

    async def _execute_strategy(self, prompt: str, obfuscation_score: float) -> JudgeResult:
        if self._strategy == "local_only":
            return await self._run_local_only(prompt)
        elif self._strategy == "cloud_only":
            return await self._run_cloud_only(prompt)
        elif self._strategy == "consensus":
            return await self._run_consensus(prompt)
        else:  # local_first (default)
            return await self._run_local_first(prompt, obfuscation_score)

    async def _run_local_first(self, prompt: str, obfuscation_score: float) -> JudgeResult:
        """Local LLM first, escalate to cloud if low confidence or high obfuscation."""
        # High obfuscation → skip local, go directly to cloud
        if obfuscation_score >= self._obfuscation_threshold:
            logger.info(
                "High obfuscation score ({score:.2f}), skipping local LLM",
                score=obfuscation_score,
            )
            return await self._run_cloud_only(prompt)

        # Try local
        if self._local and await self._local.is_available():
            try:
                result = await self._local.judge(prompt)
                if result.confidence >= self._confidence_threshold:
                    logger.info(
                        "Local LLM confident ({conf:.2f}), using result",
                        conf=result.confidence,
                    )
                    return result
                logger.info(
                    "Local LLM low confidence ({conf:.2f}), escalating to cloud",
                    conf=result.confidence,
                )
            except Exception:
                logger.warning("Local LLM failed, falling back to cloud")

        # Escalate to cloud
        return await self._run_cloud_only(prompt)

    async def _run_cloud_only(self, prompt: str) -> JudgeResult:
        """Cloud LLM with fallback chain: Anthropic → OpenAI."""
        if self._cloud_primary and await self._cloud_primary.is_available():
            try:
                return await self._cloud_primary.judge(prompt)
            except Exception:
                logger.warning("Cloud primary (Anthropic) failed, trying fallback")

        if self._cloud_fallback and await self._cloud_fallback.is_available():
            try:
                return await self._cloud_fallback.judge(prompt)
            except Exception:
                logger.warning("Cloud fallback (OpenAI) failed")

        raise RuntimeError("All cloud providers unavailable")

    async def _run_local_only(self, prompt: str) -> JudgeResult:
        """Local LLM only — no cloud fallback."""
        if self._local and await self._local.is_available():
            return await self._local.judge(prompt)
        raise RuntimeError("Local LLM (Ollama) unavailable")

    async def _run_consensus(self, prompt: str) -> JudgeResult:
        """Run both local and cloud in parallel, require agreement."""
        import asyncio

        local_result = None
        cloud_result = None

        async def _run_local() -> JudgeResult | None:
            if self._local and await self._local.is_available():
                try:
                    return await self._local.judge(prompt)
                except Exception:
                    logger.warning("Local LLM failed during consensus")
            return None

        async def _run_cloud() -> JudgeResult | None:
            try:
                return await self._run_cloud_only(prompt)
            except Exception:
                logger.warning("Cloud LLM failed during consensus")
            return None

        local_result, cloud_result = await asyncio.gather(_run_local(), _run_cloud())

        # If only one succeeded, use it
        if local_result and not cloud_result:
            return local_result
        if cloud_result and not local_result:
            return cloud_result
        if not local_result and not cloud_result:
            raise RuntimeError("Both local and cloud failed in consensus mode")

        # Both succeeded — check agreement
        if local_result.verdict == cloud_result.verdict:
            # Agree: use higher confidence, note consensus
            winner = local_result if local_result.confidence >= cloud_result.confidence else cloud_result
            local_pn = local_result.provider_name
            cloud_pn = cloud_result.provider_name
            l_tok, c_tok = local_result.token_usage, cloud_result.token_usage
            prompt_tok = l_tok.get("prompt_tokens", 0) + c_tok.get("prompt_tokens", 0)
            comp_tok = l_tok.get("completion_tokens", 0) + c_tok.get("completion_tokens", 0)
            return JudgeResult(
                verdict=winner.verdict,
                reasons=winner.reasons + [f"Consensus: both {local_pn} and {cloud_pn} agree"],
                confidence=max(local_result.confidence, cloud_result.confidence),
                suspicious_lines=winner.suspicious_lines,
                provider_name=f"consensus({local_pn}+{cloud_pn})",
                latency_ms=local_result.latency_ms + cloud_result.latency_ms,
                token_usage={"prompt_tokens": prompt_tok, "completion_tokens": comp_tok},
            )
        else:
            # Disagree: take the more cautious verdict (malicious > suspicious > safe)
            severity = {"safe": 0, "suspicious": 1, "malicious": 2}
            if severity.get(local_result.verdict, 0) >= severity.get(cloud_result.verdict, 0):
                cautious = local_result
            else:
                cautious = cloud_result

            return JudgeResult(
                verdict=cautious.verdict,
                reasons=cautious.reasons
                + [
                    f"Disagreement: {local_result.provider_name}={local_result.verdict}, "
                    f"{cloud_result.provider_name}={cloud_result.verdict}. Using cautious verdict."
                ],
                confidence=min(local_result.confidence, cloud_result.confidence) * 0.8,
                suspicious_lines=cautious.suspicious_lines,
                provider_name=f"consensus({local_result.provider_name}+{cloud_result.provider_name})",
                latency_ms=local_result.latency_ms + cloud_result.latency_ms,
                token_usage={
                    "prompt_tokens": local_result.token_usage.get("prompt_tokens", 0)
                    + cloud_result.token_usage.get("prompt_tokens", 0),
                    "completion_tokens": local_result.token_usage.get("completion_tokens", 0)
                    + cloud_result.token_usage.get("completion_tokens", 0),
                },
            )
