"""Configuration API."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/config", tags=["config"])


@router.get("")
async def show_config(request: Request) -> dict:
    """Show current configuration (sensitive values redacted)."""
    settings = request.app.state.settings
    config = settings.model_dump()

    # Redact sensitive values
    for key in ("anthropic_api_key", "openai_api_key", "custom_llm_api_key"):
        val = config.get(key, "")
        if val:
            config[key] = val[:8] + "..." if len(val) > 8 else "***"

    return config
