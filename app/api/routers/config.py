"""Configuration API."""

from fastapi import APIRouter, Request

router = APIRouter(prefix="/config", tags=["config"])


@router.get("")
async def show_config(request: Request) -> dict:
    """Show current configuration (sensitive values redacted)."""
    settings = request.app.state.settings
    config = settings.model_dump()

    # Redact sensitive values
    secret_keys = ("anthropic_api_key", "openai_api_key", "custom_llm_api_key", "slack_webhook_url")
    for key in secret_keys:
        val = config.get(key, "")
        if val:
            config[key] = "****"

    return config
