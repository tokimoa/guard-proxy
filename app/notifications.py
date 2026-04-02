"""Notification service for security events (Slack webhook)."""

import httpx
from loguru import logger

from app.schemas.decision import DecisionResult


class NotificationService:
    """Send notifications on deny/quarantine events."""

    def __init__(self, webhook_url: str | None = None) -> None:
        self._webhook_url = webhook_url
        self._enabled = bool(webhook_url)

    async def notify_decision(
        self,
        registry: str,
        package_name: str,
        version: str,
        decision: DecisionResult,
    ) -> None:
        """Send notification for non-allow decisions."""
        if not self._enabled or decision.verdict == "allow":
            return

        emoji = ":warning:" if decision.verdict == "quarantine" else ":no_entry:"
        color = "#ff9900" if decision.verdict == "quarantine" else "#ff0000"

        payload = {
            "attachments": [
                {
                    "color": color,
                    "blocks": [
                        {
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    f"{emoji} *Guard Proxy Alert*\n"
                                    f"*Package:* `{package_name}@{version}` ({registry})\n"
                                    f"*Verdict:* `{decision.verdict.upper()}`\n"
                                    f"*Score:* {decision.final_score:.4f}\n"
                                    f"*Mode:* {decision.mode}"
                                ),
                            },
                        }
                    ],
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self._webhook_url, json=payload)
                if resp.status_code != 200:
                    logger.warning(
                        "Slack webhook returned {status}",
                        status=resp.status_code,
                    )
        except Exception:
            logger.exception("Failed to send Slack notification")
