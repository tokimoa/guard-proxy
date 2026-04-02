"""Logging configuration with loguru."""

import sys

from loguru import logger

from app.core.config import Settings


def setup_logging(settings: Settings) -> None:
    """Configure loguru based on application settings."""
    logger.remove()

    if settings.log_format == "json":
        logger.add(
            sys.stderr,
            level=settings.log_level,
            serialize=True,
        )
    else:
        logger.add(
            sys.stderr,
            level=settings.log_level,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
                "<level>{message}</level>"
            ),
        )

    if settings.debug:
        logger.debug("Debug mode enabled")
