"""Scan result cache model."""

from datetime import UTC, datetime

from sqlalchemy import Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


class ScanCache(Base):
    __tablename__ = "scan_cache"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    cache_key: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    registry: Mapped[str] = mapped_column(String(10))
    package_name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str] = mapped_column(String(64))
    content_hash: Mapped[str] = mapped_column(String(128))
    verdict: Mapped[str] = mapped_column(String(20))
    final_score: Mapped[float] = mapped_column(Float)
    scan_results_json: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))
    expires_at: Mapped[datetime] = mapped_column()

    __table_args__ = (Index("ix_scan_cache_pkg_ver", "registry", "package_name", "version"),)
