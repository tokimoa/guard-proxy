"""Audit log model."""

from datetime import UTC, datetime

from sqlalchemy import Float, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC), index=True)
    registry: Mapped[str] = mapped_column(String(10))
    package_name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(20))  # allow, quarantine, deny
    final_score: Mapped[float] = mapped_column(Float)
    decision_mode: Mapped[str] = mapped_column(String(10))
    scan_details: Mapped[str] = mapped_column(Text, default="")
    request_path: Mapped[str] = mapped_column(String(1024), default="")

    __table_args__ = (Index("ix_audit_pkg", "registry", "package_name"),)
