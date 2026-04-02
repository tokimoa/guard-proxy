"""Advisory cache models for OSV/GHSA vulnerability data."""

from datetime import UTC, datetime

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


class Advisory(Base):
    __tablename__ = "advisories"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    advisory_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    source: Mapped[str] = mapped_column(String(20))  # "osv" or "ghsa"
    ecosystem: Mapped[str] = mapped_column(String(20), index=True)
    package_name: Mapped[str] = mapped_column(String(256), index=True)
    severity: Mapped[str] = mapped_column(String(20), default="UNKNOWN")
    summary: Mapped[str] = mapped_column(Text, default="")
    affected_ranges_json: Mapped[str] = mapped_column(Text, default="[]")
    aliases: Mapped[str] = mapped_column(Text, default="")
    synced_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))

    __table_args__ = (Index("ix_advisory_eco_pkg", "ecosystem", "package_name"),)


class AdvisorySyncState(Base):
    __tablename__ = "advisory_sync_state"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    source: Mapped[str] = mapped_column(String(20), unique=True)
    last_sync_at: Mapped[datetime] = mapped_column(nullable=True)
    total_advisories: Mapped[int] = mapped_column(default=0)
