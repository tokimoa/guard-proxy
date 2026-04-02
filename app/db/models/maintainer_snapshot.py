"""Maintainer snapshot model for tracking maintainer changes over time."""

from datetime import UTC, datetime

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.models import Base


class MaintainerSnapshot(Base):
    __tablename__ = "maintainer_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    registry: Mapped[str] = mapped_column(String(10))
    package_name: Mapped[str] = mapped_column(String(256))
    version: Mapped[str] = mapped_column(String(64))
    maintainers_json: Mapped[str] = mapped_column(Text)
    publisher: Mapped[str] = mapped_column(String(256), default="")
    scanned_at: Mapped[datetime] = mapped_column(default=lambda: datetime.now(UTC))

    __table_args__ = (Index("ix_maintainer_pkg", "registry", "package_name"),)
