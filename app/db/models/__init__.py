"""SQLAlchemy ORM models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.db.models.advisory import Advisory, AdvisorySyncState  # noqa: E402, F401
from app.db.models.audit_log import AuditLog  # noqa: E402, F401
from app.db.models.maintainer_snapshot import MaintainerSnapshot  # noqa: E402, F401
from app.db.models.scan_cache import ScanCache  # noqa: E402, F401
