"""Audit logging service."""

from datetime import UTC, datetime

from loguru import logger

from app.db.models.audit_log import AuditLog
from app.db.session import Database
from app.schemas.decision import DecisionResult


class AuditService:
    """Record all scan decisions for auditing."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def log_decision(
        self,
        registry: str,
        package_name: str,
        version: str,
        decision: DecisionResult,
        request_path: str = "",
    ) -> None:
        async with self._db.session() as session:
            session.add(
                AuditLog(
                    timestamp=datetime.now(UTC),
                    registry=registry,
                    package_name=package_name,
                    version=version,
                    action=decision.verdict,
                    final_score=decision.final_score,
                    decision_mode=decision.mode,
                    scan_details=decision.reason[:2000],
                    request_path=request_path,
                )
            )
            await session.commit()
        logger.debug(
            "Audit logged: {pkg}@{ver} → {verdict}",
            pkg=package_name,
            ver=version,
            verdict=decision.verdict,
        )

    async def recent(self, limit: int = 50) -> list[dict]:
        """Fetch recent audit entries."""
        from sqlalchemy import select

        async with self._db.session() as session:
            stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
            rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "timestamp": r.timestamp.isoformat(),
                "registry": r.registry,
                "package": r.package_name,
                "version": r.version,
                "action": r.action,
                "score": r.final_score,
                "mode": r.decision_mode,
            }
            for r in rows
        ]
