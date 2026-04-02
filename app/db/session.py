"""SQLite database session management with async support."""

from pathlib import Path

from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings


def _enable_wal(dbapi_conn, connection_record):  # noqa: ANN001
    """Enable WAL mode for better concurrent read/write."""
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.close()


class Database:
    """Async SQLite database manager."""

    def __init__(self, settings: Settings) -> None:
        db_path = Path(settings.db_path)
        db_path.parent.mkdir(parents=True, exist_ok=True)

        self._engine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}",
            echo=settings.debug,
        )
        event.listen(self._engine.sync_engine, "connect", _enable_wal)

        self._session_factory = async_sessionmaker(
            self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def create_tables(self) -> None:
        """Create all tables from metadata."""
        from app.db.models import Base

        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    def session(self) -> AsyncSession:
        return self._session_factory()

    async def close(self) -> None:
        await self._engine.dispose()
