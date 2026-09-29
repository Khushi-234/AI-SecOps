"""
PostgreSQL Connection Pool & Session Management for AI-SecOps Framework.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator, Optional

try:
    import psycopg2
    from psycopg2 import pool
    from psycopg2.extensions import connection as psycopg2_connection
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False
    psycopg2_connection = Any  # type: ignore

from database.config import DatabaseConfig
from database.exceptions import DatabaseConnectionError, DatabaseError

logger = logging.getLogger("ai_secops_database")


class PostgresConnectionManager:
    """
    Manages PostgreSQL connection lifecycle, connection pooling, and transaction context.
    """

    def __init__(
        self,
        config: Optional[DatabaseConfig] = None,
        connection_pool: Optional[Any] = None,
    ) -> None:
        self.config = config or DatabaseConfig()
        self._pool = connection_pool
        self._initialized = connection_pool is not None

    def initialize(self) -> None:
        """Initializes the psycopg2 connection pool if not already initialized."""
        if self._initialized:
            return

        if not HAS_PSYCOPG2:
            raise DatabaseConnectionError(
                "psycopg2 library is required for PostgreSQL connections."
            )

        try:
            logger.info(
                f"Initializing PostgreSQL connection pool: {self.config.safe_repr()}"
            )
            self._pool = pool.ThreadedConnectionPool(
                minconn=self.config.min_connections,
                maxconn=self.config.max_connections,
                **self.config.get_connection_dict(),
            )
            self._initialized = True
        except Exception as exc:
            logger.error(f"Failed to initialize PostgreSQL connection pool: {exc}")
            raise DatabaseConnectionError(
                f"Could not connect to PostgreSQL database: {exc}",
                original_exception=exc,
            ) from exc

    def close(self) -> None:
        """Closes all connections in the pool and shuts down pool."""
        if self._initialized and self._pool:
            try:
                self._pool.closeall()
                logger.info("PostgreSQL connection pool closed successfully.")
            except Exception as exc:
                logger.warning(f"Error while closing connection pool: {exc}")
            finally:
                self._pool = None
                self._initialized = False

    @contextmanager
    def get_connection(self) -> Generator[psycopg2_connection, None, None]:
        """
        Context manager for acquiring a connection from pool and returning it safely.
        """
        if not self._initialized:
            self.initialize()

        conn = None
        try:
            if self._pool is not None:
                conn = self._pool.getconn()
            if conn is None:
                raise DatabaseConnectionError("Failed to acquire connection from pool (pool returned None).")
            yield conn
        except Exception as exc:
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            if isinstance(exc, DatabaseError):
                raise
            raise DatabaseError(
                f"Database operation failed: {exc}", original_exception=exc
            ) from exc
        finally:
            if conn and self._pool is not None:
                try:
                    self._pool.putconn(conn)
                except Exception as put_exc:
                    logger.warning(f"Error returning connection to pool: {put_exc}")

    @contextmanager
    def transaction(self) -> Generator[Any, None, None]:
        """
        Context manager providing a transactional cursor. Automatically commits on success
        and rolls back on exception.
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                yield cursor
                conn.commit()
            except Exception as exc:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def check_health(self) -> bool:
        """
        Verifies database connectivity by executing a simple SELECT 1 query.
        Returns True if database is reachable and operational, False otherwise.
        """
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1;")
                res = cursor.fetchone()
                cursor.close()
                return res is not None and res[0] == 1
        except Exception as exc:
            logger.warning(f"Database health check failed: {exc}")
            return False
