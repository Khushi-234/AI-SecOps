"""
PostgreSQL Schema Migration Runner for AI-SecOps Framework.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from database.connection import PostgresConnectionManager
from database.exceptions import DatabaseError

logger = logging.getLogger("ai_secops_migrations")

SCHEMA_FILE = Path(__file__).parent / "schema.sql"


def run_migrations(
    connection_manager: Optional[PostgresConnectionManager] = None,
    schema_path: Optional[Path] = None,
) -> bool:
    """
    Executes PostgreSQL DDL migrations to initialize database tables and indexes.

    Args:
        connection_manager: PostgresConnectionManager instance.
        schema_path: Optional path to custom schema SQL file.

    Returns:
        True if migration executed successfully.
    """
    db = connection_manager or PostgresConnectionManager()
    target_schema = schema_path or SCHEMA_FILE

    if not target_schema.exists():
        raise DatabaseError(f"Migration schema file not found: {target_schema}")

    logger.info(f"Applying database migrations from: {target_schema}")
    sql_script = target_schema.read_text(encoding="utf-8")

    try:
        with db.transaction() as cursor:
            cursor.execute(sql_script)
        logger.info("Database migrations applied successfully.")
        return True
    except Exception as exc:
        logger.error(f"Failed to apply database migrations: {exc}")
        raise DatabaseError(
            f"Schema migration failed: {exc}", original_exception=exc
        ) from exc


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    try:
        run_migrations()
        print("Migration complete.")
    except Exception as err:
        print(f"Migration failed: {err}")
