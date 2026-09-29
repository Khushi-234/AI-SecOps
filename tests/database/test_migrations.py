"""
Unit tests for Database Migrations (Sprint 12 Phase 11 & 12).
"""

from unittest.mock import MagicMock
from database.connection import PostgresConnectionManager
from database.migrations.migrate import run_migrations


def test_run_migrations_success():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    result = run_migrations(connection_manager=mgr)

    assert result is True
    mock_cursor.execute.assert_called_once()
    mock_conn.commit.assert_called_once()
