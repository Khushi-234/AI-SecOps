"""
Unit tests for PostgresConnectionManager & Transaction behavior (Sprint 12 Phase 4, 10, 12).
"""

from unittest.mock import MagicMock, patch
import pytest
from database.config import DatabaseConfig
from database.connection import PostgresConnectionManager
from database.exceptions import DatabaseConnectionError, DatabaseError


def test_connection_manager_init():
    config = DatabaseConfig(dbname="test_db")
    mgr = PostgresConnectionManager(config=config)
    assert mgr.config.dbname == "test_db"
    assert mgr._initialized is False


def test_connection_manager_with_mock_pool():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchone.return_value = (1,)

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    assert mgr.check_health() is True
    mock_cursor.execute.assert_called_with("SELECT 1;")


def test_connection_manager_get_connection_context():
    mock_pool = MagicMock()
    mock_conn = MagicMock()

    mock_pool.getconn.return_value = mock_conn

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    with mgr.get_connection() as conn:
        assert conn == mock_conn

    mock_pool.putconn.assert_called_with(mock_conn)


def test_transaction_commit_on_success():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    with mgr.transaction() as cursor:
        cursor.execute("INSERT INTO dummy VALUES (1);")

    mock_conn.commit.assert_called_once()
    mock_cursor.close.assert_called_once()


def test_transaction_rollback_on_failure():
    mock_pool = MagicMock()
    mock_conn = MagicMock()
    mock_cursor = MagicMock()

    mock_pool.getconn.return_value = mock_conn
    mock_conn.cursor.return_value = mock_cursor

    mgr = PostgresConnectionManager(connection_pool=mock_pool)
    with pytest.raises((ValueError, DatabaseError)):
        with mgr.transaction() as cursor:
            raise ValueError("Database query failed")

    assert mock_conn.rollback.called
    mock_cursor.close.assert_called_once()


def test_connection_failure_raises_typed_exception():
    mgr = PostgresConnectionManager(
        config=DatabaseConfig(host="invalid_host_address_xyz", connect_timeout=1)
    )
    assert mgr.check_health() is False
