"""
Unit tests for DatabaseConfig & Database Exceptions (Sprint 12 Phase 3 & 12).
"""

import pytest
from database.config import DatabaseConfig
from database.exceptions import DatabaseConfigurationError


def test_database_config_defaults():
    config = DatabaseConfig(password="secret_pass")
    assert config.dbname in ("aisecops_db", "security_logs")
    assert config.host == "localhost"
    assert config.port == 5432
    assert config.user == "postgres"
    assert config.min_connections == 1
    assert config.max_connections == 10
    assert "password='****'" in config.safe_repr()
    assert "secret_pass" not in config.safe_repr()


def test_database_config_parsed_from_url():
    url = "postgresql://custom_user:secret_pass@db.example.com:5433/custom_db"
    config = DatabaseConfig(database_url=url)
    assert config.host == "db.example.com"
    assert config.port == 5433
    assert config.user == "custom_user"
    assert config.password == "secret_pass"
    assert config.dbname == "custom_db"


def test_database_config_dsn():
    config = DatabaseConfig(
        dbname="testdb",
        user="testuser",
        password="testpassword",
        host="localhost",
        port=5432,
        sslmode="require",
    )
    dsn = config.get_dsn()
    assert "dbname=testdb" in dsn
    assert "user=testuser" in dsn
    assert "password=testpassword" in dsn
    assert "host=localhost" in dsn
    assert "port=5432" in dsn
    assert "sslmode=require" in dsn


def test_database_config_validation_invalid_port():
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(port=99999)


def test_database_config_validation_invalid_pool_min():
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(min_connections=0)


def test_database_config_validation_invalid_pool_max():
    with pytest.raises(DatabaseConfigurationError):
        DatabaseConfig(min_connections=5, max_connections=2)
