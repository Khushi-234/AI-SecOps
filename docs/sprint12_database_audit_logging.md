# Sprint 12 — Database & Audit Logging Documentation
AI-SecOps Framework v1.0

## Overview

Sprint 12 introduces a modular, secure, and production-grade **PostgreSQL Database & Audit Logging** layer for the AI-SecOps Framework. It persists structured security audit events generated across all 8 pipeline guardrail stages without altering the frozen security modules or pipeline orchestration logic.

---

## Architecture Diagram

```
+-------------------------------------------------------------+
|                      AISecOpsPipeline                       |
| (InputValidator -> PromptFirewall -> RiskEngine -> Policy) |
+-------------------------------------------------------------+
                              │
                              ▼
                +----------------------------+
                |    DatabaseAuditLogger     |
                |  (Secret Redaction/Scrub)  |
                +----------------------------+
                              │
                              ▼
                +----------------------------+
                |      AuditRepository       |
                |   (Parameterized SQL DAO)  |
                +----------------------------+
                              │
                              ▼
                +----------------------------+
                |     PostgreSQL Database    |
                |    (audit_events table)    |
                +----------------------------+
```

---

## Module Structure

```
database/
├── __init__.py               # Package exports
├── config.py                 # DatabaseConfig (DATABASE_URL parsing & env loading)
├── connection.py             # PostgresConnectionManager (psycopg2 pool, transactions)
├── exceptions.py             # Typed exception hierarchy
├── entities.py               # Entity re-exports
├── db_manager.py             # Connection manager re-export
├── schema.sql                # PostgreSQL DDL
├── models/
│   ├── __init__.py
│   └── audit_event.py        # AuditEvent model, enums & secret scrubbing
├── repositories/
│   ├── __init__.py
│   └── audit_repository.py  # AuditRepository (persistence and querying)
├── audit/
│   ├── __init__.py
│   └── audit_logger.py      # DatabaseAuditLogger (AuditLogger interface implementation)
└── migrations/
    ├── __init__.py
    ├── schema.sql            # Migration DDL script
    └── migrate.py            # Migration runner
```

---

## PostgreSQL Setup & Environment Variables

### Prerequisites
- PostgreSQL 12+ running instance
- Created database: `aisecops_db`
- Connection user: `postgres` (or custom user)

### Configuration Variables (`.env`)

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection DSN URL | `postgresql://postgres:postgres@localhost:5432/aisecops_db` |
| `DB_HOST` | Database hostname | `localhost` |
| `DB_PORT` | Port number | `5432` |
| `DB_NAME` | Database name | `aisecops_db` |
| `DB_USER` | Username | `postgres` |
| `DB_PASSWORD` | Password | `postgres` |
| `DB_POOL_MIN` | Minimum pool connections | `1` |
| `DB_POOL_MAX` | Maximum pool connections | `10` |
| `DB_CONNECT_TIMEOUT` | Connection timeout in seconds | `5` |
| `FAIL_SECURE_ON_DB_ERROR` | Trigger fail-secure exit if DB logging fails | `false` |

---

## Database Schema (`audit_events`)

```sql
CREATE TABLE IF NOT EXISTS audit_events (
    event_id VARCHAR(64) PRIMARY KEY,
    request_id VARCHAR(64) NOT NULL,
    trace_id VARCHAR(64) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    component VARCHAR(64) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    action VARCHAR(32) NOT NULL,
    status VARCHAR(32) NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_events_request_id ON audit_events (request_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_trace_id ON audit_events (trace_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_component ON audit_events (component);
CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON audit_events (event_type);
CREATE INDEX IF NOT EXISTS idx_audit_events_severity ON audit_events (severity);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp ON audit_events (timestamp DESC);
```

---

## Schema Migration Command

Initialize tables and indexes programmatically:

```bash
python -m database.migrations.migrate
```

---

## Audit Event Structure

Each `AuditEvent` captures:
- `event_id`: Unique identifier (`evt_...`).
- `request_id`: Correlation identifier for the pipeline request.
- `trace_id`: Distributed trace identifier (defaults to `request_id`).
- `timestamp`: Timezone-aware UTC timestamp.
- `component`: Stage name (`InputValidator`, `PromptFirewall`, `RiskEngine`, `PolicyEngine`, `PromptHardener`, `LLMProvider`, `OutputGuard`, `AISecOpsPipeline`).
- `event_type`: Event category (`INPUT_VALIDATION`, `PROMPT_FIREWALL`, `RISK_ASSESSMENT`, `POLICY_DECISION`, `PROMPT_HARDENING`, `LLM_REQUEST`, `LLM_RESPONSE`, `OUTPUT_GUARD`, `PIPELINE_EVENT`, `ERROR`, `FAIL_SECURE`).
- `severity`: Severity level (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
- `action`: Security action (`ALLOW`, `BLOCK`, `WARN`, `HARDEN`, `SANITIZE`, `EXECUTE`, `FAIL_SECURE`).
- `status`: Outcome (`SUCCESS`, `BLOCKED`, `WARNING`, `ERROR`, `FAIL_SECURE`).
- `message`: Summary log text.
- `metadata`: Key-value payload of telemetry and findings (sanitized).

---

## Sensitive Secret Protection

All `AuditEvent` instances automatically scrub sensitive keys, tokens, passwords, and API keys matching patterns (e.g., `password`, `token`, `api_key`, `GROQ_API_KEY`, `bearer`) before persistence. Raw credentials will never be written to PostgreSQL logs.

---

## Failure Behavior & Fail-Secure Principles

1. **DB Offline / Unreachable (Default Mode)**:
   - Security checks execute as normal.
   - DB errors are caught and logged to system logger (`PipelineLogger`).
   - Requests are **NOT** bypassed. Guardrails remain 100% active.

2. **Strict Fail-Secure Mode (`FAIL_SECURE_ON_DB_ERROR=true`)**:
   - DB failure triggers `FailSecurePipelineError`.
   - Pipeline immediately halts and returns `PipelineStatus.FAIL_SECURE_BLOCKED`.

---

## Running Tests

Run the complete test suite including all 31 new Sprint 12 tests:

```bash
.venv/bin/pytest
```

Run database tests specifically:

```bash
.venv/bin/pytest tests/database/ tests/pipeline/test_pipeline_audit.py
```
