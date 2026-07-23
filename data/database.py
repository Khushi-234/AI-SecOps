import os
import psycopg2
import datetime
from dotenv import load_dotenv

# Ensure environment variables are loaded
load_dotenv()


def get_pg_connection():
    """Helper function to connect to your clean PostgreSQL database using environment variables."""
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        dbname=os.getenv("DB_NAME"),
    )


def init_db():
    """Creates tables in your PostgreSQL security_log database."""
    conn = get_pg_connection()
    cursor = conn.cursor()

    # 2. Changed 'INTEGER PRIMARY KEY AUTOINCREMENT' to PostgreSQL's 'SERIAL PRIMARY KEY'
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assessment_logs (
            id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP,
            category TEXT,
            user_input TEXT,
            model_response TEXT,
            status TEXT,
            risk_score REAL,
            recommendation TEXT,
            mitigated_by_local BOOLEAN
        )
    """)
    conn.commit()
    cursor.close()
    conn.close()


def log_assessment(
    category,
    user_input,
    model_response,
    status,
    risk_score,
    recommendation,
    mitigated_by_local,
):
    """Saves a complete evaluation record to PostgreSQL."""
    conn = get_pg_connection()
    cursor = conn.cursor()

    # 3. Changed SQL placeholders from '?' to '%s' (PostgreSQL style syntax)
    cursor.execute(
        """
        INSERT INTO assessment_logs (
            timestamp, category, user_input, model_response, status, risk_score, recommendation, mitigated_by_local
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """,
        (
            datetime.datetime.now(),
            category,
            user_input,
            model_response,
            status,
            risk_score,
            recommendation,
            mitigated_by_local,  # psycopg2 handles Python booleans perfectly
        ),
    )
    conn.commit()
    cursor.close()
    conn.close()
