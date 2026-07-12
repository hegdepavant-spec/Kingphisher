import logging
import os
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor


logger = logging.getLogger(__name__)

# PostgreSQL configuration.
# Put your local password here, or set KINGPHISHER_DB_PASSWORD in your environment.
POSTGRES_PASSWORD = "5432"

DB_CONFIG = {
    "host": os.getenv("KINGPHISHER_DB_HOST", "localhost"),
    "port": int(os.getenv("KINGPHISHER_DB_PORT", "5432")),
    "dbname": os.getenv("KINGPHISHER_DB_NAME", "kingphisher"),
    "user": os.getenv("KINGPHISHER_DB_USER", "postgres"),
    "password": os.getenv("KINGPHISHER_DB_PASSWORD", POSTGRES_PASSWORD),
}


CREATE_SCAN_HISTORY_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS scan_history (
    id VARCHAR(100) PRIMARY KEY,
    url TEXT,
    timestamp TIMESTAMP,
    status VARCHAR(50),
    prediction VARCHAR(50),
    risk_score FLOAT,
    confidence FLOAT,
    source VARCHAR(50),
    scan_type VARCHAR(50),
    extracted_text TEXT,
    decoded_url TEXT,
    recommendation TEXT,
    blocked BOOLEAN
);
"""


def get_connection():
    logger.info(
        "Opening PostgreSQL connection host=%s port=%s dbname=%s user=%s password_set=%s",
        DB_CONFIG["host"],
        DB_CONFIG["port"],
        DB_CONFIG["dbname"],
        DB_CONFIG["user"],
        bool(DB_CONFIG.get("password")),
    )
    connection = psycopg2.connect(**DB_CONFIG)
    logger.info(
        "PostgreSQL connection established dbname=%s user=%s server=%s",
        connection.get_dsn_parameters().get("dbname"),
        connection.get_dsn_parameters().get("user"),
        connection.get_parameter_status("server_version"),
    )
    return connection


@contextmanager
def get_cursor(commit=False):
    connection = None
    try:
        connection = get_connection()
        with connection.cursor(cursor_factory=RealDictCursor) as cursor:
            yield cursor
        if commit:
            logger.info("Committing PostgreSQL transaction")
            connection.commit()
            logger.info("PostgreSQL commit succeeded")
    except psycopg2.Error:
        if connection:
            logger.exception("PostgreSQL operation failed; rolling back transaction")
            connection.rollback()
        else:
            logger.exception("PostgreSQL operation failed before connection was established")
        raise
    finally:
        if connection:
            connection.close()
            logger.debug("PostgreSQL connection closed")


def initialize_database():
    logger.info("Ensuring PostgreSQL table scan_history exists")
    logger.info("Executing SQL: %s", CREATE_SCAN_HISTORY_TABLE_SQL.strip())
    with get_cursor(commit=True) as cursor:
        cursor.execute(CREATE_SCAN_HISTORY_TABLE_SQL)
    logger.info("PostgreSQL table scan_history is ready")


def get_database_status():
    initialize_database()
    with get_cursor() as cursor:
        cursor.execute(
            """
            SELECT
                current_database() AS database_name,
                current_user AS database_user,
                COUNT(*) AS table_count
            FROM scan_history
            """
        )
        row = cursor.fetchone()
    status = {
        "connected": True,
        "database": row["database_name"],
        "user": row["database_user"],
        "table": "scan_history",
        "table_count": int(row["table_count"]),
    }
    logger.info(
        "PostgreSQL connected successfully database=%s table=%s count=%d",
        status["database"],
        status["table"],
        status["table_count"],
    )
    return status
