"""
database/db_handler.py
======================
All MySQL database operations for LogSentinel.

Provides functions to:
  - Connect to MySQL using credentials from .env
  - Initialise the schema (create tables)
  - Insert log entries and threat events
  - Query threats, log entries, and summary statistics
  - Clear all data for a fresh run
"""

import os
from datetime import datetime

import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv

# Load .env so that os.getenv() picks up DB_* variables
load_dotenv()


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_connection():
    """
    Open and return a new MySQL connection using credentials from .env.
    Raises mysql.connector.Error if the connection fails.
    """
    return mysql.connector.connect(
        host=os.getenv("DB_HOST", "localhost"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASSWORD", ""),
        database=os.getenv("DB_NAME", "logsentinel"),
        # Automatically reconnect if the server closes the connection
        autocommit=False,
    )


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_database():
    """
    Read schema.sql and execute each statement to create the tables.
    Safe to call on every startup — uses CREATE TABLE IF NOT EXISTS.
    """
    # Locate schema.sql relative to the project root (two levels up from this file)
    schema_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "schema.sql"
    )

    with open(schema_path, "r") as f:
        sql_content = f.read()

    conn = get_connection()
    cursor = conn.cursor()

    # Split on ';' to execute each statement individually
    statements = [s.strip() for s in sql_content.split(";") if s.strip()]
    for statement in statements:
        cursor.execute(statement)

    conn.commit()
    cursor.close()
    conn.close()


# ---------------------------------------------------------------------------
# Insert operations
# ---------------------------------------------------------------------------

def insert_log_entry(entry: dict) -> int:
    """
    Insert a single parsed log entry into the log_entries table.

    Parameters
    ----------
    entry : dict
        Keys: source_file, log_type, timestamp, ip_address,
              user, action, status, raw_line

    Returns
    -------
    int
        The auto-generated primary key of the new row.
    """
    conn = get_connection()
    cursor = conn.cursor()

    sql = """
        INSERT INTO log_entries
            (source_file, log_type, timestamp, ip_address, user, action, status, raw_line)
        VALUES
            (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    values = (
        entry.get("source_file"),
        entry.get("log_type"),
        entry.get("timestamp"),       # datetime object or None
        entry.get("ip_address"),
        entry.get("user"),
        entry.get("action"),
        entry.get("status"),
        entry.get("raw_line"),
    )

    cursor.execute(sql, values)
    conn.commit()
    new_id = cursor.lastrowid

    cursor.close()
    conn.close()
    return new_id


def insert_threat_event(threat: dict):
    """
    Insert a detected threat event into the threat_events table.

    Parameters
    ----------
    threat : dict
        Keys: log_entry_id, threat_type, severity, description, detected_at
    """
    conn = get_connection()
    cursor = conn.cursor()

    sql = """
        INSERT INTO threat_events
            (log_entry_id, threat_type, severity, description, detected_at)
        VALUES
            (%s, %s, %s, %s, %s)
    """
    values = (
        threat.get("log_entry_id"),
        threat.get("threat_type"),
        threat.get("severity"),
        threat.get("description"),
        threat.get("detected_at", datetime.now()),
    )

    cursor.execute(sql, values)
    conn.commit()

    cursor.close()
    conn.close()


# ---------------------------------------------------------------------------
# Query operations
# ---------------------------------------------------------------------------

def get_all_threats() -> list:
    """
    Return all threat events joined with their originating log entry details.
    Ordered newest first.
    """
    conn = get_connection()
    # dictionary=True makes each row a plain dict instead of a tuple
    cursor = conn.cursor(dictionary=True)

    sql = """
        SELECT
            te.id,
            te.log_entry_id,
            te.threat_type,
            te.severity,
            te.description,
            te.detected_at,
            le.ip_address,
            le.user,
            le.source_file,
            le.log_type,
            le.timestamp
        FROM threat_events te
        LEFT JOIN log_entries le ON te.log_entry_id = le.id
        ORDER BY
            FIELD(te.severity, 'HIGH', 'MEDIUM', 'LOW'),
            te.detected_at DESC
    """
    cursor.execute(sql)
    results = cursor.fetchall()

    cursor.close()
    conn.close()
    return results


def get_all_log_entries() -> list:
    """
    Return all parsed log entries ordered by timestamp descending.
    Capped at 500 rows to keep the HTML report manageable.
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM log_entries ORDER BY timestamp DESC LIMIT 500"
    )
    results = cursor.fetchall()

    cursor.close()
    conn.close()
    return results


def get_summary_stats() -> dict:
    """
    Return a dict of aggregate statistics for the report header:
      - total_logs        : total log entry count
      - total_threats     : total threat event count
      - by_severity       : dict of severity -> count
      - by_type           : list of dicts {threat_type, count} sorted by count desc
      - by_log_type       : list of dicts {log_type, count} sorted by count desc
    """
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    stats = {}

    # Total log entries
    cursor.execute("SELECT COUNT(*) AS count FROM log_entries")
    stats["total_logs"] = cursor.fetchone()["count"]

    # Total threat events
    cursor.execute("SELECT COUNT(*) AS count FROM threat_events")
    stats["total_threats"] = cursor.fetchone()["count"]

    # Threat counts broken down by severity
    cursor.execute(
        "SELECT severity, COUNT(*) AS count FROM threat_events GROUP BY severity"
    )
    stats["by_severity"] = {row["severity"]: row["count"] for row in cursor.fetchall()}

    # Threat counts broken down by type (sorted for bar-chart ordering)
    cursor.execute(
        """
        SELECT threat_type, COUNT(*) AS count
        FROM threat_events
        GROUP BY threat_type
        ORDER BY count DESC
        """
    )
    stats["by_type"] = cursor.fetchall()

    # Log entry counts broken down by source type
    cursor.execute(
        """
        SELECT log_type, COUNT(*) AS count
        FROM log_entries
        GROUP BY log_type
        ORDER BY count DESC
        """
    )
    stats["by_log_type"] = cursor.fetchall()

    cursor.close()
    conn.close()
    return stats


# ---------------------------------------------------------------------------
# Maintenance
# ---------------------------------------------------------------------------

def clear_database():
    """
    Delete all rows from both tables (threat_events first due to FK).
    Useful for running the full pipeline again on a clean slate.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Disable FK checks temporarily so we can truncate in any order
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
    cursor.execute("TRUNCATE TABLE threat_events")
    cursor.execute("TRUNCATE TABLE log_entries")
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1")

    conn.commit()
    cursor.close()
    conn.close()
