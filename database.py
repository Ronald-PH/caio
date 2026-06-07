# database.py — SQLite database management for CAIO
# Handles scan persistence, history queries, and cost statistics.

import sqlite3
import json
import logging
import os
from datetime import datetime, timedelta
from contextlib import contextmanager

logger = logging.getLogger(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "caio.db")

SCHEMA = """
-- Scans table: stores all analysis results
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    module_type TEXT NOT NULL,
    ai_provider TEXT NOT NULL,
    result_text TEXT NOT NULL,
    tokens_used INTEGER DEFAULT 0,
    cost_estimate REAL DEFAULT 0.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for fast filtering
CREATE INDEX IF NOT EXISTS idx_module_type ON scans(module_type);
CREATE INDEX IF NOT EXISTS idx_ai_provider ON scans(ai_provider);
CREATE INDEX IF NOT EXISTS idx_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_created_at ON scans(created_at);
"""


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Initialize the database with schema if it doesn't exist."""
    with get_db() as conn:
        conn.executescript(SCHEMA)
    logger.info("Database initialized at %s", DB_PATH)


def save_scan(target: str, module_type: str, ai_provider: str,
              result_text: str, tokens_used: int = 0, cost_estimate: float = 0.0) -> int:
    """
    Save a scan result to the database.
    Returns the ID of the new record.
    """
    with get_db() as conn:
        cursor = conn.execute("""
            INSERT INTO scans (target, module_type, ai_provider, result_text, tokens_used, cost_estimate)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target, module_type, ai_provider, result_text, tokens_used, cost_estimate))
        return cursor.lastrowid


def get_scan(scan_id: int) -> dict | None:
    """Retrieve a single scan by ID."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return dict(row) if row else None


def list_scans(module_type: str = None, ai_provider: str = None,
               target: str = None, days: int = None, limit: int = 100) -> list[dict]:
    """
    List scans with optional filters.
    - module_type: filter by module (recon, log_analysis, vuln_scan)
    - ai_provider: filter by provider (ollama, openai, claude)
    - target: partial match on target field
    - days: only scans from last N days
    - limit: max number of results (default 100)
    """
    query = "SELECT * FROM scans WHERE 1=1"
    params = []

    if module_type:
        query += " AND module_type = ?"
        params.append(module_type)

    if ai_provider:
        query += " AND ai_provider = ?"
        params.append(ai_provider)

    if target:
        query += " AND target LIKE ?"
        params.append(f"%{target}%")

    if days:
        cutoff = datetime.now() - timedelta(days=days)
        query += " AND created_at >= ?"
        params.append(cutoff.isoformat())

    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def delete_scan(scan_id: int) -> bool:
    """Delete a scan by ID. Returns True if deleted, False if not found."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def get_cost_stats(days: int = 30) -> dict:
    """
    Get cost statistics for the dashboard.
    Returns aggregated data by provider and module.
    """
    cutoff = (datetime.now() - timedelta(days=days)).isoformat()

    with get_db() as conn:
        # Overall totals
        total = conn.execute("""
            SELECT
                SUM(tokens_used) as total_tokens,
                SUM(cost_estimate) as total_cost,
                COUNT(*) as total_scans
            FROM scans WHERE created_at >= ?
        """, (cutoff,)).fetchone()

        # Breakdown by provider
        by_provider = conn.execute("""
            SELECT
                ai_provider,
                COUNT(*) as scan_count,
                SUM(tokens_used) as tokens,
                SUM(cost_estimate) as cost
            FROM scans WHERE created_at >= ?
            GROUP BY ai_provider
            ORDER BY cost DESC
        """, (cutoff,)).fetchall()

        # Breakdown by module
        by_module = conn.execute("""
            SELECT
                module_type,
                COUNT(*) as scan_count,
                SUM(tokens_used) as tokens,
                SUM(cost_estimate) as cost
            FROM scans WHERE created_at >= ?
            GROUP BY module_type
            ORDER BY cost DESC
        """, (cutoff,)).fetchall()

        # Daily cost for chart
        daily = conn.execute("""
            SELECT
                DATE(created_at) as date,
                SUM(cost_estimate) as cost,
                COUNT(*) as scans
            FROM scans
            WHERE created_at >= ?
            GROUP BY DATE(created_at)
            ORDER BY date ASC
        """, (cutoff,)).fetchall()

    return {
        "total_tokens": total["total_tokens"] or 0,
        "total_cost": total["total_cost"] or 0.0,
        "total_scans": total["total_scans"] or 0,
        "by_provider": [dict(row) for row in by_provider],
        "by_module": [dict(row) for row in by_module],
        "daily": [{"date": row["date"], "cost": row["cost"] or 0.0, "scans": row["scans"]} for row in daily],
    }


def get_recent_scans(limit: int = 10) -> list[dict]:
    """Get most recent scans for dashboard preview."""
    return list_scans(limit=limit)


# Optional: clear all data (useful for testing)
def clear_all_scans() -> int:
    """Delete all scans. Returns number deleted."""
    with get_db() as conn:
        cursor = conn.execute("DELETE FROM scans")
        return cursor.rowcount