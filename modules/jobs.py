import logging
import threading
import uuid
import json
import sqlite3
import os
from datetime import datetime
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

JOBS_DB_PATH = os.path.join(os.path.dirname(__file__), "caio_jobs.db")

JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,  -- pending, running, completed, error
    progress INTEGER DEFAULT 0,
    message TEXT,
    result TEXT,
    error TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


def _init_jobs_db():
    """Initialize the jobs database."""
    conn = sqlite3.connect(JOBS_DB_PATH)
    conn.executescript(JOB_SCHEMA)
    conn.commit()
    conn.close()


def _get_job_db():
    """Get a database connection for jobs."""
    conn = sqlite3.connect(JOBS_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


class JobManager:
    """Singleton manager for background jobs."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._threads: dict[str, threading.Thread] = {}
        self._shutdown = False
        _init_jobs_db()

    def _update_job(self, job_id: str, status: str = None,
                    progress: int = None, message: str = None,
                    result: str = None, error: str = None):
        """Update job status in database."""
        conn = _get_job_db()
        try:
            updates = []
            params = []

            if status is not None:
                updates.append("status = ?")
                params.append(status)
            if progress is not None:
                updates.append("progress = ?")
                params.append(progress)
            if message is not None:
                updates.append("message = ?")
                params.append(message)
            if result is not None:
                updates.append("result = ?")
                params.append(result)
            if error is not None:
                updates.append("error = ?")
                params.append(error)

            updates.append("updated_at = CURRENT_TIMESTAMP")

            if updates:
                query = f"UPDATE jobs SET {', '.join(updates)} WHERE job_id = ?"
                params.append(job_id)
                conn.execute(query, params)
                conn.commit()
        finally:
            conn.close()

    def submit(self, fn: Callable, *args, **kwargs) -> str:
        """Submit a job to run in background. Returns job_id."""
        job_id = str(uuid.uuid4())

        # Create job record
        conn = _get_job_db()
        try:
            conn.execute(
                "INSERT INTO jobs (job_id, status, progress, message) VALUES (?, ?, ?, ?)",
                (job_id, "pending", 0, "Queued...")
            )
            conn.commit()
        finally:
            conn.close()

        def run_with_progress():
            """Wrapper to capture progress callbacks."""
            progress_cb = lambda pct, msg: self._update_job(
                job_id, progress=pct, message=msg
            )

            try:
                self._update_job(job_id, status="running", progress=0, message="Starting...")
                result = fn(*args, **kwargs, progress_cb=progress_cb)
                self._update_job(job_id, status="completed", progress=100, message="Done", result=result)
            except Exception as e:
                logger.exception("Job %s failed", job_id)
                self._update_job(job_id, status="error", error=str(e), message=f"Error: {e}")

        thread = threading.Thread(target=run_with_progress, daemon=True)
        self._threads[job_id] = thread
        thread.start()

        return job_id

    def status(self, job_id: str) -> dict:
        """Get job status as dict."""
        conn = _get_job_db()
        try:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
            if not row:
                return {"status": "not_found", "job_id": job_id}
            return dict(row)
        finally:
            conn.close()

    def cleanup_old_jobs(self, hours: int = 24):
        """Remove completed/error jobs older than specified hours."""
        conn = _get_job_db()
        try:
            cutoff = datetime.now().timestamp() - (hours * 3600)
            conn.execute(
                "DELETE FROM jobs WHERE status IN ('completed', 'error') AND julianday('now') - julianday(created_at) > ?",
                (hours / 24,)
            )
            conn.commit()
        finally:
            conn.close()


# Singleton instance
_job_manager = None


def get_manager() -> JobManager:
    """Get the global job manager instance."""
    global _job_manager
    if _job_manager is None:
        _job_manager = JobManager()
    return _job_manager