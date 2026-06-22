"""SQLite-backed persistence for triaged findings, feeding both the CLI
report and the dashboard API. Every finding is tagged with app_name so
multiple applications can share one store and one dashboard."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator, List, Optional

from config import settings
from models import FindingStatus, OwaspCategory, Severity, TriagedFinding

_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tool TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    url TEXT,
    app_name TEXT NOT NULL DEFAULT 'unspecified',
    severity TEXT NOT NULL,
    exploitable INTEGER NOT NULL,
    rationale TEXT,
    remediation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class FindingsStore:
    def __init__(self, db_path=None):
        self.db_path = str(db_path or settings.db_path)
        with self._connect() as conn:
            conn.execute(_SCHEMA)
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        """Adds app_name to a findings.db created before multi-app support
        existed. Safe to run on every startup - the second attempt just
        fails with 'duplicate column' and is ignored."""
        try:
            conn.execute("ALTER TABLE findings ADD COLUMN app_name TEXT NOT NULL DEFAULT 'unspecified'")
        except sqlite3.OperationalError:
            pass  # column already exists

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, finding: TriagedFinding) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                """INSERT INTO findings
                   (tool, category, title, url, app_name, severity, exploitable, rationale, remediation, status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding.tool,
                    finding.category.value,
                    finding.title,
                    finding.url,
                    finding.app_name,
                    finding.severity.value,
                    int(finding.exploitable),
                    finding.rationale,
                    finding.remediation,
                    finding.status.value,
                ),
            )
            return cursor.lastrowid

    def all(self, app_name: Optional[str] = None) -> List[sqlite3.Row]:
        query = "SELECT * FROM findings"
        params: tuple = ()
        if app_name:
            query += " WHERE app_name = ?"
            params = (app_name,)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            return conn.execute(query, params).fetchall()

    def list_apps(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT app_name FROM findings ORDER BY app_name"
            ).fetchall()
        return [row["app_name"] for row in rows]

    def severity_summary(self, app_name: Optional[str] = None) -> dict:
        query = "SELECT severity, COUNT(*) as count FROM findings WHERE status != 'dismissed'"
        params: tuple = ()
        if app_name:
            query += " AND app_name = ?"
            params = (app_name,)
        query += " GROUP BY severity"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        summary = {s.value: 0 for s in Severity}
        for row in rows:
            summary[row["severity"]] = row["count"]
        return summary

    def category_summary(self, app_name: Optional[str] = None) -> dict:
        query = "SELECT category, COUNT(*) as count FROM findings WHERE status = 'open'"
        params: tuple = ()
        if app_name:
            query += " AND app_name = ?"
            params = (app_name,)
        query += " GROUP BY category"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        summary = {c.value: 0 for c in OwaspCategory}
        for row in rows:
            summary[row["category"]] = row["count"]
        return summary

    def update_status(self, finding_id: int, status: FindingStatus) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status.value, finding_id))
