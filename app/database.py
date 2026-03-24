import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import json

from app.config import settings


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    def __init__(self, database_url: str):
        if not database_url.startswith("sqlite:///"):
            raise ValueError("Only sqlite database URLs are supported, expected sqlite:///path/to/db")
        self.path = database_url.replace("sqlite:///", "", 1)
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    user_id TEXT,
                    target_domain TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_results (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    module TEXT NOT NULL,
                    status TEXT NOT NULL,
                    raw_data TEXT,
                    severity TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_summaries (
                    scan_id TEXT PRIMARY KEY,
                    short_narrative TEXT,
                    full_narrative TEXT,
                    model_used TEXT,
                    provider TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(id)
                )
                """
            )

    def create_scan(self, scan_id: str, target_domain: str, user_id: Optional[str] = None) -> None:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (id, user_id, target_domain, status, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, user_id, target_domain, "queued", now, now),
            )

    def create_scan_result(self, result_id: str, scan_id: str, module: str) -> None:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scan_results (id, scan_id, module, status, raw_data, severity, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (result_id, scan_id, module, "pending", None, "info", now, now),
            )

    def update_scan_result(self, scan_id: str, module: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = _utc_now_iso()
        columns = ", ".join(f"{k} = ?" for k in fields.keys())
        values = list(fields.values()) + [scan_id, module]
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE scan_results SET {columns} WHERE scan_id = ? AND module = ?",
                values,
            )

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        if not fields:
            return
        fields["updated_at"] = _utc_now_iso()
        columns = ", ".join(f"{k} = ?" for k in fields.keys())
        values = list(fields.values()) + [scan_id]
        with self._lock, self._connect() as conn:
            conn.execute(
                f"UPDATE scans SET {columns} WHERE id = ?",
                values,
            )

    def upsert_summary(
        self,
        scan_id: str,
        short_narrative: str,
        full_narrative: str,
        model_used: str,
        provider: str,
    ) -> None:
        now = _utc_now_iso()
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ai_summaries (scan_id, short_narrative, full_narrative, model_used, provider, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    short_narrative = excluded.short_narrative,
                    full_narrative = excluded.full_narrative,
                    model_used = excluded.model_used,
                    provider = excluded.provider
                """,
                (scan_id, short_narrative, full_narrative, model_used, provider, now),
            )

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None

    def get_results(self, scan_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ? ORDER BY created_at ASC",
                (scan_id,),
            ).fetchall()
            parsed = []
            for row in rows:
                record = dict(row)
                raw_data = record.get("raw_data")
                if isinstance(raw_data, str) and raw_data:
                    try:
                        record["raw_data"] = json.loads(raw_data)
                    except json.JSONDecodeError:
                        pass
                parsed.append(record)
            return parsed

    def get_summary(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM ai_summaries WHERE scan_id = ?", (scan_id,)).fetchone()
            return dict(row) if row else None


storage = Storage(settings.database_url)
