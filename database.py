"""
SQLite Database Management for Cloud Security Alert System.
Stores audit scan history and telemetry data.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
DB_PATH = os.path.join(DB_DIR, "security_scans.db")


def get_connection() -> sqlite3.Connection:
    """Ensure data directory exists and return an SQLite connection."""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initialize database tables and create baseline record if empty."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                status TEXT NOT NULL,
                trigger_type TEXT NOT NULL,
                total_buckets INTEGER NOT NULL,
                public_buckets INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                raw_payload TEXT
            )
        """)

        # Insert baseline initial record if empty
        cursor.execute("SELECT COUNT(*) AS count FROM scans")
        if cursor.fetchone()["count"] == 0:
            now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            cursor.execute("""
                INSERT INTO scans (timestamp, status, trigger_type, total_buckets, public_buckets, findings_json, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                now_iso,
                "SECURE",
                "SYSTEM_INIT",
                3,
                0,
                json.dumps([]),
                json.dumps({"message": "System initialized in secure state."})
            ))
        conn.commit()


def save_scan(
    status: str,
    trigger_type: str,
    total_buckets: int,
    public_buckets: int,
    findings: List[Dict[str, Any]],
    raw_payload: Optional[Dict[str, Any]] = None,
) -> int:
    """Insert a new scan result record into the database."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scans (timestamp, status, trigger_type, total_buckets, public_buckets, findings_json, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            now_iso,
            status,
            trigger_type,
            total_buckets,
            public_buckets,
            json.dumps(findings),
            json.dumps(raw_payload or {})
        ))
        conn.commit()
        return cursor.lastrowid


def get_latest_status() -> Optional[Dict[str, Any]]:
    """Retrieve the most recent audit scan result."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "timestamp": row["timestamp"],
            "status": row["status"],
            "trigger_type": row["trigger_type"],
            "total_buckets": row["total_buckets"],
            "public_buckets": row["public_buckets"],
            "findings": json.loads(row["findings_json"]),
        }


def get_scan_history(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve chronological list of past audit scans."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "status": r["status"],
                "trigger_type": r["trigger_type"],
                "total_buckets": r["total_buckets"],
                "public_buckets": r["public_buckets"],
                "findings": json.loads(r["findings_json"]),
            })
        return results
