"""
Lightweight SQLite Audit Log for BrandShield AI Scans
Persists historical scan investigations to brandshield/backend/scans_audit.db.
"""

import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "scans_audit.db")
)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scan_records (
            scan_id TEXT PRIMARY KEY,
            timestamp_utc TEXT,
            brand_name TEXT,
            suspect_handle TEXT,
            platform TEXT,
            threat_score REAL,
            severity_level TEXT,
            enricher_status TEXT,
            full_response_json TEXT
        )
    """)
    conn.commit()
    conn.close()


def record_scan(scan_dict: Dict[str, Any]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            INSERT OR REPLACE INTO scan_records (
                scan_id, timestamp_utc, brand_name, suspect_handle, platform,
                threat_score, severity_level, enricher_status, full_response_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_dict["scan_id"],
            scan_dict.get("timestamp_utc", datetime.now(timezone.utc).isoformat()),
            scan_dict.get("brand_profile", {}).get("brand_name", "Unknown"),
            scan_dict.get("suspect_handle", "@unknown"),
            scan_dict.get("platform", "Web"),
            float(scan_dict.get("unified_threat_score", 0.0)),
            scan_dict.get("severity_level", "LOW"),
            scan_dict.get("enricher_status", "LIVE_SCRAPE_OK"),
            json.dumps(scan_dict)
        ))
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_scan_history(limit: int = 20) -> List[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT scan_id, timestamp_utc, brand_name, suspect_handle, platform,
               threat_score, severity_level, enricher_status, full_response_json
        FROM scan_records
        ORDER BY timestamp_utc DESC
        LIMIT ?
    """, (limit,))
    rows = cur.fetchall()
    conn.close()

    results = []
    for r in rows:
        try:
            results.append(json.loads(r["full_response_json"]))
        except Exception:
            results.append(dict(r))
    return results


def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT full_response_json FROM scan_records WHERE scan_id = ?", (scan_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return json.loads(row["full_response_json"])
    return None


init_db()
