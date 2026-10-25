"""Local SQLite scan history."""
import sqlite3, json
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path(__file__).resolve().parent / "deepphish_history.db"

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with connect() as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scanned_at TEXT NOT NULL,
            url TEXT NOT NULL,
            result TEXT NOT NULL,
            phishing_score REAL,
            risk_score INTEGER NOT NULL,
            signals_json TEXT NOT NULL,
            intel_json TEXT,
            model_version TEXT NOT NULL DEFAULT 'url-only-rf-v2'
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at)")
        conn.commit()

def save_scan(record):
    with connect() as conn:
        cur = conn.execute("""INSERT INTO scans
            (scanned_at,url,result,phishing_score,risk_score,signals_json,intel_json,model_version)
            VALUES (?,?,?,?,?,?,?,?)""",
            (record["scanned_at"], record["url"], record["result"], record.get("phishing_score"),
             record["risk_score"], json.dumps(record["signals"]), json.dumps(record.get("intel")),
             record.get("model_version", "url-only-rf-v2")))
        conn.commit()
        return cur.lastrowid

def get_scans(limit=500):
    with connect() as conn:
        rows = conn.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
    result = []
    for row in rows:
        item = dict(row)
        item["signals"] = json.loads(item.pop("signals_json") or "[]")
        raw_intel = item.pop("intel_json")
        item["intel"] = json.loads(raw_intel) if raw_intel else None
        result.append(item)
    return result

def delete_scan(scan_id):
    with connect() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (int(scan_id),))
        conn.commit()

def clear_scans():
    with connect() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
