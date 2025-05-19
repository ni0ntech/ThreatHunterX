# db.py

import sqlite3
import json
from datetime import datetime

DB_NAME = "threathunterx.db"

def connect():
    return sqlite3.connect(DB_NAME)

def init_db():
    conn = connect()
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS iocs (
            value TEXT PRIMARY KEY,
            ioc_type TEXT,
            risk_score INTEGER,
            enrichment TEXT,
            timestamp TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_ioc(value):
    conn = connect()
    c = conn.cursor()
    c.execute("SELECT * FROM iocs WHERE value = ?", (value,))
    row = c.fetchone()
    conn.close()
    if row:
        return {
            "value": row[0],
            "ioc_type": row[1],
            "risk_score": row[2],
            "enrichment_data": json.loads(row[3]),
            "timestamp": row[4]
        }
    return None

def save_ioc(ioc_obj):
    conn = connect()
    c = conn.cursor()
    c.execute('''
        INSERT OR REPLACE INTO iocs (value, ioc_type, risk_score, enrichment, timestamp)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        ioc_obj.value,
        type(ioc_obj).__name__.replace("IOC", ""),
        ioc_obj.risk_score,
        json.dumps(ioc_obj.enrichment_data),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()
