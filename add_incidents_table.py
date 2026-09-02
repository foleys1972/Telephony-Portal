#!/usr/bin/env python3
"""
Create incident_record table for existing SQLite databases.
"""

import os
import shutil
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "instance", "telephony.db")
BACKUP_DIR = os.path.join(BASE_DIR, "backups")


def backup_database():
    if not os.path.exists(DB_PATH):
        return None
    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_filename = f"telephony_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    backup_path = os.path.join(BACKUP_DIR, backup_filename)
    shutil.copy2(DB_PATH, backup_path)
    return backup_path


def migrate():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incident_record (
                id INTEGER PRIMARY KEY,
                incident_number VARCHAR(50),
                zendesk_number VARCHAR(50),
                incident_date DATETIME,
                incident_time VARCHAR(20),
                technology VARCHAR(200),
                location VARCHAR(200),
                severity VARCHAR(50),
                calls_lost INTEGER,
                overview TEXT,
                rca_link VARCHAR(500),
                date_created DATETIME,
                last_updated DATETIME,
                last_updated_by VARCHAR(100)
            )
            """
        )
        conn.commit()
        print("✓ incident_record table is present.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding incident_record table...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


