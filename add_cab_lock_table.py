#!/usr/bin/env python3
"""
Create cab_lock table for locking CAB Mondays.
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
            CREATE TABLE IF NOT EXISTS cab_lock (
                id INTEGER PRIMARY KEY,
                cab_monday DATE NOT NULL UNIQUE,
                is_locked BOOLEAN DEFAULT 1,
                locked_by VARCHAR(100),
                locked_at DATETIME
            )
            """
        )
        conn.commit()
        print("✓ cab_lock table is present.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding cab_lock table...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


