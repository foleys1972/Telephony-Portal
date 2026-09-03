#!/usr/bin/env python3
"""
Add approval fields to change_record:
  - approved (BOOLEAN)
  - approved_by (VARCHAR)
  - cab_date (DATETIME)

SQLite doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS, so we PRAGMA-check first.
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


def add_columns():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='change_record'")
        if not cursor.fetchone():
            raise RuntimeError("change_record table not found. Run `add_changes_table.py` (or start the app) first.")

        cursor.execute("PRAGMA table_info(change_record)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        to_add = [
            ("approved", "BOOLEAN DEFAULT 0"),
            ("approved_by", "VARCHAR(100)"),
            ("cab_date", "DATETIME"),
        ]

        for name, col_type in to_add:
            if name in existing_cols:
                print(f"- Column {name} already exists, skipping.")
                continue
            cursor.execute(f"ALTER TABLE change_record ADD COLUMN {name} {col_type}")
            print(f"✓ Added column: {name}")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding approval fields to change_record...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    add_columns()


