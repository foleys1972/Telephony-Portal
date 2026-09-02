#!/usr/bin/env python3
"""
Add raised_datetime (auto-set, non-editable) to change_record.

Backfill rule:
  - If date_created exists, copy it into raised_datetime
  - Else set raised_datetime to CURRENT_TIMESTAMP
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
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='change_record'")
        if not cursor.fetchone():
            raise RuntimeError("change_record table not found. Run `add_changes_table.py` (or start the app) first.")

        cursor.execute("PRAGMA table_info(change_record)")
        cols = {row[1] for row in cursor.fetchall()}

        if "raised_datetime" not in cols:
            cursor.execute("ALTER TABLE change_record ADD COLUMN raised_datetime DATETIME")
            print("✓ Added column: raised_datetime")
        else:
            print("- Column raised_datetime already exists, skipping.")

        if "date_created" in cols:
            cursor.execute(
                """
                UPDATE change_record
                SET raised_datetime = COALESCE(raised_datetime, date_created, CURRENT_TIMESTAMP)
                """
            )
        else:
            cursor.execute(
                """
                UPDATE change_record
                SET raised_datetime = COALESCE(raised_datetime, CURRENT_TIMESTAMP)
                """
            )
        print("✓ Backfilled raised_datetime")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding raised_datetime to change_record...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


