#!/usr/bin/env python3
"""
Add approved_status (tri-state) to change_record and backfill from legacy boolean `approved`.

approved_status values:
  - Yes
  - No
  - On Hold
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

        if "approved_status" not in cols:
            cursor.execute("ALTER TABLE change_record ADD COLUMN approved_status VARCHAR(20) DEFAULT 'No'")
            print("✓ Added column: approved_status")
        else:
            print("- Column approved_status already exists, skipping.")

        # Backfill approved_status from legacy approved boolean where status is NULL/empty
        if "approved" in cols:
            cursor.execute(
                """
                UPDATE change_record
                SET approved_status = CASE
                    WHEN approved = 1 THEN 'Yes'
                    ELSE 'No'
                END
                WHERE approved_status IS NULL OR approved_status = ''
                """
            )
            print("✓ Backfilled approved_status from approved")
        else:
            cursor.execute("UPDATE change_record SET approved_status = 'No' WHERE approved_status IS NULL OR approved_status = ''")
            print("✓ Backfilled approved_status to 'No'")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding tri-state approved_status to change_record...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


