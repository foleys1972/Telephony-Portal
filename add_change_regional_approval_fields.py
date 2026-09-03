#!/usr/bin/env python3
"""
Add regional approval fields to change_record:
  - regional_approval_status (VARCHAR)
  - regional_approver_name (VARCHAR)

Backfill:
  - If legacy regional_approval contains 'Yes'/'No', copy to regional_approval_status.
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

        if "regional_approval_status" not in cols:
            cursor.execute("ALTER TABLE change_record ADD COLUMN regional_approval_status VARCHAR(20)")
            print("✓ Added column: regional_approval_status")
        else:
            print("- Column regional_approval_status already exists, skipping.")

        if "regional_approver_name" not in cols:
            cursor.execute("ALTER TABLE change_record ADD COLUMN regional_approver_name VARCHAR(100)")
            print("✓ Added column: regional_approver_name")
        else:
            print("- Column regional_approver_name already exists, skipping.")

        if "regional_approval" in cols:
            cursor.execute(
                """
                UPDATE change_record
                SET regional_approval_status =
                    CASE
                        WHEN lower(trim(regional_approval)) IN ('yes','no') THEN upper(substr(trim(regional_approval),1,1)) || lower(substr(trim(regional_approval),2))
                        ELSE regional_approval_status
                    END
                WHERE regional_approval_status IS NULL OR regional_approval_status = ''
                """
            )
            print("✓ Backfilled regional_approval_status from legacy regional_approval where possible")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding regional approval fields to change_record...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


