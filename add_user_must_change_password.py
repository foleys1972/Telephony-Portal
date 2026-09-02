#!/usr/bin/env python3
"""
Add must_change_password flag to user table (force password change on first login).
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
        cursor.execute("PRAGMA table_info(user)")
        cols = {row[1] for row in cursor.fetchall()}

        if "must_change_password" in cols:
            print("- Column must_change_password already exists, skipping.")
        else:
            cursor.execute("ALTER TABLE user ADD COLUMN must_change_password BOOLEAN DEFAULT 0")
            print("✓ Added column: must_change_password")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding must_change_password to user...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    migrate()


