#!/usr/bin/env python3
"""
Add additional MAC address fields to dealerboard_turret.

This keeps the existing `mac_address` (primary/unique) and adds:
  - mac_address_2
  - mac_address_3
  - mac_address_4
  - mac_address_5
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
        cursor.execute("PRAGMA table_info(dealerboard_turret)")
        existing_cols = {row[1] for row in cursor.fetchall()}

        new_cols = [
            ("mac_address_2", "VARCHAR(50)"),
            ("mac_address_3", "VARCHAR(50)"),
            ("mac_address_4", "VARCHAR(50)"),
            ("mac_address_5", "VARCHAR(50)"),
        ]

        for name, col_type in new_cols:
            if name in existing_cols:
                print(f"- Column {name} already exists, skipping.")
                continue

            cursor.execute(f"ALTER TABLE dealerboard_turret ADD COLUMN {name} {col_type}")
            print(f"✓ Added column: {name}")

        conn.commit()
        print("Done.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding turret MAC fields...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    add_columns()

