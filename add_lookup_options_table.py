#!/usr/bin/env python3
"""
Create lookup_option table for managing dropdown values (if missing).
Also seeds core defaults.
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


def create_table_and_seed():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS lookup_option (
                id INTEGER PRIMARY KEY,
                "group" VARCHAR(50) NOT NULL,
                value VARCHAR(200) NOT NULL,
                is_active BOOLEAN DEFAULT 1,
                sort_order INTEGER DEFAULT 0,
                created_date DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        defaults = {
            'region': ['Americas', 'APAC', 'EMEA'],
            'yes_no': ['Yes', 'No'],
            'change_category': ['Batch', 'Software', 'Hardware'],
            'technology': ['TFV', 'MC'],
            'approved_status': ['No', 'On Hold', 'Yes'],
        }

        for group, values in defaults.items():
            for idx, value in enumerate(values):
                cursor.execute(
                    "SELECT 1 FROM lookup_option WHERE \"group\" = ? AND value = ?",
                    (group, value),
                )
                if cursor.fetchone():
                    continue
                cursor.execute(
                    "INSERT INTO lookup_option (\"group\", value, is_active, sort_order) VALUES (?, ?, 1, ?)",
                    (group, value, idx),
                )

        conn.commit()
        print("✓ lookup_option table is present and defaults are seeded.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding lookup_option table...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    create_table_and_seed()

