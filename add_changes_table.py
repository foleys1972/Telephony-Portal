#!/usr/bin/env python3
"""
Create the Changes tracking table for existing SQLite databases.

Note: if you simply start the app, `db.create_all()` will also create missing tables.
This script is useful when you want to apply the schema change without starting Flask.
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


def create_table():
    if not os.path.exists(DB_PATH):
        raise FileNotFoundError(f"Database not found at: {DB_PATH}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS change_record (
                id INTEGER PRIMARY KEY,
                region VARCHAR(100),
                cr_number VARCHAR(50),
                ice_sent BOOLEAN DEFAULT 0,
                ice_approved BOOLEAN DEFAULT 0,
                coo_update VARCHAR(200),
                change_category VARCHAR(100),
                regional_approval VARCHAR(200),
                risk_mitigation TEXT,
                technology VARCHAR(200),
                snow_link VARCHAR(500),
                bau_project VARCHAR(50),
                raised_by VARCHAR(100),
                tech_lead VARCHAR(100),
                title VARCHAR(300),
                change_risk_level VARCHAR(50),
                start_date DATETIME,
                status VARCHAR(50),
                regular_change BOOLEAN DEFAULT 0,
                comments TEXT,
                date_created DATETIME,
                last_updated DATETIME,
                last_updated_by VARCHAR(100)
            )
            """
        )
        conn.commit()
        print("✓ change_record table is present.")
    finally:
        conn.close()


if __name__ == "__main__":
    print("Adding Changes table...")
    bp = backup_database()
    if bp:
        print(f"Backup created: {bp}")
    create_table()

