#!/usr/bin/env python3
"""
Script to add active column to User table
"""

import os
import sqlite3

# Database path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'telephony.db')

def add_active_column():
    """Add active column to User table"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check if the database exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
    if not cursor.fetchone():
        print("Error: User table doesn't exist.")
        conn.close()
        return False
    
    try:
        cursor.execute("ALTER TABLE user ADD COLUMN active BOOLEAN DEFAULT 1")
        print("Added active column to User table")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("Column active already exists, skipping.")
        else:
            print(f"Error adding column: {e}")
    
    conn.commit()
    conn.close()
    print("Database update completed.")
    return True

if __name__ == "__main__":
    add_active_column()