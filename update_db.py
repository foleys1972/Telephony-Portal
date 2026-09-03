#!/usr/bin/env python3
"""
Database Migration Script for Enhanced Telephony Portal
Run this BEFORE starting the new app.py
"""

import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'telephony.db')

def backup_database():
    """Create a backup of the current database"""
    if os.path.exists(DB_PATH):
        backup_path = DB_PATH.replace('.db', f'_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.db')
        import shutil
        shutil.copy2(DB_PATH, backup_path)
        print(f"Database backed up to: {backup_path}")

def migrate_database():
    """Add all new columns and tables for enhanced features"""
    if not os.path.exists(DB_PATH):
        print("Database file not found. Please run the original app.py first to create the database.")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        print("Starting database migration...")
        
        # 1. Add user management columns
        print("Adding user management columns...")
        user_columns = [
            ("is_active", "BOOLEAN DEFAULT 1"),
            ("disabled_date", "DATETIME"),
            ("disabled_by", "VARCHAR(100)"),
            ("disable_reason", "VARCHAR(500)")
        ]
        
        for column_name, column_def in user_columns:
            try:
                cursor.execute(f"ALTER TABLE user ADD COLUMN {column_name} {column_def}")
                print(f"✓ Added user column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"- User column {column_name} already exists, skipping.")
                else:
                    print(f"✗ Error adding user column {column_name}: {e}")
        
        # Set all existing users to active
        cursor.execute("UPDATE user SET is_active = 1 WHERE is_active IS NULL")
        print("✓ Set all existing users to active")
        
        # 2. Add Private Wire new fields
        print("Adding Private Wire new fields...")
        pw_columns = [
            ("aor_number", "VARCHAR(50)"),
            ("port_number", "VARCHAR(50)"),
            ("channel_number", "VARCHAR(50)")
        ]
        
        for column_name, column_def in pw_columns:
            try:
                cursor.execute(f"ALTER TABLE private_wire ADD COLUMN {column_name} {column_def}")
                print(f"✓ Added private wire column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"- Private wire column {column_name} already exists, skipping.")
                else:
                    print(f"✗ Error adding private wire column {column_name}: {e}")
        
        # 3. Add DDI additional fields
        print("Adding DDI additional fields...")
        ddi_columns = [
            ("line_type", "VARCHAR(50)"),
            ("tpo_dns_name", "VARCHAR(100)"),
            ("voice_recording", "VARCHAR(10)"),
            ("place", "VARCHAR(100)"),
            ("slots", "VARCHAR(50)"),
            ("virtual_slot_start", "VARCHAR(50)"),
            ("virtual_slot_stop", "VARCHAR(50)")
        ]
        
        for column_name, column_def in ddi_columns:
            try:
                cursor.execute(f"ALTER TABLE ddi_number ADD COLUMN {column_name} {column_def}")
                print(f"✓ Added DDI column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"- DDI column {column_name} already exists, skipping.")
                else:
                    print(f"✗ Error adding DDI column {column_name}: {e}")
        
        # 4. Add Turret additional fields
        print("Adding Turret additional fields...")
        turret_columns = [
            ("installed_by", "VARCHAR(100)"),
            ("installation_date", "DATETIME"),
            ("installation_snow_ref", "VARCHAR(50)"),
            ("status", "VARCHAR(20) DEFAULT 'Active'"),
            ("created_by", "VARCHAR(100)"),
            ("last_updated_by", "VARCHAR(100)")
        ]
        
        for column_name, column_def in turret_columns:
            try:
                cursor.execute(f"ALTER TABLE dealerboard_turret ADD COLUMN {column_name} {column_def}")
                print(f"✓ Added turret column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"- Turret column {column_name} already exists, skipping.")
                else:
                    print(f"✗ Error adding turret column {column_name}: {e}")
        
        # Set all existing turrets to active status
        cursor.execute("UPDATE dealerboard_turret SET status = 'Active' WHERE status IS NULL")
        print("✓ Set all existing turrets to active status")
        
        # 5. Create TurretMoveGroup table
        print("Creating TurretMoveGroup table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_move_group (
            id INTEGER PRIMARY KEY,
            move_name VARCHAR(200) NOT NULL,
            description TEXT,
            created_by VARCHAR(100) NOT NULL,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            planned_execution_date DATETIME,
            status VARCHAR(20) DEFAULT 'Planning',
            executed_date DATETIME,
            executed_by VARCHAR(100),
            notes TEXT,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_updated_by VARCHAR(100)
        )
        """)
        print("✓ Created turret_move_group table")
        
        # 6. Create TurretMove table
        print("Creating TurretMove table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_move (
            id INTEGER PRIMARY KEY,
            move_group_id INTEGER NOT NULL,
            turret_id INTEGER NOT NULL,
            from_desk VARCHAR(100),
            to_desk VARCHAR(100) NOT NULL,
            from_office VARCHAR(100),
            to_office VARCHAR(100),
            from_country VARCHAR(50),
            to_country VARCHAR(50),
            move_reason VARCHAR(500),
            priority VARCHAR(20) DEFAULT 'Normal',
            status VARCHAR(20) DEFAULT 'Planned',
            snow_reference VARCHAR(50),
            business_justification TEXT,
            estimated_downtime_minutes INTEGER,
            actual_downtime_minutes INTEGER,
            requires_network_config BOOLEAN DEFAULT 0,
            requires_phone_config BOOLEAN DEFAULT 0,
            execution_notes TEXT,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            executed_date DATETIME,
            FOREIGN KEY (move_group_id) REFERENCES turret_move_group (id),
            FOREIGN KEY (turret_id) REFERENCES dealerboard_turret (id)
        )
        """)
        print("✓ Created turret_move table")
        
        # 7. Create TurretMoveHistory table
        print("Creating TurretMoveHistory table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_move_history (
            id INTEGER PRIMARY KEY,
            turret_id INTEGER NOT NULL,
            move_id INTEGER,
            move_group_id INTEGER,
            from_desk VARCHAR(100),
            to_desk VARCHAR(100),
            from_office VARCHAR(100),
            to_office VARCHAR(100),
            from_country VARCHAR(50),
            to_country VARCHAR(50),
            move_date DATETIME NOT NULL,
            moved_by VARCHAR(100) NOT NULL,
            move_reason VARCHAR(500),
            snow_reference VARCHAR(50),
            actual_downtime_minutes INTEGER,
            issues_encountered TEXT,
            resolution_notes TEXT,
            notes TEXT,
            FOREIGN KEY (turret_id) REFERENCES dealerboard_turret (id),
            FOREIGN KEY (move_id) REFERENCES turret_move (id),
            FOREIGN KEY (move_group_id) REFERENCES turret_move_group (id)
        )
        """)
        print("✓ Created turret_move_history table")
        
        # 8. Create ImportMappingTemplate table
        print("Creating ImportMappingTemplate table...")
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS import_mapping_template (
            id INTEGER PRIMARY KEY,
            template_name VARCHAR(100) NOT NULL,
            import_type VARCHAR(50) NOT NULL,
            field_mappings TEXT NOT NULL,
            created_by VARCHAR(100) NOT NULL,
            created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_used_date DATETIME,
            is_default BOOLEAN DEFAULT 0
        )
        """)
        print("✓ Created import_mapping_template table")
        
        # 9. Update CeasedPrivateWire table with new fields
        print("Updating CeasedPrivateWire table...")
        ceased_pw_columns = [
            ("aor_number", "VARCHAR(50)"),
            ("port_number", "VARCHAR(50)"),
            ("channel_number", "VARCHAR(50)")
        ]
        
        for column_name, column_def in ceased_pw_columns:
            try:
                cursor.execute(f"ALTER TABLE ceased_private_wire ADD COLUMN {column_name} {column_def}")
                print(f"✓ Added ceased private wire column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"- Ceased private wire column {column_name} already exists, skipping.")
                else:
                    print(f"✗ Error adding ceased private wire column {column_name}: {e}")
        
        conn.commit()
        print("\n🎉 Database migration completed successfully!")
        print("\nYou can now run the new app.py file.")
        
    except Exception as e:
        print(f"\n❌ Error during migration: {e}")
        conn.rollback()
        raise
    
    finally:
        conn.close()

def verify_migration():
    """Verify that all new columns and tables exist"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("\nVerifying migration...")
    
    try:
        # Check User table
        cursor.execute("PRAGMA table_info(user)")
        user_columns = [row[1] for row in cursor.fetchall()]
        required_user_columns = ['is_active', 'disabled_date', 'disabled_by', 'disable_reason']
        
        for col in required_user_columns:
            if col in user_columns:
                print(f"✓ User table has {col} column")
            else:
                print(f"✗ User table missing {col} column")
        
        # Check if new tables exist
        new_tables = ['turret_move_group', 'turret_move', 'turret_move_history', 'import_mapping_template']
        
        for table in new_tables:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,))
            if cursor.fetchone():
                print(f"✓ Table {table} exists")
            else:
                print(f"✗ Table {table} missing")
        
        print("\nMigration verification complete!")
        
    except Exception as e:
        print(f"Error during verification: {e}")
    
    finally:
        conn.close()

if __name__ == "__main__":
    print("Telephony Portal Database Migration")
    print("=" * 40)
    
    # Create backup first
    backup_database()
    
    # Run migration
    migrate_database()
    
    # Verify migration
    verify_migration()
    
    print("\n" + "=" * 40)
    print("Migration complete! You can now start the new app.py")