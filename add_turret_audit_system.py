#!/usr/bin/env python3
"""
Script to add comprehensive turret audit system
"""

import os
import sqlite3

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'telephony.db')

def add_turret_audit_system():
    """Add turret audit tables and update existing tables"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        # Add new columns to DealerboardTurret table
        turret_columns = [
            "installed_by VARCHAR(100)",
            "installation_date DATETIME",
            "installation_snow_ref VARCHAR(50)",
            "status VARCHAR(20) DEFAULT 'Active'",
            "created_by VARCHAR(100)",
            "last_updated_by VARCHAR(100)"
        ]
        
        for column_def in turret_columns:
            column_name = column_def.split()[0]
            try:
                cursor.execute(f"ALTER TABLE dealerboard_turret ADD COLUMN {column_def}")
                print(f"Added column: {column_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column name" in str(e):
                    print(f"Column {column_name} already exists, skipping.")
                else:
                    print(f"Error adding column {column_name}: {e}")
        
        # Create TurretMoveRequest table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_move_request (
            id INTEGER PRIMARY KEY,
            turret_id INTEGER NOT NULL,
            current_desk_location VARCHAR(100),
            current_office VARCHAR(100),
            current_country VARCHAR(50),
            planned_desk_location VARCHAR(100) NOT NULL,
            planned_office VARCHAR(100),
            planned_country VARCHAR(50),
            move_reason VARCHAR(500),
            priority VARCHAR(20) DEFAULT 'Normal',
            business_justification TEXT,
            snow_reference VARCHAR(50),
            snow_change_request VARCHAR(50),
            status VARCHAR(20) DEFAULT 'Planned',
            requested_by VARCHAR(100) NOT NULL,
            assigned_to VARCHAR(100),
            approved_by VARCHAR(100),
            executed_by VARCHAR(100),
            requested_date DATETIME,
            planned_move_date DATETIME,
            approved_date DATETIME,
            executed_date DATETIME,
            estimated_cost FLOAT,
            actual_cost FLOAT,
            requires_network_config BOOLEAN DEFAULT 0,
            requires_phone_config BOOLEAN DEFAULT 0,
            downtime_required BOOLEAN DEFAULT 0,
            estimated_downtime_minutes INTEGER,
            notes TEXT,
            execution_notes TEXT,
            last_updated DATETIME,
            last_updated_by VARCHAR(100),
            FOREIGN KEY (turret_id) REFERENCES dealerboard_turret (id)
        )
        """)
        print("Created turret_move_request table")
        
        # Create TurretMoveHistory table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_move_history (
            id INTEGER PRIMARY KEY,
            turret_id INTEGER NOT NULL,
            move_request_id INTEGER,
            from_desk_location VARCHAR(100),
            to_desk_location VARCHAR(100),
            from_office VARCHAR(100),
            to_office VARCHAR(100),
            from_country VARCHAR(50),
            to_country VARCHAR(50),
            move_date DATETIME,
            moved_by VARCHAR(100),
            move_reason VARCHAR(500),
            snow_reference VARCHAR(50),
            actual_downtime_minutes INTEGER,
            issues_encountered TEXT,
            resolution_notes TEXT,
            notes TEXT,
            FOREIGN KEY (turret_id) REFERENCES dealerboard_turret (id),
            FOREIGN KEY (move_request_id) REFERENCES turret_move_request (id)
        )
        """)
        print("Created turret_move_history table")
        
        # Create TurretAuditLog table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS turret_audit_log (
            id INTEGER PRIMARY KEY,
            turret_id INTEGER NOT NULL,
            action VARCHAR(50) NOT NULL,
            field_changed VARCHAR(100),
            old_value VARCHAR(500),
            new_value VARCHAR(500),
            change_reason VARCHAR(500),
            snow_reference VARCHAR(50),
            related_move_request_id INTEGER,
            changed_by VARCHAR(100) NOT NULL,
            change_date DATETIME,
            ip_address VARCHAR(45),
            user_agent VARCHAR(500),
            FOREIGN KEY (turret_id) REFERENCES dealerboard_turret (id),
            FOREIGN KEY (related_move_request_id) REFERENCES turret_move_request (id)
        )
        """)
        print("Created turret_audit_log table")
        
        conn.commit()
        print("Turret audit system created successfully.")
        
    except Exception as e:
        print(f"Error creating audit system: {e}")
        conn.rollback()
    
    conn.close()

if __name__ == "__main__":
    add_turret_audit_system()