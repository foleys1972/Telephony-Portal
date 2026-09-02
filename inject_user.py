#!/usr/bin/env python3
"""
Interactive User Injection Script for Telephony DDI Portal

This script allows you to inject or update a user in the database with admin privileges.
When run without arguments, it will interactively prompt for username, password and role.

Run this script from the command line:
    python inject_user.py

Or with direct arguments:
    python inject_user.py username password [role]
"""

import os
import sys
import sqlite3
import getpass
from werkzeug.security import generate_password_hash

# Configuration
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'telephony.db')

def check_database_exists():
    """Check if the database file exists."""
    if not os.path.exists(DB_PATH):
        print(f"Error: Database file not found at {DB_PATH}")
        print("Make sure you're running this script from the project root directory.")
        print("If the database doesn't exist, make sure to run the application first to create it.")
        return False
    return True

def inject_user(username, password, role='admin'):
    """
    Inject or update a user in the database.
    
    Args:
        username (str): The username for the new/updated user
        password (str): The password for the new/updated user
        role (str): The role for the user ('admin' or 'user')
    
    Returns:
        bool: True if successful, False otherwise
    """
    if not check_database_exists():
        return False
    
    try:
        # Connect to the database
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Check if the user table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user'")
        if not cursor.fetchone():
            print("Error: User table doesn't exist in the database.")
            print("Run the application first to initialize the database schema.")
            conn.close()
            return False
        
        # Hash the password
        hashed_password = generate_password_hash(password)
        
        # Check if the user already exists
        cursor.execute("SELECT id FROM user WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            # Update existing user
            cursor.execute(
                "UPDATE user SET password = ?, role = ? WHERE username = ?",
                (hashed_password, role, username)
            )
            action = "updated"
        else:
            # Create new user
            cursor.execute(
                "INSERT INTO user (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_password, role)
            )
            action = "created"
        
        # Commit the changes and close the connection
        conn.commit()
        conn.close()
        
        print(f"Success: User '{username}' {action} with {role} privileges.")
        print(f"You can now log in with username '{username}' and the provided password.")
        return True
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def prompt_for_input():
    """Interactive prompts for user details."""
    print("=== Telephony DDI Portal - User Management ===")
    
    # Get username
    username = input("Enter username: ").strip()
    while not username:
        print("Username cannot be empty.")
        username = input("Enter username: ").strip()
    
    # Get password (masked input)
    password = getpass.getpass("Enter password: ")
    while not password:
        print("Password cannot be empty.")
        password = getpass.getpass("Enter password: ")
    
    # Confirm password
    confirm_password = getpass.getpass("Confirm password: ")
    while password != confirm_password:
        print("Passwords don't match. Please try again.")
        password = getpass.getpass("Enter password: ")
        confirm_password = getpass.getpass("Confirm password: ")
    
    # Get role
    valid_roles = ['admin', 'user']
    role = input("Enter role (admin/user) [default: admin]: ").strip().lower()
    if not role:
        role = 'admin'  # Default role
    
    while role not in valid_roles:
        print(f"Invalid role. Please choose from: {', '.join(valid_roles)}")
        role = input("Enter role (admin/user) [default: admin]: ").strip().lower()
        if not role:
            role = 'admin'  # Default role
    
    return username, password, role

def main():
    """Main function to handle command line arguments or interactive input."""
    if len(sys.argv) > 2:
        # Command line arguments provided
        username = sys.argv[1]
        password = sys.argv[2]
        role = sys.argv[3] if len(sys.argv) > 3 else 'admin'
    else:
        # Interactive mode
        username, password, role = prompt_for_input()
    
    # Inject the user
    inject_user(username, password, role)

if __name__ == "__main__":
    main()