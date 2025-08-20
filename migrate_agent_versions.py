#!/usr/bin/env python3
"""
Database migration script to add agent_version column if missing
Run this on the remote server before running the diagnostic script
"""

import sqlite3
import sys

def migrate_database():
    """Add agent_version column to agents table if it doesn't exist"""
    try:
        conn = sqlite3.connect('network_scanner.db')
        cursor = conn.cursor()
        
        print("=== DATABASE MIGRATION ===")
        
        # Check if agents table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='agents'")
        if not cursor.fetchone():
            print("❌ Agents table does not exist. Please check your database.")
            return False
        
        # Check if agent_version column exists
        cursor.execute("PRAGMA table_info(agents)")
        columns = cursor.fetchall()
        column_names = [col[1] for col in columns]
        
        if 'agent_version' in column_names:
            print("✅ agent_version column already exists")
            return True
        
        print("Adding agent_version column to agents table...")
        
        # Add agent_version column
        cursor.execute("ALTER TABLE agents ADD COLUMN agent_version TEXT")
        
        # Add updated_at column if it doesn't exist
        if 'updated_at' not in column_names:
            print("Adding updated_at column to agents table...")
            cursor.execute("ALTER TABLE agents ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        
        conn.commit()
        print("✅ Database migration completed successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration error: {e}")
        return False
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Network Discovery Database Migration Tool")
    print("=" * 45)
    
    if migrate_database():
        print("\n✅ Migration successful!")
        print("You can now run the diagnostic script: python3 debug_agent_versions.py")
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)
