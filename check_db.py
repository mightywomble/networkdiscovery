#!/usr/bin/env python3
"""
Check database initialization
"""

import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

def check_db():
    """Check database initialization"""
    print("🔍 Checking database initialization...")
    
    try:
        from database import Database
        
        # Initialize database
        db = Database(':memory:')
        print("  - Creating database...")
        db.init_db()
        print("  - Database init_db() completed")
        
        # Check what tables were created
        with db.get_connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            
        print(f"  - Created {len(tables)} tables:")
        for table in sorted(tables):
            print(f"    ✓ {table}")
            
        # Check specifically for ai_api_settings
        if 'ai_api_settings' in tables:
            print("  ✅ ai_api_settings table created successfully")
            
            # Check table schema
            with db.get_connection() as conn:
                cursor = conn.execute("PRAGMA table_info(ai_api_settings);")
                columns = cursor.fetchall()
                
            print("    Columns:")
            for col in columns:
                print(f"      - {col[1]} ({col[2]})")
                
        else:
            print("  ❌ ai_api_settings table not found")
            return False
            
        return True
        
    except Exception as e:
        print(f"  ❌ Database check failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = check_db()
    if success:
        print("\n🎉 Database initialization check passed!")
    else:
        print("\n❌ Database initialization check failed!")
    sys.exit(0 if success else 1)
