#!/usr/bin/env python3
"""
Simple runner script for the Network Map application
"""

import os
import sys

def main():
    # Ensure we're in the right directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    # Check if virtual environment is activated
    if not hasattr(sys, 'real_prefix') and not (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("Warning: Virtual environment not detected.")
        print("It's recommended to run this in a virtual environment.")
        print("\nTo set up a virtual environment:")
        print("  python3 -m venv venv")
        print("  source venv/bin/activate")
        print("  pip3 install -r requirements.txt")
        print()
    
    # Try to import required modules
    try:
        import flask
        import paramiko
        print("✓ Required dependencies found")
    except ImportError as e:
        print(f"✗ Missing required dependency: {e}")
        print("Please install requirements: pip3 install -r requirements.txt")
        sys.exit(1)
    
    # Start the application
    print("Starting Network Map application...")
    print("Application will be available at: http://localhost:5150")
    print("Press Ctrl+C to stop\n")
    
    try:
        from app import app, db
        
        # Initialize database
        print("Initializing database...")
        db.init_db()
        print("✓ Database initialized")
        
        # Start Flask app
        app.run(debug=True, host='0.0.0.0', port=5150, threaded=True)
        
    except KeyboardInterrupt:
        print("\n\nShutting down gracefully...")
    except Exception as e:
        print(f"\nError starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
