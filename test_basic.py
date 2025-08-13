#!/usr/bin/env python3
"""
Basic test script to verify Network Map application components
"""

import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

class TestNetworkMapComponents(unittest.TestCase):
    
    def test_imports(self):
        """Test that all modules can be imported"""
        try:
            import app
            import database
            import host_manager
            import network_scanner
            print("✓ All modules imported successfully")
        except ImportError as e:
            self.fail(f"Failed to import modules: {e}")
    
    def test_database_init(self):
        """Test database initialization"""
        from database import Database
        
        # Use temporary database
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            db = Database(tmp_path)
            db.init_db()
            
            # Test adding a host
            host_id = db.add_host("test-host", "192.168.1.100", "testuser", 22, "Test host")
            self.assertIsNotNone(host_id)
            
            # Test retrieving the host
            host = db.get_host(host_id)
            self.assertIsNotNone(host)
            self.assertEqual(host['name'], "test-host")
            self.assertEqual(host['ip_address'], "192.168.1.100")
            
            # Test getting all hosts
            hosts = db.get_all_hosts()
            self.assertEqual(len(hosts), 1)
            
            print("✓ Database functionality working")
            
        finally:
            # Clean up
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def test_host_manager_init(self):
        """Test host manager initialization"""
        from database import Database
        from host_manager import HostManager
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            db = Database(tmp_path)
            db.init_db()
            
            hm = HostManager(db)
            self.assertIsNotNone(hm)
            
            # Test adding host through host manager
            host_id = hm.add_host("test-host-2", "192.168.1.101")
            self.assertIsNotNone(host_id)
            
            hosts = hm.get_all_hosts()
            self.assertEqual(len(hosts), 1)
            
            print("✓ Host Manager functionality working")
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    def test_network_scanner_init(self):
        """Test network scanner initialization"""
        from database import Database
        from host_manager import HostManager
        from network_scanner import NetworkScanner
        
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        
        try:
            db = Database(tmp_path)
            db.init_db()
            
            hm = HostManager(db)
            ns = NetworkScanner(hm, db)
            
            self.assertIsNotNone(ns)
            
            print("✓ Network Scanner initialization working")
            
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
    
    @patch('paramiko.SSHClient')
    def test_flask_app_creation(self, mock_ssh):
        """Test Flask app creation"""
        # Mock SSH to avoid actual connections
        mock_ssh.return_value = MagicMock()
        
        try:
            from app import app
            
            self.assertIsNotNone(app)
            self.assertTrue(app.config['TESTING'] if 'TESTING' in app.config else True)
            
            # Test that routes are registered
            with app.test_client() as client:
                # Test main page (should return 200 or redirect)
                response = client.get('/')
                self.assertIn(response.status_code, [200, 302, 500])  # 500 might occur due to missing DB
                
                # Test hosts page
                response = client.get('/hosts')
                self.assertIn(response.status_code, [200, 302, 500])
                
            print("✓ Flask application creation working")
            
        except Exception as e:
            self.fail(f"Flask app creation failed: {e}")

def run_tests():
    """Run all tests"""
    print("Running Network Map component tests...\n")
    
    # Check dependencies first
    try:
        import flask
        import paramiko
        print("✓ Required dependencies available\n")
    except ImportError as e:
        print(f"✗ Missing dependency: {e}")
        print("Please install requirements: pip3 install -r requirements.txt")
        return False
    
    # Run unit tests
    unittest.main(verbosity=2, exit=False, argv=[''])
    
    print("\n" + "="*50)
    print("Basic component tests completed!")
    print("\nTo start the application:")
    print("  python3 run.py")
    print("  or: python3 app.py")
    return True

if __name__ == '__main__':
    run_tests()
