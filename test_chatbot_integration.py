#!/usr/bin/env python3
"""
Integration test for chatbot version checking functionality.
Tests the complete flow from database settings to version validation.
"""

import os
import tempfile
import sys
from unittest.mock import MagicMock, patch
from database import Database
from chatbot_controller import ChatbotController

def create_test_database():
    """Create a test database with sample data"""
    temp_db = tempfile.mktemp(suffix='.db')
    db = Database(temp_db)
    db.init_db()
    
    # Add some test hosts
    host1_id = db.add_host("test-host-1", "192.168.1.10", "root", 22, "Test host 1")
    host2_id = db.add_host("test-host-2", "192.168.1.20", "root", 22, "Test host 2")
    host3_id = db.add_host("test-host-3", "192.168.1.30", "root", 22, "Test host 3")
    
    # Add test agents with different versions
    db.register_agent("agent-1", "test-host-1", "192.168.1.10", "root", "1.6.0", host1_id)
    db.register_agent("agent-2", "test-host-2", "192.168.1.20", "root", "1.5.9", host2_id)  # Below minimum
    db.register_agent("agent-3", "test-host-3", "192.168.1.30", "root", "1.7.0", host3_id)  # Above minimum
    
    # Add a host without an agent
    host4_id = db.add_host("test-host-4", "192.168.1.40", "root", 22, "Test host without agent")
    
    return temp_db, db, [host1_id, host2_id, host3_id, host4_id]

def test_version_checking_integration():
    """Test the complete version checking integration"""
    print("=== Testing Chatbot Version Checking Integration ===\n")
    
    temp_db_path, db, host_ids = create_test_database()
    
    try:
        # Create chatbot controller with test database
        # Mock a basic host manager since we're only testing version checking
        class MockHostManager:
            def __init__(self):
                pass
        
        mock_host_manager = MockHostManager()
        controller = ChatbotController(db, mock_host_manager)
        
        print("Database setup complete with test data:")
        print(f"- Host 1 (ID {host_ids[0]}): Agent version 1.6.0 (meets minimum)")
        print(f"- Host 2 (ID {host_ids[1]}): Agent version 1.5.9 (below minimum)")
        print(f"- Host 3 (ID {host_ids[2]}): Agent version 1.7.0 (above minimum)")
        print(f"- Host 4 (ID {host_ids[3]}): No agent")
        
        # Test 1: All compatible hosts
        print("\n=== Test 1: Compatible hosts only ===")
        compatible_hosts = [host_ids[0], host_ids[2]]  # 1.6.0 and 1.7.0
        is_valid, error_msg = controller._validate_agent_versions(compatible_hosts)
        print(f"Validation result: {is_valid}")
        if not is_valid:
            print(f"Error message: {error_msg}")
        assert is_valid, "Expected validation to pass for compatible hosts"
        print("✅ Compatible hosts validation passed")
        
        # Test 2: Include incompatible host
        print("\n=== Test 2: Include incompatible host ===")
        mixed_hosts = [host_ids[0], host_ids[1], host_ids[2]]  # Including 1.5.9
        is_valid, error_msg = controller._validate_agent_versions(mixed_hosts)
        print(f"Validation result: {is_valid}")
        print(f"Error message: {error_msg}")
        assert not is_valid, "Expected validation to fail for incompatible hosts"
        assert "1.5.9" in error_msg, "Error message should mention incompatible version"
        assert "test-host-2" in error_msg, "Error message should mention incompatible host"
        print("✅ Incompatible host validation correctly failed")
        
        # Test 3: Include host with missing agent
        print("\n=== Test 3: Include host with missing agent ===")
        missing_agent_hosts = [host_ids[0], host_ids[3]]  # Include host without agent
        is_valid, error_msg = controller._validate_agent_versions(missing_agent_hosts)
        print(f"Validation result: {is_valid}")
        print(f"Error message: {error_msg}")
        assert not is_valid, "Expected validation to fail for hosts without agents"
        assert "test-host-4" in error_msg, "Error message should mention host without agent"
        print("✅ Missing agent validation correctly failed")
        
        # Test 4: Disable version checking
        print("\n=== Test 4: Version checking disabled ===")
        db.save_application_setting('chatbot.require_version_check', False, 'boolean')
        is_valid, error_msg = controller._validate_agent_versions(mixed_hosts)
        print(f"Validation result: {is_valid}")
        assert is_valid, "Expected validation to pass when version checking is disabled"
        print("✅ Version checking disable works correctly")
        
        # Test 5: Change minimum version and re-enable checking
        print("\n=== Test 5: Updated minimum version ===")
        db.save_application_setting('chatbot.require_version_check', True, 'boolean')
        db.save_application_setting('chatbot.minimum_agent_version', '1.7.0', 'string')
        
        # Now host 1 (1.6.0) should fail, but host 3 (1.7.0) should pass
        is_valid, error_msg = controller._validate_agent_versions([host_ids[0]])  # 1.6.0
        print(f"Host 1 validation result: {is_valid}")
        if not is_valid:
            print(f"Error message: {error_msg}")
        assert not is_valid, "Expected host 1 to fail with raised minimum version"
        
        is_valid, error_msg = controller._validate_agent_versions([host_ids[2]])  # 1.7.0
        print(f"Host 3 validation result: {is_valid}")
        assert is_valid, "Expected host 3 to pass with raised minimum version"
        print("✅ Updated minimum version works correctly")
        
        # Test 6: Direct validation function test
        print("\n=== Test 6: Direct validation function test ===")
        
        # Reset minimum version for this test
        db.save_application_setting('chatbot.minimum_agent_version', '1.6.0', 'string')
        
        # Test the validation function directly - this is the core functionality
        # Testing with compatible hosts
        is_valid, error_msg = controller._validate_agent_versions([host_ids[0], host_ids[2]])  # 1.6.0 and 1.7.0
        print(f"Direct validation - compatible hosts: {is_valid}")
        assert is_valid, f"Expected validation to pass, got error: {error_msg}"
        
        # Testing with incompatible hosts
        is_valid, error_msg = controller._validate_agent_versions([host_ids[0], host_ids[1]])  # 1.6.0 and 1.5.9
        print(f"Direct validation - incompatible hosts: {is_valid}")
        print(f"Error message: {error_msg}")
        assert not is_valid, "Expected validation to fail for incompatible hosts"
        assert "1.5.9" in error_msg, "Error should mention incompatible version"
        print("✅ Direct validation function works correctly")
        
        print("\n✅ All integration tests passed!")
        return True
        
    except Exception as e:
        print(f"\n❌ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Clean up
        if os.path.exists(temp_db_path):
            os.unlink(temp_db_path)
            print(f"\nCleaned up test database: {temp_db_path}")

if __name__ == "__main__":
    success = test_version_checking_integration()
    exit(0 if success else 1)
