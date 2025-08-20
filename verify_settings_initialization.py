#!/usr/bin/env python3
"""
Verification script to test that default application settings are properly initialized
during database setup and can be retrieved correctly.
"""

import os
import tempfile
from database import Database

def verify_settings_initialization():
    """Test that default settings are initialized during database setup"""
    print("=== Testing Default Settings Initialization ===\n")
    
    # Use temporary database to test initialization
    temp_db = tempfile.mktemp(suffix='.db')
    try:
        print(f"Creating temporary database: {temp_db}")
        db = Database(temp_db)
        
        # Initialize database - this should create default settings
        print("Initializing database...")
        db.init_db()
        
        # Verify default settings were created
        print("\nVerifying default application settings:")
        
        # Test chatbot minimum agent version
        min_version = db.get_application_setting('chatbot.minimum_agent_version')
        print(f"✓ chatbot.minimum_agent_version: {min_version} (expected: '1.6.0')")
        assert min_version == '1.6.0', f"Expected '1.6.0', got {min_version}"
        
        # Test version check enforcement flag
        require_check = db.get_application_setting('chatbot.require_version_check')
        print(f"✓ chatbot.require_version_check: {require_check} (expected: True)")
        assert require_check is True, f"Expected True, got {require_check}"
        
        # Test script timeout
        timeout = db.get_application_setting('chatbot.script_timeout')
        print(f"✓ chatbot.script_timeout: {timeout} (expected: 300)")
        assert timeout == 300, f"Expected 300, got {timeout}"
        
        # Test max concurrent executions
        max_concurrent = db.get_application_setting('chatbot.max_concurrent_executions')
        print(f"✓ chatbot.max_concurrent_executions: {max_concurrent} (expected: 5)")
        assert max_concurrent == 5, f"Expected 5, got {max_concurrent}"
        
        # Test default value handling for non-existent setting
        non_existent = db.get_application_setting('non.existent.setting', 'default_value')
        print(f"✓ non-existent setting with default: {non_existent} (expected: 'default_value')")
        assert non_existent == 'default_value', f"Expected 'default_value', got {non_existent}"
        
        # Test getting all settings
        all_settings = db.get_all_application_settings()
        print(f"\n✓ Retrieved {len(all_settings)} application settings")
        
        expected_keys = [
            'chatbot.minimum_agent_version',
            'chatbot.require_version_check',
            'chatbot.script_timeout',
            'chatbot.max_concurrent_executions'
        ]
        
        for key in expected_keys:
            assert key in all_settings, f"Expected key '{key}' not found in all settings"
            setting_info = all_settings[key]
            print(f"  - {key}: {setting_info['value']} ({setting_info['type']}) - {setting_info['description'][:50]}...")
        
        print("\n=== Settings Modification Test ===")
        
        # Test updating a setting
        db.save_application_setting('chatbot.minimum_agent_version', '1.7.0', 'string', 'Updated minimum version')
        updated_version = db.get_application_setting('chatbot.minimum_agent_version')
        print(f"✓ Updated minimum version: {updated_version} (expected: '1.7.0')")
        assert updated_version == '1.7.0', f"Expected '1.7.0', got {updated_version}"
        
        # Test adding a new setting
        db.save_application_setting('test.new_setting', 42, 'integer', 'Test integer setting')
        new_setting = db.get_application_setting('test.new_setting')
        print(f"✓ New integer setting: {new_setting} (expected: 42)")
        assert new_setting == 42, f"Expected 42, got {new_setting}"
        
        # Test boolean setting
        db.save_application_setting('test.boolean_setting', False, 'boolean', 'Test boolean setting')
        bool_setting = db.get_application_setting('test.boolean_setting')
        print(f"✓ Boolean setting: {bool_setting} (expected: False)")
        assert bool_setting is False, f"Expected False, got {bool_setting}"
        
        print("\n=== Reinitialization Test ===")
        
        # Test that reinitialization doesn't overwrite existing settings
        db.initialize_default_settings()
        preserved_version = db.get_application_setting('chatbot.minimum_agent_version')
        print(f"✓ Setting preserved after reinitialization: {preserved_version} (expected: '1.7.0')")
        assert preserved_version == '1.7.0', f"Expected '1.7.0', got {preserved_version}"
        
        print("\n✅ All settings initialization tests passed!")
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # Clean up temporary database
        if os.path.exists(temp_db):
            os.unlink(temp_db)
            print(f"\nCleaned up temporary database: {temp_db}")
    
    return True

if __name__ == "__main__":
    success = verify_settings_initialization()
    exit(0 if success else 1)
