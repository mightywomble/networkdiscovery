#!/usr/bin/env python3
"""
Complete functionality test for chatbot enhancements.
This demonstrates the complete integration of hostname prefixes and version checking.
"""

import tempfile
import os
from database import Database
from ai_command_generator import AICommandGenerator
from version_utils import is_version_compatible, parse_version
from chatbot_controller import ChatbotController

def test_complete_functionality():
    """Test the complete enhanced chatbot functionality"""
    print("=== Complete Chatbot Enhancement Functionality Test ===\n")
    
    # Create temporary database
    temp_db = tempfile.mktemp(suffix='.db')
    try:
        db = Database(temp_db)
        db.init_db()
        
        print("1. Database initialized with default settings")
        min_version = db.get_application_setting('chatbot.minimum_agent_version')
        require_check = db.get_application_setting('chatbot.require_version_check')
        print(f"   - Default minimum agent version: {min_version}")
        print(f"   - Version checking enabled: {require_check}")
        
        # Test AI Command Generator with hostname prefixes
        print("\n2. Testing AI Command Generator with hostname prefixes")
        generator = AICommandGenerator(db)
        
        # Test various command types
        test_commands = [
            "Check disk space on all servers",
            "Show memory usage",
            "List running processes"
        ]
        
        all_have_hostname = True
        for cmd in test_commands:
            result = generator.generate_script_from_request(cmd)
            if result.get('success'):
                script = result['script']
                has_hostname = 'hostname' in script.lower()
                print(f"   ✓ '{cmd}' -> hostname prefix: {has_hostname}")
                if not has_hostname:
                    all_have_hostname = False
            else:
                print(f"   ✗ '{cmd}' -> generation failed: {result.get('error')}")
                all_have_hostname = False
        
        if all_have_hostname:
            print("   ✅ All generated scripts include hostname commands")
        else:
            print("   ❌ Some scripts missing hostname commands")
            
        # Test version utilities
        print("\n3. Testing version compatibility utilities")
        
        version_tests = [
            ("1.6.0", "1.6.0", True),   # Equal versions
            ("1.6.1", "1.6.0", True),   # Higher patch
            ("1.7.0", "1.6.0", True),   # Higher minor
            ("2.0.0", "1.6.0", True),   # Higher major  
            ("1.5.9", "1.6.0", False),  # Lower patch
            ("1.5.0", "1.6.0", False),  # Lower minor
            ("0.9.0", "1.6.0", False),  # Much lower
        ]
        
        version_test_success = True
        for current, minimum, expected in version_tests:
            result = is_version_compatible(current, minimum)
            status = "✓" if result == expected else "✗"
            print(f"   {status} {current} >= {minimum}: {result} (expected: {expected})")
            if result != expected:
                version_test_success = False
        
        if version_test_success:
            print("   ✅ All version compatibility tests passed")
        else:
            print("   ❌ Some version compatibility tests failed")
            
        # Test chatbot controller integration
        print("\n4. Testing ChatbotController with version validation")
        
        # Add test hosts and agents
        host1_id = db.add_host("prod-server-1", "10.0.1.10", "admin", 22, "Production server")
        host2_id = db.add_host("prod-server-2", "10.0.1.20", "admin", 22, "Production server")
        host3_id = db.add_host("dev-server-1", "10.0.2.10", "dev", 22, "Development server")
        
        # Register agents with different versions
        db.register_agent("agent-1", "prod-server-1", "10.0.1.10", "admin", "1.6.0", host1_id)    # Meets minimum
        db.register_agent("agent-2", "prod-server-2", "10.0.1.20", "admin", "1.7.1", host2_id)    # Above minimum
        db.register_agent("agent-3", "dev-server-1", "10.0.2.10", "dev", "1.5.8", host3_id)       # Below minimum
        
        print(f"   - Added 3 hosts with agents (versions: 1.6.0, 1.7.1, 1.5.8)")
        print(f"   - Minimum required version: {min_version}")
        
        # Create controller with mock host manager
        class MockHostManager:
            def __init__(self):
                pass
                
        controller = ChatbotController(db, MockHostManager())
        
        # Test validation scenarios
        test_scenarios = [
            {
                'name': 'All compatible hosts',
                'hosts': [host1_id, host2_id],
                'expected': True,
                'description': 'Hosts with versions 1.6.0 and 1.7.1'
            },
            {
                'name': 'Mixed compatibility',
                'hosts': [host1_id, host2_id, host3_id],
                'expected': False,
                'description': 'Including host with version 1.5.8'
            },
            {
                'name': 'Only incompatible host',
                'hosts': [host3_id],
                'expected': False,
                'description': 'Host with version 1.5.8'
            }
        ]
        
        validation_success = True
        for scenario in test_scenarios:
            is_valid, error_msg = controller._validate_agent_versions(scenario['hosts'])
            expected = scenario['expected']
            status = "✓" if is_valid == expected else "✗"
            print(f"   {status} {scenario['name']}: {is_valid} (expected: {expected})")
            print(f"     {scenario['description']}")
            if error_msg and not is_valid:
                print(f"     Error: {error_msg.split(chr(10))[0]}...")  # First line of error
            if is_valid != expected:
                validation_success = False
        
        if validation_success:
            print("   ✅ All validation scenarios passed")
        else:
            print("   ❌ Some validation scenarios failed")
            
        # Test settings modification
        print("\n5. Testing dynamic settings modification")
        
        # Change minimum version
        db.save_application_setting('chatbot.minimum_agent_version', '1.7.0', 'string')
        print("   - Changed minimum version to 1.7.0")
        
        # Now host1 (1.6.0) should fail, but host2 (1.7.1) should pass
        is_valid_h1, _ = controller._validate_agent_versions([host1_id])
        is_valid_h2, _ = controller._validate_agent_versions([host2_id])
        
        print(f"   ✓ Host 1 (v1.6.0) validation: {is_valid_h1} (expected: False)")
        print(f"   ✓ Host 2 (v1.7.1) validation: {is_valid_h2} (expected: True)")
        
        settings_success = (not is_valid_h1) and is_valid_h2
        if settings_success:
            print("   ✅ Dynamic settings modification works correctly")
        else:
            print("   ❌ Dynamic settings modification failed")
            
        # Test disable version checking
        print("\n6. Testing version checking disable")
        db.save_application_setting('chatbot.require_version_check', False, 'boolean')
        
        # Now all hosts should pass validation regardless of version
        is_valid, _ = controller._validate_agent_versions([host1_id, host2_id, host3_id])
        print(f"   ✓ All hosts with checking disabled: {is_valid} (expected: True)")
        
        disable_success = is_valid
        if disable_success:
            print("   ✅ Version checking disable works correctly")
        else:
            print("   ❌ Version checking disable failed")
            
        # Overall result
        print("\n" + "="*60)
        all_tests_passed = (
            all_have_hostname and 
            version_test_success and 
            validation_success and 
            settings_success and 
            disable_success
        )
        
        if all_tests_passed:
            print("🎉 ALL TESTS PASSED - Chatbot enhancements are fully functional!")
            print("\n📋 Summary of implemented features:")
            print("   ✅ Hostname prefix injection in all generated scripts")
            print("   ✅ Semantic version comparison utilities")
            print("   ✅ Agent version validation before script execution")
            print("   ✅ Database-driven configuration for version requirements")
            print("   ✅ Dynamic settings modification")
            print("   ✅ Optional version checking (can be disabled)")
            print("   ✅ Detailed error messages for version incompatibilities")
        else:
            print("❌ SOME TESTS FAILED - Please review the output above")
            
        return all_tests_passed
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up
        if os.path.exists(temp_db):
            os.unlink(temp_db)

if __name__ == "__main__":
    success = test_complete_functionality()
    exit(0 if success else 1)
