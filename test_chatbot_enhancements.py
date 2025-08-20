#!/usr/bin/env python3
"""
Test script to verify chatbot enhancements for hostname prefix and version checking
"""

from ai_command_generator import AICommandGenerator
from version_utils import is_version_compatible, format_version_comparison_error


class MockDatabase:
    """Mock database for testing"""
    
    def __init__(self):
        self.settings = {
            'chatbot.minimum_agent_version': '1.6.0',
            'chatbot.require_version_check': True
        }
        
    def get_enabled_ai_apis(self):
        return []
    
    def get_application_setting(self, key, default=None):
        return self.settings.get(key, default)


def test_hostname_prefix():
    """Test that all generated scripts include hostname command"""
    print("Testing hostname prefix in generated scripts...")
    
    mock_db = MockDatabase()
    generator = AICommandGenerator(mock_db)
    
    test_requests = [
        "Check disk space",
        "Show memory usage",
        "List running processes"
    ]
    
    for request in test_requests:
        result = generator.generate_script_from_request(request)
        
        if result['success']:
            script = result['script']
            has_hostname = 'hostname' in script.lower()
            
            # Check if hostname appears early in the script
            script_lines = script.split('\n')
            hostname_line_found = False
            for i, line in enumerate(script_lines[:10]):  # Check first 10 lines
                if line.strip() == 'hostname' or 'hostname' in line.lower():
                    hostname_line_found = True
                    break
            
            status = "✓" if hostname_line_found else "✗"
            print(f"{status} Request: '{request}' - Hostname prefix: {hostname_line_found}")
            
            if hostname_line_found:
                print(f"   Script preview: {script[:100]}...")
        else:
            print(f"✗ Request: '{request}' - Failed to generate script: {result.get('error')}")
    
    print()


def test_version_compatibility():
    """Test version compatibility checking"""
    print("Testing version compatibility checks...")
    
    test_cases = [
        # (current_version, minimum_version, expected_compatible)
        ("1.6.0", "1.6.0", True),
        ("1.6.1", "1.6.0", True),
        ("1.7.0", "1.6.0", True),
        ("2.0.0", "1.6.0", True),
        ("1.5.9", "1.6.0", False),
        ("1.6.0", "1.6.1", False),
        ("1.0.0", "1.6.0", False),
        ("", "1.6.0", False),
        ("invalid", "1.6.0", False),
    ]
    
    for current, minimum, expected in test_cases:
        result = is_version_compatible(current, minimum)
        status = "✓" if result == expected else "✗"
        print(f"{status} {current or 'None'} >= {minimum}: {result}")
        
        if not result and current and current != "invalid":
            error_msg = format_version_comparison_error(current, minimum)
            print(f"   Error: {error_msg}")
    
    print()


def test_script_templates():
    """Test that template scripts include hostname"""
    print("Testing template scripts include hostname...")
    
    mock_db = MockDatabase()
    generator = AICommandGenerator(mock_db)
    
    # Test each template
    template_requests = [
        "disk space",      # Should match disk_space template
        "memory usage",    # Should match memory_usage template  
        "cpu load",        # Should match cpu_usage template
        "network interface", # Should match network_info template
        "running processes", # Should match running_processes template
        "uptime",          # Should match uptime template
    ]
    
    for request in template_requests:
        result = generator.generate_script_from_request(request)
        
        if result['success']:
            script = result['script']
            template_used = result.get('template_used', 'unknown')
            
            # Check for hostname command
            has_hostname_cmd = any(
                line.strip() == 'hostname' or line.strip().startswith('hostname')
                for line in script.split('\n')
            )
            
            status = "✓" if has_hostname_cmd else "✗"
            print(f"{status} Template '{template_used}' for '{request}': hostname command present")
            
        else:
            print(f"✗ Request: '{request}' failed: {result.get('error', 'Unknown error')}")
    
    print()


def test_fallback_script():
    """Test that fallback script includes hostname"""
    print("Testing fallback script includes hostname...")
    
    mock_db = MockDatabase()
    generator = AICommandGenerator(mock_db)
    
    # Create a fallback script directly
    result = generator._create_fallback_script("test request")
    
    if result['success']:
        script = result['script']
        
        # Check for hostname command
        has_hostname_cmd = any(
            line.strip() == 'hostname' or line.strip().startswith('hostname')
            for line in script.split('\n')
        )
        
        status = "✓" if has_hostname_cmd else "✗"
        print(f"{status} Fallback script includes hostname command: {has_hostname_cmd}")
        
        if has_hostname_cmd:
            print("   Script preview:")
            for line in script.split('\n')[:15]:
                print(f"   {line}")
    else:
        print(f"✗ Failed to create fallback script: {result.get('error')}")
    
    print()


def main():
    """Run all tests"""
    print("=== Testing Chatbot Enhancements ===\n")
    
    # Test hostname prefix functionality
    test_hostname_prefix()
    
    # Test version compatibility
    test_version_compatibility()
    
    # Test template scripts
    test_script_templates()
    
    # Test fallback script
    test_fallback_script()
    
    print("=== Testing Complete ===")


if __name__ == "__main__":
    main()
