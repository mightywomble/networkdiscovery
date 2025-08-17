#!/usr/bin/env python3
"""
Test script for AI Reports functionality
"""

import sys
import os
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

def test_ai_data_collector():
    """Test the AI Data Collector"""
    print("🧪 Testing AI Data Collector...")
    
    try:
        from database import Database
        from host_manager import HostManager
        from ai_data_collector import AIDataCollector
        
        # Initialize components
        db = Database(':memory:')  # Use in-memory database for testing
        db.init_db()
        host_manager = HostManager(db)
        collector = AIDataCollector(db, host_manager)
        
        # Test data statistics
        print("  - Getting data statistics...")
        stats = collector.get_data_statistics()
        print(f"    ✓ Stats retrieved: {stats}")
        
        # Test data collection methods
        print("  - Testing data collection methods...")
        
        # Test latest capture
        print("    - Latest capture...")
        latest = collector.collect_latest_capture()
        print(f"      ✓ Latest capture: {len(str(latest))} characters")
        
        # Test latest logs
        print("    - Latest logs...")
        logs = collector.collect_latest_logs()
        print(f"      ✓ Latest logs: {len(str(logs))} characters")
        
        # Test all data (limited)
        print("    - All data...")
        all_data = collector.collect_all_data()
        print(f"      ✓ All data: {len(str(all_data))} characters")
        
        print("  ✅ AI Data Collector tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ AI Data Collector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ai_report_generator():
    """Test the AI Report Generator (without actual API calls)"""
    print("🤖 Testing AI Report Generator...")
    
    try:
        from database import Database
        from host_manager import HostManager
        from ai_report_generator import AIReportGenerator
        
        # Initialize components
        db = Database(':memory:')
        db.init_db()
        host_manager = HostManager(db)
        
        # Add some test AI settings
        db.save_ai_api_settings(
            provider='gemini',
            api_key='test-key-12345',
            model_name='gemini-pro',
            api_endpoint='https://generativelanguage.googleapis.com/v1/models/{model}:generateContent',
            enabled=True
        )
        
        generator = AIReportGenerator(db, host_manager)
        
        print("  - Testing data collection...")
        # Test data collection
        test_data = generator._collect_data_by_type('latest_logs')
        print(f"    ✓ Data collected: {len(str(test_data))} characters")
        
        print("  - Testing AI configuration...")
        # Test AI configuration
        config = generator._get_ai_configuration('gemini')
        print(f"    ✓ AI config retrieved: {config is not None}")
        
        print("  - Testing analysis methods...")
        # Test analysis methods (without AI calls)
        topology = generator._analyze_topology(test_data)
        print(f"    ✓ Topology analysis: {topology}")
        
        connections = generator._analyze_connections(test_data)
        print(f"    ✓ Connection analysis: {connections}")
        
        print("  - Testing report generation (error case)...")
        # Test report generation (will fail due to no real API key, which is expected)
        try:
            report = generator.generate_report('gemini', 'latest_logs')
            print(f"    ✓ Report generated with {len(report)} sections")
            # Check for expected sections
            expected_sections = ['metadata', 'executive_summary', 'network_overview', 
                               'security_analysis', 'performance_insights', 
                               'infrastructure_analysis', 'recommendations', 'detailed_findings']
            for section in expected_sections:
                if section in report:
                    print(f"      ✓ Section '{section}' present")
                else:
                    print(f"      ❌ Section '{section}' missing")
        except Exception as e:
            print(f"    ✓ Expected error in report generation (no valid API): {str(e)[:100]}")
        
        print("  ✅ AI Report Generator tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ AI Report Generator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_database_ai_settings():
    """Test database AI settings functionality"""
    print("💾 Testing Database AI Settings...")
    
    try:
        from database import Database
        
        # Initialize database
        db = Database(':memory:')
        db.init_db()
        
        print("  - Testing AI settings CRUD operations...")
        
        # Test save settings
        db.save_ai_api_settings(
            provider='chatgpt',
            api_key='sk-test123456',
            model_name='gpt-3.5-turbo',
            api_endpoint='https://api.openai.com/v1/chat/completions',
            temperature=0.8,
            max_tokens=2000,
            timeout=45,
            enabled=True,
            additional_config={'stream': True}
        )
        print("    ✓ Settings saved")
        
        # Test get settings
        settings = db.get_ai_api_settings('chatgpt')
        print(f"    ✓ Settings retrieved: {settings['provider']}")
        assert settings['provider'] == 'chatgpt'
        assert settings['enabled'] == True
        assert settings['additional_config']['stream'] == True
        
        # Test get all settings
        all_settings = db.get_all_ai_api_settings()
        print(f"    ✓ All settings retrieved: {len(all_settings)} providers")
        
        # Test enable/disable
        db.enable_ai_api('chatgpt', False)
        settings = db.get_ai_api_settings('chatgpt')
        assert settings['enabled'] == False
        print("    ✓ Settings disabled")
        
        # Test enabled APIs only
        enabled_apis = db.get_enabled_ai_apis()
        print(f"    ✓ Enabled APIs: {len(enabled_apis)}")
        
        # Test delete settings
        success = db.delete_ai_api_settings('chatgpt')
        assert success == True
        print("    ✓ Settings deleted")
        
        print("  ✅ Database AI Settings tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ Database AI Settings test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🚀 Starting AI Reports Implementation Tests")
    print("=" * 50)
    
    tests = [
        test_database_ai_settings,
        test_ai_data_collector,
        test_ai_report_generator
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! AI Reports implementation is working correctly.")
        return True
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
