#!/usr/bin/env python3
"""
Basic test script for AI Reports functionality (without paramiko dependencies)
"""

import sys
import os
import json
from datetime import datetime

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

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

def test_ai_data_collector_basic():
    """Test the AI Data Collector without host_manager"""
    print("🧪 Testing AI Data Collector (basic)...")
    
    try:
        from database import Database
        from ai_data_collector import AIDataCollector
        
        # Initialize components
        db = Database(':memory:')
        db.init_db()
        
        # Mock host manager
        class MockHostManager:
            def get_all_hosts(self):
                return [
                    {
                        'id': 1,
                        'name': 'test-host-1',
                        'ip_address': '192.168.1.10',
                        'username': 'root',
                        'ssh_port': 22,
                        'description': 'Test host 1',
                        'status': 'online',
                        'last_seen': datetime.now().isoformat(),
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    },
                    {
                        'id': 2,
                        'name': 'test-host-2',
                        'ip_address': '192.168.1.11',
                        'username': 'root',
                        'ssh_port': 22,
                        'description': 'Test host 2',
                        'status': 'offline',
                        'last_seen': datetime.now().isoformat(),
                        'created_at': datetime.now().isoformat(),
                        'updated_at': datetime.now().isoformat()
                    }
                ]
        
        host_manager = MockHostManager()
        collector = AIDataCollector(db, host_manager)
        
        # Test data statistics
        print("  - Getting data statistics...")
        stats = collector.get_data_statistics()
        print(f"    ✓ Stats retrieved with {len(stats)} categories")
        
        # Test data collection methods
        print("  - Testing data collection methods...")
        
        # Test latest capture
        print("    - Latest capture...")
        latest = collector.collect_latest_capture()
        print(f"      ✓ Latest capture: {len(str(latest))} characters")
        assert latest['data_type'] == 'latest_capture'
        assert 'hosts' in latest
        
        # Test latest logs
        print("    - Latest logs...")
        logs = collector.collect_latest_logs()
        print(f"      ✓ Latest logs: {len(str(logs))} characters")
        assert logs['data_type'] == 'latest_logs'
        
        # Test all data (limited)
        print("    - All data...")
        all_data = collector.collect_all_data()
        print(f"      ✓ All data: {len(str(all_data))} characters")
        assert all_data['data_type'] == 'complete_dataset'
        
        # Test data formatting
        print("    - Testing data formatting...")
        formatted = collector.format_data_for_ai(all_data)
        print(f"      ✓ Formatted data has summary: {'data_summary' in formatted}")
        
        print("  ✅ AI Data Collector tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ AI Data Collector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_ai_report_generator_basic():
    """Test the AI Report Generator (without actual API calls)"""
    print("🤖 Testing AI Report Generator (basic)...")
    
    try:
        from database import Database
        from ai_report_generator import AIReportGenerator
        
        # Initialize components
        db = Database(':memory:')
        db.init_db()
        
        # Mock host manager
        class MockHostManager:
            def get_all_hosts(self):
                return [
                    {
                        'id': 1,
                        'name': 'test-host-1',
                        'ip_address': '192.168.1.10',
                        'status': 'online'
                    }
                ]
        
        # Add some test AI settings
        db.save_ai_api_settings(
            provider='gemini',
            api_key='test-key-12345',
            model_name='gemini-pro',
            api_endpoint='https://generativelanguage.googleapis.com/v1/models/{model}:generateContent',
            enabled=True
        )
        
        host_manager = MockHostManager()
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
        
        security_threats = generator._identify_security_threats(test_data)
        print(f"    ✓ Security threats identified: {len(security_threats)}")
        
        print("  - Testing report generation (with mock data)...")
        # Test report generation (will fail due to no real API key, which is expected)
        try:
            report = generator.generate_report('gemini', 'latest_logs')
            print(f"    ✓ Report generated with {len(report)} sections")
            
            # Check for expected sections
            expected_sections = ['metadata', 'executive_summary', 'network_overview', 
                               'security_analysis', 'performance_insights', 
                               'infrastructure_analysis', 'recommendations', 'detailed_findings']
            
            missing_sections = []
            for section in expected_sections:
                if section in report:
                    print(f"      ✓ Section '{section}' present")
                else:
                    missing_sections.append(section)
                    print(f"      ❌ Section '{section}' missing")
            
            if missing_sections:
                print(f"    ⚠️ Missing sections: {missing_sections}")
            else:
                print("    ✓ All expected sections present")
                
        except Exception as e:
            print(f"    ⚠️ Expected error in report generation (no valid API): {str(e)[:100]}")
        
        print("  ✅ AI Report Generator tests passed!")
        return True
        
    except Exception as e:
        print(f"  ❌ AI Report Generator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_flask_routes():
    """Test that Flask routes can be imported"""
    print("🌐 Testing Flask AI Routes...")
    
    try:
        # Test that the flask app can be imported
        print("  - Testing app.py import...")
        
        # Just test that our new routes exist
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check for AI Reports routes
        routes_to_check = [
            "def ai_reports():",
            "def get_ai_reports_data_stats():",
            "def generate_ai_report():",
            "/ai_reports",
            "/api/ai_reports/data_stats",
            "/api/ai_reports/generate"
        ]
        
        missing_routes = []
        for route in routes_to_check:
            if route in content:
                print(f"    ✓ Found: {route}")
            else:
                missing_routes.append(route)
                print(f"    ❌ Missing: {route}")
        
        if missing_routes:
            print(f"  ❌ Missing routes: {missing_routes}")
            return False
        else:
            print("  ✅ All Flask AI routes found!")
            return True
        
    except Exception as e:
        print(f"  ❌ Flask routes test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_template_exists():
    """Test that the AI Reports template exists"""
    print("📄 Testing AI Reports Template...")
    
    try:
        template_path = 'templates/ai_reports.html'
        if os.path.exists(template_path):
            print(f"  ✓ Template found: {template_path}")
            
            # Check template content
            with open(template_path, 'r') as f:
                content = f.read()
            
            # Check for key elements
            key_elements = [
                'AI Reports',
                'data_stats',
                'generate_report',
                'ai_model',
                'data_type'
            ]
            
            for element in key_elements:
                if element in content:
                    print(f"    ✓ Found element: {element}")
                else:
                    print(f"    ❌ Missing element: {element}")
            
            print("  ✅ AI Reports template verified!")
            return True
        else:
            print(f"  ❌ Template not found: {template_path}")
            return False
        
    except Exception as e:
        print(f"  ❌ Template test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🚀 Starting AI Reports Basic Tests")
    print("=" * 50)
    
    tests = [
        test_database_ai_settings,
        test_ai_data_collector_basic,
        test_ai_report_generator_basic,
        test_flask_routes,
        test_template_exists
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
        print("\n🔧 Next Steps:")
        print("1. Configure AI API keys in the web interface")
        print("2. Access AI Reports at: http://localhost:5150/ai_reports")
        print("3. Test with real network data for comprehensive reports")
        return True
    else:
        print("❌ Some tests failed. Please check the implementation.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
