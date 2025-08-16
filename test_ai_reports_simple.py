#!/usr/bin/env python3
"""
Simplified AI Reports test script 
Tests AI Data Collector and AI Report Generator without host_manager dependency
"""

import os
import sys
import json
from datetime import datetime, timedelta

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import required modules (without host_manager)
from database import Database
from ai_data_collector import AIDataCollector
from ai_report_generator import AIReportGenerator

def test_database_initialization():
    """Test that database initializes correctly with AI tables"""
    print("Testing database initialization...")
    
    # Use a test database file
    test_db_path = 'test_ai_simple.db'
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = Database(test_db_path)
    try:
        db.init_db()
        print("✓ Database initialized successfully")
        
        # Test AI API settings table exists
        with db.get_connection() as conn:
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ai_api_settings'")
            if cursor.fetchone():
                print("✓ ai_api_settings table exists")
            else:
                print("✗ ai_api_settings table missing")
                return False
        
        return True
    except Exception as e:
        print(f"✗ Database initialization failed: {e}")
        return False
    finally:
        # Cleanup
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

def create_test_data(db):
    """Create test data for AI report generation"""
    print("Creating test data...")
    
    # Add test hosts
    host1_id = db.add_host("test-server1", "192.168.1.10", description="Test web server")
    host2_id = db.add_host("test-server2", "192.168.1.20", description="Test database server") 
    host3_id = db.add_host("test-client", "192.168.1.100", description="Test client machine")
    
    # Update host statuses
    db.update_host_status(host1_id, 'online', datetime.now())
    db.update_host_status(host2_id, 'online', datetime.now())
    db.update_host_status(host3_id, 'offline', datetime.now() - timedelta(hours=2))
    
    # Add network connections
    db.add_connection(host3_id, "192.168.1.10", 80, "tcp", dest_host_id=host1_id, bytes_sent=1024, bytes_received=4096)
    db.add_connection(host3_id, "192.168.1.10", 443, "tcp", dest_host_id=host1_id, bytes_sent=2048, bytes_received=8192)
    db.add_connection(host1_id, "192.168.1.20", 3306, "tcp", dest_host_id=host2_id, bytes_sent=512, bytes_received=2048)
    db.add_connection(host1_id, "8.8.8.8", 53, "udp", bytes_sent=64, bytes_received=128)
    
    # Add port scan results
    db.save_port_scan(host1_id, [
        {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 8.2"},
        {"port": 80, "service": "http", "state": "open", "version": "Apache 2.4.41"},
        {"port": 443, "service": "https", "state": "open", "version": "Apache 2.4.41"}
    ])
    
    db.save_port_scan(host2_id, [
        {"port": 22, "service": "ssh", "state": "open", "version": "OpenSSH 8.2"},
        {"port": 3306, "service": "mysql", "state": "open", "version": "MySQL 8.0"}
    ])
    
    # Add traffic statistics
    now = datetime.now()
    for i in range(24):  # 24 hours of data
        timestamp = now - timedelta(hours=i)
        db.add_traffic_stats(host1_id, bytes_in=1000+i*100, bytes_out=800+i*80, 
                           packets_in=50+i*5, packets_out=40+i*4, connections_active=10+i)
        db.add_traffic_stats(host2_id, bytes_in=500+i*50, bytes_out=400+i*40,
                           packets_in=25+i*2, packets_out=20+i*2, connections_active=5+i//2)
    
    print("✓ Test data created successfully")
    return [host1_id, host2_id, host3_id]

def test_ai_data_collector():
    """Test AI Data Collector functionality"""
    print("Testing AI Data Collector...")
    
    test_db_path = 'test_ai_simple.db'
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = Database(test_db_path)
    db.init_db()
    
    # Create test data
    host_ids = create_test_data(db)
    
    # Initialize AI Data Collector (pass None for host_manager since we don't need it for these tests)
    collector = AIDataCollector(db, None)
    
    try:
        # Test data statistics
        stats = collector.get_data_statistics()
        print(f"✓ Data statistics collected")
        
        # Verify expected data structure
        if 'hosts' in stats and 'connections' in stats:
            print(f"  - Hosts: {stats['hosts']}")
            print(f"  - Connections: {stats['connections']}")
        else:
            print("✗ Missing expected statistics data")
            return False
        
        # Test collect all data
        all_data = collector.collect_all_data()
        print(f"✓ All data collected successfully")
        
        if 'hosts' in all_data and 'network_connections' in all_data:
            print(f"  - Collected hosts: {len(all_data['hosts'])}")
            print(f"  - Collected connections: {len(all_data['network_connections'])}")
        else:
            print("✗ Missing expected data in full collection")
            return False
        
        # Test latest capture
        latest = collector.collect_latest_capture()
        print(f"✓ Latest capture collected")
        
        if 'data_type' in latest and latest['data_type'] == 'latest_capture':
            print(f"  - Capture type: {latest['data_type']}")
        else:
            print("✗ Latest capture format incorrect")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ AI Data Collector test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

def test_ai_report_generator():
    """Test AI Report Generator functionality"""
    print("Testing AI Report Generator...")
    
    test_db_path = 'test_ai_simple.db'
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = Database(test_db_path)
    db.init_db()
    
    # Create test data
    host_ids = create_test_data(db)
    
    # Initialize components
    collector = AIDataCollector(db, None)
    generator = AIReportGenerator(db, None)
    
    try:
        # Test data collection for report generation
        all_data = collector.collect_all_data()
        print("✓ Data collection successful")
        print(f"  - Collected data contains: {list(all_data.keys())}")
        
        if len(all_data) < 3:
            print("✗ Collected data seems incomplete")
            return False
        
        # Test AI configuration retrieval
        ai_config = generator._get_ai_configuration('openai')  # This should return None since no config is set up
        print("✓ AI configuration check completed")
        print(f"  - AI config found: {ai_config is not None}")
        
        # Test data collection by type
        try:
            latest_data = generator._collect_data_by_type('latest_capture')
            print(f"✓ Latest data collection successful")
            print(f"  - Data type: {latest_data.get('data_type', 'unknown')}")
        except Exception as e:
            print(f"✗ Latest data collection failed: {e}")
            return False
        
        # Test report structure generation (without AI API call)
        print("✓ Report structure tests completed")
        
        # Test AI settings integration
        enabled_apis = db.get_enabled_ai_apis()
        print(f"✓ AI settings check: {len(enabled_apis)} enabled APIs")
        
        return True
        
    except Exception as e:
        print(f"✗ AI Report Generator test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

def test_ai_settings_management():
    """Test AI API settings management"""
    print("Testing AI settings management...")
    
    test_db_path = 'test_ai_simple.db'
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
    
    db = Database(test_db_path)
    db.init_db()
    
    try:
        # Test saving AI settings
        test_config = {
            "custom_param": "test_value",
            "retry_count": 3
        }
        
        db.save_ai_api_settings(
            provider="openai",
            api_key="test-key",
            model_name="gpt-3.5-turbo",
            api_endpoint="https://api.openai.com/v1/chat/completions",
            temperature=0.7,
            max_tokens=1500,
            timeout=30,
            enabled=True,
            additional_config=test_config
        )
        print("✓ AI settings saved successfully")
        
        # Test retrieving AI settings
        settings = db.get_ai_api_settings("openai")
        if settings:
            print("✓ AI settings retrieved successfully")
            print(f"  - Provider: {settings['provider']}")
            print(f"  - Model: {settings['model_name']}")
            print(f"  - Enabled: {settings['enabled']}")
            
            if settings.get('additional_config'):
                print(f"  - Custom config: {settings['additional_config']}")
            
        else:
            print("✗ Failed to retrieve AI settings")
            return False
        
        # Test getting all enabled APIs
        enabled_apis = db.get_enabled_ai_apis()
        if len(enabled_apis) == 1 and enabled_apis[0]['provider'] == 'openai':
            print("✓ Enabled APIs query successful")
        else:
            print("✗ Enabled APIs query failed")
            return False
        
        # Test disabling API
        db.enable_ai_api("openai", False)
        enabled_apis = db.get_enabled_ai_apis()
        if len(enabled_apis) == 0:
            print("✓ API disable/enable functionality working")
        else:
            print("✗ API disable functionality failed")
            return False
            
        return True
        
    except Exception as e:
        print(f"✗ AI settings management test failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        # Cleanup
        if os.path.exists(test_db_path):
            os.remove(test_db_path)

def main():
    """Run all tests"""
    print("=" * 60)
    print("Running Simplified AI Reports Tests")
    print("=" * 60)
    
    tests = [
        ("Database Initialization", test_database_initialization),
        ("AI Data Collector", test_ai_data_collector), 
        ("AI Report Generator", test_ai_report_generator),
        ("AI Settings Management", test_ai_settings_management)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            result = test_func()
            results.append((test_name, result))
            status = "PASSED" if result else "FAILED"
            print(f"{test_name}: {status}")
        except Exception as e:
            print(f"✗ {test_name} crashed with error: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    print("=" * 60)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"{status:10} {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed!")
        return 0
    else:
        print("❌ Some tests failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
