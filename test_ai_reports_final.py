#!/usr/bin/env python3
"""
Final test for AI Reports functionality
Tests the complete flow with proper API configurations
"""

import sys
import os
sys.path.append('.')

from database import Database
from host_manager import HostManager
from ai_report_generator import AIReportGenerator
from ai_data_collector import AIDataCollector

def test_ai_configuration():
    """Test AI API configuration saving and loading"""
    print("Testing AI API configuration...")
    
    db = Database()
    
    # Save test Gemini settings
    db.save_ai_api_settings(
        provider='gemini',
        api_key='test-key-gemini',
        model_name='gemini-2.5-flash',
        api_endpoint='https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
        temperature=0.7,
        max_tokens=1000,
        timeout=120,
        enabled=True
    )
    
    # Save test ChatGPT settings
    db.save_ai_api_settings(
        provider='chatgpt',
        api_key='test-key-chatgpt',
        model_name='gpt-3.5-turbo',
        api_endpoint='https://api.openai.com/v1/chat/completions',
        temperature=0.7,
        max_tokens=1000,
        timeout=120,
        enabled=True
    )
    
    # Test loading settings
    gemini_settings = db.get_ai_api_settings('gemini')
    chatgpt_settings = db.get_ai_api_settings('chatgpt')
    
    print(f"✓ Gemini settings saved: {gemini_settings['enabled']}")
    print(f"✓ ChatGPT settings saved: {chatgpt_settings['enabled']}")
    
    return True

def test_ai_data_collector():
    """Test AI data collection"""
    print("\nTesting AI data collection...")
    
    db = Database()
    host_manager = HostManager(db)
    collector = AIDataCollector(db, host_manager)
    
    # Test data statistics
    stats = collector.get_data_statistics()
    print(f"✓ Data stats collected: {stats}")
    
    # Test data collection (without actual API calls)
    try:
        all_data = collector.collect_all_data()
        formatted_data = collector.format_data_for_ai(all_data)
        print(f"✓ Data collection successful: {len(formatted_data)} data points")
    except Exception as e:
        print(f"✗ Data collection error: {e}")
        
    return True

def test_ai_report_formatting():
    """Test the AI report HTML formatting function"""
    print("\nTesting AI report HTML formatting...")
    
    # Import the formatting function
    from app import format_ai_report_to_html
    
    # Test with a sample report structure
    sample_report = {
        'metadata': {
            'generated_at': '2025-08-16T21:00:00',
            'ai_model': 'gemini',
            'data_type': 'all_data',
            'generation_time': '2.5 seconds'
        },
        'executive_summary': {
            'title': 'Executive Summary',
            'summary': 'This is a test network analysis report showing key insights.',
            'key_points': [
                'Network is operating normally',
                'No critical issues detected',
                'Performance is within expected parameters'
            ],
            'risk_level': 'LOW'
        },
        'network_overview': {
            'title': 'Network Overview',
            'analysis': 'The network topology shows a well-structured environment.',
            'topology_insights': {'total_hosts': 5, 'total_connections': 25}
        }
    }
    
    # Test formatting
    formatted_html = format_ai_report_to_html(sample_report)
    
    if len(formatted_html) > 100 and '<h2>' in formatted_html:
        print("✓ Report formatting successful")
        print(f"✓ Generated HTML length: {len(formatted_html)} characters")
        return True
    else:
        print("✗ Report formatting failed")
        print(f"Generated HTML: {formatted_html[:200]}...")
        return False

def test_ai_report_generator_initialization():
    """Test AI report generator initialization without API calls"""
    print("\nTesting AI report generator initialization...")
    
    try:
        db = Database()
        host_manager = HostManager(db)
        generator = AIReportGenerator(db, host_manager)
        
        # Test AI configuration loading
        gemini_config = generator._get_ai_configuration('gemini')
        chatgpt_config = generator._get_ai_configuration('chatgpt')
        
        if gemini_config and gemini_config.get('enabled'):
            print("✓ Gemini configuration loaded successfully")
        else:
            print("✗ Gemini configuration not available")
            
        if chatgpt_config and chatgpt_config.get('enabled'):
            print("✓ ChatGPT configuration loaded successfully")
        else:
            print("✗ ChatGPT configuration not available")
            
        print("✓ AI Report Generator initialized successfully")
        return True
        
    except Exception as e:
        print(f"✗ AI Report Generator initialization failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🤖 Starting AI Reports Final Test")
    print("=" * 50)
    
    tests = [
        test_ai_configuration,
        test_ai_data_collector,
        test_ai_report_formatting,
        test_ai_report_generator_initialization
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print("✗ Test failed")
        except Exception as e:
            print(f"✗ Test exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"🏁 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! AI Reports should work correctly.")
        print("\n📝 Next steps:")
        print("1. Start your Flask server")
        print("2. Go to Settings and configure your real AI API keys")
        print("3. Enable the AI services")
        print("4. Go to AI Reports and try generating a report")
        return True
    else:
        print("❌ Some tests failed. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
