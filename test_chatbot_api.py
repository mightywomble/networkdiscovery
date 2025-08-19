#!/usr/bin/env python3
"""
Simple test script to verify chatbot API endpoints are working correctly.
Run this script to test the basic chatbot functionality.
"""

import requests
import json
import time

BASE_URL = "http://localhost:5150"

def test_chatbot_endpoints():
    """Test basic chatbot API endpoints"""
    print("🤖 Testing AI Chatbot API Endpoints\n")
    
    # Test 1: Check if server is running
    print("1. Testing server connectivity...")
    try:
        response = requests.get(f"{BASE_URL}/api/test", timeout=5)
        if response.status_code == 200:
            print("   ✅ Server is running")
        else:
            print("   ❌ Server returned non-200 status")
            return False
    except requests.exceptions.RequestException as e:
        print(f"   ❌ Cannot connect to server: {e}")
        print("   💡 Make sure the Flask app is running on localhost:5150")
        return False
    
    # Test 2: Get hosts
    print("\n2. Testing host list retrieval...")
    try:
        response = requests.get(f"{BASE_URL}/api/hosts")
        data = response.json()
        if data.get('success'):
            hosts = data.get('hosts', [])
            print(f"   ✅ Found {len(hosts)} configured hosts")
            for host in hosts[:3]:  # Show first 3 hosts
                print(f"      - {host['name']} ({host['ip_address']}) - {host.get('status', 'unknown')}")
        else:
            print(f"   ⚠️  Host API returned: {data.get('error', 'Unknown error')}")
    except Exception as e:
        print(f"   ❌ Error getting hosts: {e}")
    
    # Test 3: Start conversation
    print("\n3. Testing conversation start...")
    try:
        response = requests.post(
            f"{BASE_URL}/api/chatbot/start",
            json={"user_id": "test_user"},
            headers={"Content-Type": "application/json"}
        )
        data = response.json()
        if data.get('success'):
            conversation_id = data.get('conversation_id')
            print(f"   ✅ Conversation started: {conversation_id}")
        else:
            print(f"   ❌ Failed to start conversation: {data.get('error')}")
            return False
    except Exception as e:
        print(f"   ❌ Error starting conversation: {e}")
        return False
    
    # Test 4: Send test message
    print("\n4. Testing message sending...")
    try:
        test_message = "Check system uptime and basic status"
        response = requests.post(
            f"{BASE_URL}/api/chatbot/message",
            json={
                "conversation_id": conversation_id,
                "message": test_message,
                "selected_hosts": []
            },
            headers={"Content-Type": "application/json"}
        )
        data = response.json()
        if data.get('success'):
            print(f"   ✅ Message sent successfully")
            print(f"      Bot response: {data.get('response', 'No response')[:100]}...")
            if data.get('script_content'):
                print(f"      Script generated: Yes ({len(data['script_content'])} chars)")
            if data.get('validation_result'):
                validation = data['validation_result']
                print(f"      Validation: {validation.get('risk_level', 'Unknown')} risk")
        else:
            print(f"   ❌ Failed to send message: {data.get('error')}")
    except Exception as e:
        print(f"   ❌ Error sending message: {e}")
    
    # Test 5: Test script validation endpoint
    print("\n5. Testing script validation...")
    try:
        test_script = "#!/bin/bash\necho 'Hello World'\nuptime\necho 'System status check complete'"
        response = requests.post(
            f"{BASE_URL}/api/chatbot/validate_script",
            json={"script": test_script},
            headers={"Content-Type": "application/json"}
        )
        data = response.json()
        if data.get('success'):
            validation = data.get('validation', {})
            print(f"   ✅ Script validation working")
            print(f"      Risk level: {validation.get('risk_level', 'Unknown')}")
            print(f"      Safe commands: {len(validation.get('safe_commands', []))}")
            print(f"      Risky commands: {len(validation.get('risky_commands', []))}")
        else:
            print(f"   ❌ Script validation failed: {data.get('error')}")
    except Exception as e:
        print(f"   ❌ Error validating script: {e}")
    
    # Test 6: Test script generation endpoint
    print("\n6. Testing script generation...")
    try:
        response = requests.post(
            f"{BASE_URL}/api/chatbot/generate_script",
            json={
                "request": "Show network interfaces and their IP addresses",
                "selected_hosts": []
            },
            headers={"Content-Type": "application/json"}
        )
        data = response.json()
        if data.get('success'):
            print(f"   ✅ Script generation working")
            if data.get('script'):
                print(f"      Generated script: {len(data['script'])} characters")
                print(f"      First line: {data['script'].split('\\n')[0]}")
        else:
            print(f"   ❌ Script generation failed: {data.get('error')}")
    except Exception as e:
        print(f"   ❌ Error generating script: {e}")
    
    print("\n🎉 Chatbot API testing completed!")
    print("\n💡 Next steps:")
    print("   1. Open http://localhost:5150/ai_chatbot in your browser")
    print("   2. Configure AI API keys in Settings if needed")
    print("   3. Add some hosts to test script execution")
    print("   4. Try asking the AI to help with network tasks")
    
    return True

def check_dependencies():
    """Check if required modules are available"""
    print("📦 Checking dependencies...\n")
    
    required_modules = [
        'flask',
        'sqlite3',
        'requests',
        'json',
        'datetime',
        'threading',
        'time'
    ]
    
    missing_modules = []
    
    for module in required_modules:
        try:
            __import__(module)
            print(f"   ✅ {module}")
        except ImportError:
            print(f"   ❌ {module} - MISSING")
            missing_modules.append(module)
    
    if missing_modules:
        print(f"\n⚠️  Missing modules: {', '.join(missing_modules)}")
        print("   Install them with: pip install " + " ".join(missing_modules))
        return False
    
    print("\n✅ All dependencies are available!")
    return True

if __name__ == "__main__":
    print("=" * 50)
    print("AI CHATBOT API TEST")
    print("=" * 50)
    
    # Check dependencies first
    if not check_dependencies():
        exit(1)
    
    print("\n" + "=" * 50)
    
    # Test the API endpoints
    test_chatbot_endpoints()
