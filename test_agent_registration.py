#!/usr/bin/env python3
"""
Test script to manually register an agent with the server
"""

import requests
import json
import uuid
import socket
import platform

def test_agent_registration(server_url):
    """Test agent registration with the server"""
    
    # Get system info
    hostname = socket.gethostname()
    try:
        # Try to get the real IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
    except:
        ip_address = socket.gethostbyname(hostname)
    
    # Create registration data
    agent_id = str(uuid.uuid4())
    data = {
        'agent_id': agent_id,
        'hostname': hostname,
        'ip_address': ip_address,
        'username': 'test-user',
        'agent_version': '1.0.0',
        'platform': platform.platform()
    }
    
    print(f"Attempting to register agent:")
    print(f"  Agent ID: {agent_id}")
    print(f"  Hostname: {hostname}")
    print(f"  IP Address: {ip_address}")
    print(f"  Server URL: {server_url}")
    print()
    
    try:
        # Test registration
        url = f"{server_url}/api/agent/register"
        print(f"POST {url}")
        print(f"Data: {json.dumps(data, indent=2)}")
        print()
        
        response = requests.post(url, json=data, timeout=30)
        
        print(f"Response Status: {response.status_code}")
        print(f"Response Headers: {dict(response.headers)}")
        print()
        
        if response.status_code == 200:
            result = response.json()
            print(f"Response Body: {json.dumps(result, indent=2)}")
            
            if result.get('success'):
                print("✓ Agent registration successful!")
                
                # Test heartbeat
                print("\nTesting heartbeat...")
                heartbeat_data = {
                    'agent_id': agent_id,
                    'status': 'active'
                }
                
                heartbeat_url = f"{server_url}/api/agent/heartbeat"
                heartbeat_response = requests.post(heartbeat_url, json=heartbeat_data, timeout=10)
                
                print(f"Heartbeat Status: {heartbeat_response.status_code}")
                if heartbeat_response.status_code == 200:
                    heartbeat_result = heartbeat_response.json()
                    print(f"Heartbeat Response: {json.dumps(heartbeat_result, indent=2)}")
                    if heartbeat_result.get('success'):
                        print("✓ Heartbeat successful!")
                        
                        # Check if agent appears in the agents list
                        print("\nChecking agents list...")
                        agents_response = requests.get(f"{server_url}/api/agents")
                        if agents_response.status_code == 200:
                            agents_data = agents_response.json()
                            print(f"Total agents: {agents_data.get('count', 0)}")
                            for agent in agents_data.get('agents', []):
                                if agent.get('agent_id') == agent_id:
                                    print(f"✓ Found our agent in list: {agent.get('hostname')} - Status: {agent.get('heartbeat_status')}")
                                    break
                            else:
                                print("✗ Our agent not found in agents list")
                        else:
                            print(f"✗ Failed to get agents list: {agents_response.status_code}")
                    else:
                        print("✗ Heartbeat failed:", heartbeat_result.get('error'))
                else:
                    print(f"✗ Heartbeat failed with status {heartbeat_response.status_code}")
                    print(heartbeat_response.text)
            else:
                print("✗ Agent registration failed:", result.get('error'))
        else:
            print(f"✗ Registration failed with status {response.status_code}")
            print("Response body:", response.text)
            
    except Exception as e:
        print(f"✗ Error during registration test: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 test_agent_registration.py <server_url>")
        print("Example: python3 test_agent_registration.py http://192.168.1.100:5150")
        sys.exit(1)
    
    server_url = sys.argv[1].rstrip('/')
    test_agent_registration(server_url)
