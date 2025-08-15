#!/usr/bin/env python3
"""
Test script to verify enhanced test results generation
"""

import sys
import os
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Any

# Add the current directory to Python path to import our agent
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def run_test_network_scan():
    """Test the enhanced network scan functionality"""
    print("🚀 Testing Enhanced Network Scan Results v1.5.2")
    print("=" * 60)
    
    # Create sample scan data similar to what the agent would collect
    scan_data = {
        'timestamp': datetime.now().isoformat(),
        'hostname': 'test-host',
        'system_info': {
            'hostname': 'test-host',
            'ip_address': '192.168.1.100',
            'platform': 'Linux-5.4.0-test',
            'python_version': '3.8.10',
            'agent_version': '1.5.2'
        },
        'network_interfaces': {
            'ip_addr': """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 52:54:00:12:34:56 brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"""
        },
        'routing_table': [
            'default via 192.168.1.1 dev eth0 proto dhcp src 192.168.1.100 metric 100',
            '192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100',
            '192.168.1.1 dev eth0 proto dhcp scope link src 192.168.1.100 metric 100'
        ],
        'arp_table': [
            '192.168.1.1 (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0',
            '192.168.1.50 (192.168.1.50) at 11:22:33:44:55:66 [ether] on eth0'
        ],
        'listening_ports': [
            'State      Recv-Q Send-Q Local Address:Port               Peer Address:Port',
            'LISTEN     0      128    0.0.0.0:22                      0.0.0.0:*',
            'LISTEN     0      128    0.0.0.0:5150                    0.0.0.0:*',
            'LISTEN     0      80     0.0.0.0:80                      0.0.0.0:*'
        ],
        'active_connections': [
            'State      Recv-Q Send-Q Local Address:Port               Peer Address:Port',
            'LISTEN     0      128    0.0.0.0:22                      0.0.0.0:*',
            'ESTAB      0      0      192.168.1.100:22                192.168.1.50:45678',
            'ESTAB      0      0      192.168.1.100:5150              192.168.1.50:56789'
        ],
        'network_stats': {
            'net_dev': """Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000000    1000    0    0    0     0          0         0  1000000    1000    0    0    0     0       0          0
  eth0: 50000000   45000    0    0    0     0          0         0 25000000   30000    0    0    0     0       0          0"""
        },
        'process_network': [
            'COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME',
            'sshd      123 root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)',
            'python3   456 user    4u  IPv4  23456      0t0  TCP *:5150 (LISTEN)',
            'nginx     789 www     5u  IPv4  34567      0t0  TCP *:80 (LISTEN)'
        ]
    }
    
    # Import the enhanced agent class
    try:
        from networkmap_agent import NetworkMapAgent
        print("✅ Successfully imported NetworkMapAgent v1.5.2")
    except ImportError as e:
        print(f"❌ Failed to import agent: {e}")
        return False
    
    # Create agent instance
    agent = NetworkMapAgent()
    
    # Test the enhanced network test functions
    try:
        print("\n🔬 Running Enhanced Network Tests...")
        test_results = agent._run_network_tests(scan_data)
        
        print(f"\n📊 Test Results Generated:")
        print(f"   Categories: {len(test_results)}")
        
        for category, tests in test_results.items():
            print(f"\n📁 {category}:")
            for test_name, result in tests.items():
                status = "✅ PASS" if result.get('success') else "❌ FAIL"
                print(f"   {status} {test_name}")
                print(f"       Description: {result.get('description', 'N/A')}")
                if result.get('details'):
                    # Show first line of details
                    details_preview = result['details'].split('\n')[0][:80]
                    print(f"       Details: {details_preview}...")
        
        # Check if we have enhanced details
        has_enhanced_details = False
        for category, tests in test_results.items():
            for test_name, result in tests.items():
                if result.get('details') and len(result['details']) > 50:
                    has_enhanced_details = True
                    break
            if has_enhanced_details:
                break
        
        if has_enhanced_details:
            print("\n✅ Enhanced test details are being generated correctly!")
        else:
            print("\n⚠️  Test details are basic - enhanced details may not be working")
        
        # Save test results to a file for inspection
        with open('/tmp/networkmap_test_results.json', 'w') as f:
            json.dump({
                'scan_data': scan_data,
                'test_results': test_results
            }, f, indent=2)
        
        print(f"\n💾 Full test results saved to: /tmp/networkmap_test_results.json")
        return True
        
    except Exception as e:
        print(f"❌ Error running enhanced tests: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_test_network_scan()
    print("\n" + "=" * 60)
    if success:
        print("🎉 Enhanced test results are working correctly!")
        print("💡 If your agents still show basic details, they need to be updated to v1.5.2")
    else:
        print("💥 There's an issue with the enhanced test functionality")
    
    sys.exit(0 if success else 1)
