#!/usr/bin/env python3
"""
Check Database Scan Data
Script to examine what scan data is actually being stored in the database
"""

import sqlite3
import json
import sys
from datetime import datetime

def check_database_scan_data():
    """Check what scan data is stored in the database"""
    db_path = "/Users/david/code/networkmap/networkmap.db"
    
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        
        print("NetworkMap Database Scan Data Analysis")
        print("=" * 50)
        
        # 1. Check how many agents we have
        cursor = conn.execute("SELECT COUNT(*) as count FROM agents")
        agent_count = cursor.fetchone()['count']
        print(f"Total agents in database: {agent_count}")
        
        # 2. List all agents with their versions
        cursor = conn.execute("""
            SELECT agent_id, hostname, ip_address, agent_version, status, last_heartbeat 
            FROM agents 
            ORDER BY last_heartbeat DESC
        """)
        agents = cursor.fetchall()
        
        print(f"\nAgents:")
        for agent in agents:
            print(f"  • {agent['hostname']} ({agent['ip_address']}) - Version: {agent['agent_version']} - Status: {agent['status']}")
            print(f"    Last heartbeat: {agent['last_heartbeat']}")
        
        # 3. Check scan results count
        cursor = conn.execute("SELECT COUNT(*) as count FROM agent_scan_results")
        scan_count = cursor.fetchone()['count']
        print(f"\nTotal scan results in database: {scan_count}")
        
        # 4. Get latest scan results for each agent
        for agent in agents:
            agent_id = agent['agent_id']
            hostname = agent['hostname']
            
            print(f"\n" + "="*60)
            print(f"AGENT: {hostname} (ID: {agent_id})")
            print(f"="*60)
            
            # Get latest scan result
            cursor = conn.execute("""
                SELECT * FROM agent_scan_results 
                WHERE agent_id = ? 
                ORDER BY scan_timestamp DESC 
                LIMIT 1
            """, (agent_id,))
            
            latest_scan = cursor.fetchone()
            
            if not latest_scan:
                print("  ❌ No scan results found for this agent")
                continue
            
            print(f"  📅 Latest scan: {latest_scan['scan_timestamp']}")
            print(f"  📋 Scan type: {latest_scan['scan_type']}")
            print(f"  ✅ Processed: {latest_scan['processed']}")
            
            # Parse scan data
            try:
                scan_data = json.loads(latest_scan['scan_data'])
                
                print(f"\n  📊 SCAN DATA STRUCTURE:")
                print(f"     • Keys in scan_data: {list(scan_data.keys())}")
                
                # Check if test_results exist
                if 'test_results' in scan_data:
                    test_results = scan_data['test_results']
                    print(f"     • test_results found: {type(test_results)}")
                    
                    if isinstance(test_results, dict):
                        print(f"     • Test categories: {list(test_results.keys())}")
                        
                        # Show details of each test category
                        for category, tests in test_results.items():
                            print(f"\n       🧪 {category}:")
                            if isinstance(tests, dict):
                                for test_name, result in tests.items():
                                    if isinstance(result, dict):
                                        success = result.get('success', 'unknown')
                                        description = result.get('description', 'No description')
                                        print(f"         • {test_name}: {success} - {description}")
                                    else:
                                        print(f"         • {test_name}: {result}")
                            else:
                                print(f"         • Raw data: {tests}")
                    else:
                        print(f"     • test_results content: {test_results}")
                else:
                    print(f"     ❌ No 'test_results' key found in scan_data")
                
                # Check other important keys
                important_keys = ['system_info', 'network_interfaces', 'listening_ports', 
                                'active_connections', 'arp_table', 'routing_table']
                
                print(f"\n  📝 OTHER DATA KEYS:")
                for key in important_keys:
                    if key in scan_data:
                        data = scan_data[key]
                        if isinstance(data, list):
                            print(f"     • {key}: {len(data)} items")
                        elif isinstance(data, dict):
                            print(f"     • {key}: {len(data)} fields")
                        else:
                            print(f"     • {key}: {type(data)}")
                    else:
                        print(f"     ❌ {key}: Not found")
                
                # Check scan metadata
                metadata_keys = ['timestamp', 'scan_duration', 'scan_status', 'errors']
                print(f"\n  ⚙️  SCAN METADATA:")
                for key in metadata_keys:
                    if key in scan_data:
                        value = scan_data[key]
                        print(f"     • {key}: {value}")
                
            except json.JSONDecodeError as e:
                print(f"  ❌ Failed to parse scan_data JSON: {e}")
            except Exception as e:
                print(f"  ❌ Error analyzing scan data: {e}")
            
            # Show recent scan history
            cursor = conn.execute("""
                SELECT scan_timestamp, scan_type, processed FROM agent_scan_results 
                WHERE agent_id = ? 
                ORDER BY scan_timestamp DESC 
                LIMIT 5
            """, (agent_id,))
            
            recent_scans = cursor.fetchall()
            print(f"\n  📈 RECENT SCAN HISTORY:")
            for scan in recent_scans:
                print(f"     • {scan['scan_timestamp']} - {scan['scan_type']} (processed: {scan['processed']})")
        
        conn.close()
        
        print(f"\n" + "="*60)
        print("SUMMARY")
        print(f"="*60)
        print(f"• Total agents: {agent_count}")
        print(f"• Total scans: {scan_count}")
        print("• Database analysis complete!")
        
    except Exception as e:
        print(f"Error accessing database: {e}")
        return False
    
    return True

if __name__ == "__main__":
    check_database_scan_data()
