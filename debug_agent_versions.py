#!/usr/bin/env python3
"""
Debug script to check agent version data in the database
Run this on the remote server to diagnose version tracking issues
"""

import sqlite3
import json
from datetime import datetime

def check_database_schema():
    """Check the current database schema for agent tables"""
    try:
        conn = sqlite3.connect('network_scanner.db')
        cursor = conn.cursor()
        
        print("=== DATABASE SCHEMA ANALYSIS ===")
        
        # Check if agents table exists and its schema
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='agents'")
        result = cursor.fetchone()
        if result:
            print("Agents table schema:")
            print(result[0])
        else:
            print("❌ Agents table does not exist!")
            return False
        
        # Check columns in agents table
        cursor.execute("PRAGMA table_info(agents)")
        columns = cursor.fetchall()
        print("\nColumns in agents table:")
        for col in columns:
            print(f"  - {col[1]} ({col[2]})")
        
        # Check if agent_version column exists
        column_names = [col[1] for col in columns]
        if 'agent_version' not in column_names:
            print("❌ agent_version column is missing!")
            return False
        else:
            print("✅ agent_version column exists")
        
        return True
        
    except Exception as e:
        print(f"❌ Database error: {e}")
        return False
    finally:
        if conn:
            conn.close()

def check_agent_data():
    """Check existing agent data and versions"""
    try:
        conn = sqlite3.connect('network_scanner.db')
        cursor = conn.cursor()
        
        print("\n=== AGENT DATA ANALYSIS ===")
        
        # Count total agents
        cursor.execute("SELECT COUNT(*) FROM agents")
        total_agents = cursor.fetchone()[0]
        print(f"Total agents in database: {total_agents}")
        
        if total_agents == 0:
            print("❌ No agents found in database!")
            return
        
        # Check agents with version information
        cursor.execute("SELECT COUNT(*) FROM agents WHERE agent_version IS NOT NULL AND agent_version != ''")
        agents_with_version = cursor.fetchone()[0]
        print(f"Agents with version info: {agents_with_version}")
        
        # Get all agent data
        cursor.execute("""
            SELECT agent_id, hostname, ip_address, agent_version, last_heartbeat, created_at 
            FROM agents 
            ORDER BY created_at DESC
        """)
        agents = cursor.fetchall()
        
        print("\n=== AGENT DETAILS ===")
        for agent in agents:
            agent_id, hostname, ip_address, version, last_heartbeat, created_at = agent
            print(f"Agent ID: {agent_id}")
            print(f"  Hostname: {hostname}")
            print(f"  IP: {ip_address}")
            print(f"  Version: {version or 'NULL/Empty'}")
            print(f"  Last Heartbeat: {last_heartbeat or 'Never'}")
            print(f"  Created: {created_at}")
            print("  ---")
        
        # Check version distribution
        cursor.execute("""
            SELECT agent_version, COUNT(*) as count 
            FROM agents 
            WHERE agent_version IS NOT NULL AND agent_version != ''
            GROUP BY agent_version 
            ORDER BY count DESC
        """)
        version_stats = cursor.fetchall()
        
        if version_stats:
            print("\n=== VERSION DISTRIBUTION ===")
            for version, count in version_stats:
                print(f"Version {version}: {count} agents")
        else:
            print("❌ No version data found!")
        
    except Exception as e:
        print(f"❌ Error checking agent data: {e}")
    finally:
        if conn:
            conn.close()

def update_agent_versions():
    """Update agent versions to current version if they're missing"""
    try:
        conn = sqlite3.connect('network_scanner.db')
        cursor = conn.cursor()
        
        print("\n=== UPDATING AGENT VERSIONS ===")
        
        # Check how many agents need version updates
        cursor.execute("SELECT COUNT(*) FROM agents WHERE agent_version IS NULL OR agent_version = ''")
        agents_needing_update = cursor.fetchone()[0]
        
        if agents_needing_update == 0:
            print("✅ All agents already have version information")
            return
        
        print(f"Found {agents_needing_update} agents without version information")
        
        # Update agents without version to current version (1.7.0)
        current_version = "1.7.0"
        cursor.execute("""
            UPDATE agents 
            SET agent_version = ?, updated_at = CURRENT_TIMESTAMP 
            WHERE agent_version IS NULL OR agent_version = ''
        """, (current_version,))
        
        updated_count = cursor.rowcount
        conn.commit()
        
        print(f"✅ Updated {updated_count} agents to version {current_version}")
        
    except Exception as e:
        print(f"❌ Error updating agent versions: {e}")
    finally:
        if conn:
            conn.close()

def test_api_endpoint():
    """Test the /api/agent/versions endpoint logic"""
    try:
        conn = sqlite3.connect('network_scanner.db')
        cursor = conn.cursor()
        
        print("\n=== TESTING API ENDPOINT LOGIC ===")
        
        # Simulate the API endpoint query
        cursor.execute("""
            SELECT agent_id, hostname, ip_address, agent_version, last_heartbeat, 
                   platform, created_at, updated_at
            FROM agents 
            ORDER BY updated_at DESC
        """)
        
        agents = cursor.fetchall()
        
        if not agents:
            print("❌ No agents found for API endpoint")
            return
        
        print(f"API would return {len(agents)} agents")
        
        # Calculate version statistics
        versions = []
        for agent in agents:
            version = agent[3]  # agent_version
            if version and version.strip():
                versions.append(version.strip())
        
        if not versions:
            print("❌ No valid versions found")
            return
        
        # Find most common version (current deployed)
        from collections import Counter
        version_counts = Counter(versions)
        most_common_version = version_counts.most_common(1)[0][0]
        
        # Find latest version (semantic version sort)
        def version_key(v):
            try:
                return tuple(map(int, v.split('.')))
            except:
                return (0, 0, 0)
        
        latest_version = max(versions, key=version_key)
        
        print(f"✅ Current Deployed Version: {most_common_version}")
        print(f"✅ Latest Available Version: {latest_version}")
        print(f"Version distribution: {dict(version_counts)}")
        
    except Exception as e:
        print(f"❌ Error testing API logic: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    print("Network Discovery Agent Version Diagnostic Tool")
    print("=" * 50)
    
    # Check database schema
    if not check_database_schema():
        print("❌ Database schema issues detected. Cannot continue.")
        exit(1)
    
    # Check agent data
    check_agent_data()
    
    # Update missing versions
    update_agent_versions()
    
    # Test API endpoint logic
    test_api_endpoint()
    
    print("\n" + "=" * 50)
    print("✅ Diagnostic complete!")
    print("\nNext steps:")
    print("1. Restart the Flask application")
    print("2. Check the /api/agent/versions endpoint")
    print("3. Refresh the Agent Management page")
