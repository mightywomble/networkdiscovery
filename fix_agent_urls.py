#!/usr/bin/env python3
"""
Script to fix agent server URLs on all remote hosts
"""

import json
import subprocess
import sys
from host_manager import HostManager
from database import Database

def update_agent_server_url(host, new_server_url):
    """Update agent server URL on a remote host"""
    print(f"Updating agent config on {host['name']} ({host['ip_address']})")
    
    update_script = f"""
# Check if config file exists
if [ ! -f /etc/networkmap/agent.conf ]; then
    echo "Config file not found: /etc/networkmap/agent.conf"
    exit 1
fi

# Backup original config
sudo cp /etc/networkmap/agent.conf /etc/networkmap/agent.conf.backup

# Update server URL in config
sudo python3 -c "
import json
import sys

try:
    with open('/etc/networkmap/agent.conf', 'r') as f:
        config = json.load(f)
    
    config['server_url'] = '{new_server_url}'
    
    with open('/etc/networkmap/agent.conf', 'w') as f:
        json.dump(config, f, indent=2)
    
    print('✓ Updated server URL to: {new_server_url}')
except Exception as e:
    print(f'✗ Error updating config: {{e}}')
    sys.exit(1)
"

# Restart the agent service
echo "Restarting networkmap-agent service..."
sudo systemctl restart networkmap-agent

# Wait a moment and check status
sleep 3
if sudo systemctl is-active --quiet networkmap-agent; then
    echo "✓ Agent service restarted successfully"
else
    echo "✗ Agent service failed to start properly"
    exit 1
fi

echo "✓ Agent configuration updated and service restarted"
"""
    
    return update_script

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 fix_agent_urls.py <new_server_url>")
        print("Example: python3 fix_agent_urls.py http://192.168.1.100:5150")
        sys.exit(1)
    
    new_server_url = sys.argv[1].rstrip('/')
    
    print(f"Will update all agent configs to use server URL: {new_server_url}")
    confirmation = input("Continue? (y/N): ")
    if confirmation.lower() != 'y':
        print("Cancelled")
        sys.exit(0)
    
    # Initialize database and host manager
    db = Database()
    host_manager = HostManager(db)
    
    # Get all hosts
    hosts = host_manager.get_all_hosts()
    online_hosts = [h for h in hosts if h.get('status') == 'online']
    
    if not online_hosts:
        print("No online hosts found")
        sys.exit(1)
    
    print(f"Found {len(online_hosts)} online hosts")
    
    success_count = 0
    error_count = 0
    
    for host in online_hosts:
        try:
            print(f"\n--- Updating {host['name']} ---")
            
            # Create the update script
            update_script = update_agent_server_url(host, new_server_url)
            
            # Execute via SSH
            result, error = host_manager.execute_command(host, update_script, timeout=60)
            
            if result and result['success']:
                print(f"✓ Successfully updated {host['name']}")
                print(f"Output: {result['stdout']}")
                success_count += 1
            else:
                print(f"✗ Failed to update {host['name']}")
                if result:
                    print(f"Error: {result.get('stderr', 'Unknown error')}")
                else:
                    print(f"Error: {error}")
                error_count += 1
                
        except Exception as e:
            print(f"✗ Exception updating {host['name']}: {e}")
            error_count += 1
    
    print(f"\n--- Summary ---")
    print(f"Successfully updated: {success_count}")
    print(f"Failed to update: {error_count}")
    print(f"Total hosts: {len(online_hosts)}")
    
    if success_count > 0:
        print(f"\nAgents should start registering with the server shortly.")
        print(f"Check the agents page in the web UI to verify.")

if __name__ == "__main__":
    main()
