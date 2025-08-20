#!/bin/bash
# Commands to run on the remote server (100.83.62.51)
# SSH to the server and run these commands in /home/david/live/networkmap

echo "=== Network Discovery Agent Version Fix ==="
echo "Run these commands on the remote server:"
echo ""

echo "1. Navigate to the application directory:"
echo "cd /home/david/live/networkmap"
echo ""

echo "2. Backup the current database:"
echo "cp network_scanner.db network_scanner.db.backup.$(date +%Y%m%d_%H%M%S)"
echo ""

echo "3. Copy the migration and diagnostic scripts to the server:"
echo "# Upload migrate_agent_versions.py and debug_agent_versions.py to the server"
echo ""

echo "4. Run the database migration (if needed):"
echo "python3 migrate_agent_versions.py"
echo ""

echo "5. Run the diagnostic script to check and fix version data:"
echo "python3 debug_agent_versions.py"
echo ""

echo "6. Check the current application status:"
echo "ps aux | grep python | grep app.py"
echo ""

echo "7. If the app is running, restart it:"
echo "# Stop the current process"
echo "pkill -f 'python.*app.py'"
echo "# Wait a moment"
echo "sleep 2"
echo "# Start the application (adjust path as needed)"
echo "nohup python3 app.py > app.log 2>&1 &"
echo ""

echo "8. Test the API endpoint:"
echo "curl -s http://localhost:5150/api/agent/versions | python3 -m json.tool"
echo ""

echo "9. Check application logs:"
echo "tail -f app.log"
echo ""

echo "=== Alternative: Manual Database Update ==="
echo "If the scripts don't work, you can manually update the database:"
echo ""
echo "sqlite3 network_scanner.db"
echo "-- Check current schema"
echo ".schema agents"
echo ""
echo "-- Add agent_version column if missing"
echo "ALTER TABLE agents ADD COLUMN agent_version TEXT;"
echo ""
echo "-- Update all agents to current version"
echo "UPDATE agents SET agent_version = '1.7.0' WHERE agent_version IS NULL OR agent_version = '';"
echo ""
echo "-- Check results"
echo "SELECT agent_id, hostname, ip_address, agent_version FROM agents;"
echo ""
echo ".quit"
