#!/bin/bash

# Network Map Agent Diagnostic Script
# Run this directly on the Linux host to check agent installation

echo "Network Map Agent Diagnostic Report"
echo "==================================="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo "User: $(whoami)"
echo

# 1. Check for agent files in common locations
echo "1. Checking for agent files..."
echo "------------------------------"

POSSIBLE_LOCATIONS=(
    "/opt/networkmap"
    "/opt/networkmap-agent" 
    "/usr/local/networkmap"
    "/usr/local/bin"
    "/home/$(whoami)/networkmap"
    "/tmp/networkmap"
)

for location in "${POSSIBLE_LOCATIONS[@]}"; do
    if [ -d "$location" ]; then
        echo "✅ Directory exists: $location"
        echo "   Contents:"
        ls -la "$location" | sed 's/^/   /'
        echo
        
        # Check for Python files
        find "$location" -name "*.py" -type f 2>/dev/null | head -10 | while read -r file; do
            echo "   Python file: $file"
            # Check if it contains NetworkMapAgent
            if grep -q "class NetworkMapAgent" "$file" 2>/dev/null; then
                echo "   ⭐ This appears to be the main agent file!"
                echo "   Version info:"
                grep -A 2 "__version__\|VERSION" "$file" 2>/dev/null | sed 's/^/      /'
            fi
        done
        echo
    else
        echo "❌ Directory not found: $location"
    fi
done

echo

# 2. Check systemd services
echo "2. Checking systemd services..."
echo "------------------------------"
SERVICES=(
    "networkmap-agent"
    "networkmap"
    "network-map-agent"
    "network-agent"
)

for service in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${service}.service"; then
        echo "✅ Service found: $service"
        echo "   Status: $(systemctl is-active $service 2>/dev/null || echo 'unknown')"
        echo "   Enabled: $(systemctl is-enabled $service 2>/dev/null || echo 'unknown')"
        
        # Show service file content
        echo "   Service file content:"
        systemctl cat "$service" 2>/dev/null | sed 's/^/   /' || echo "   Could not read service file"
        echo
    else
        echo "❌ Service not found: $service"
    fi
done

echo

# 3. Check running processes
echo "3. Checking running processes..."
echo "------------------------------"
echo "NetworkMap related processes:"
ps aux | grep -i networkmap | grep -v grep | sed 's/^/   /' || echo "   No NetworkMap processes found"

echo
echo "Python processes (might be our agent):"
ps aux | grep python | grep -v grep | sed 's/^/   /' || echo "   No Python processes found"

echo

# 4. Check logs
echo "4. Checking logs..."
echo "------------------"
LOG_LOCATIONS=(
    "/var/log/networkmap-agent.log"
    "/var/log/networkmap.log"
    "/tmp/networkmap-agent.log"
    "/var/log/syslog"
)

for log in "${LOG_LOCATIONS[@]}"; do
    if [ -f "$log" ]; then
        echo "✅ Log file exists: $log"
        echo "   Recent entries (last 5 lines):"
        tail -5 "$log" 2>/dev/null | sed 's/^/   /' || echo "   Could not read log"
        echo
    else
        echo "❌ Log file not found: $log"
    fi
done

# Check journalctl for NetworkMap services
echo "Checking journalctl for NetworkMap entries:"
journalctl --since "1 hour ago" | grep -i networkmap | tail -10 | sed 's/^/   /' || echo "   No recent journalctl entries found"

echo

# 5. Check configuration files
echo "5. Checking configuration files..."
echo "--------------------------------"
CONFIG_LOCATIONS=(
    "/etc/networkmap/agent.conf"
    "/etc/networkmap-agent/agent.conf"
    "/opt/networkmap/agent.conf"
    "/opt/networkmap-agent/agent.conf"
)

for config in "${CONFIG_LOCATIONS[@]}"; do
    if [ -f "$config" ]; then
        echo "✅ Config file exists: $config"
        echo "   Content:"
        cat "$config" 2>/dev/null | sed 's/^/   /' || echo "   Could not read config"
        echo
    else
        echo "❌ Config file not found: $config"
    fi
done

echo

# 6. Check Python environment
echo "6. Checking Python environment..."
echo "--------------------------------"
echo "Python version:"
python3 --version | sed 's/^/   /'

echo
echo "Python path:"
python3 -c "import sys; print('\n'.join(sys.path))" | sed 's/^/   /'

echo
echo "Installed packages (networkmap related):"
pip3 list | grep -i network | sed 's/^/   /' || echo "   No network-related packages found"

echo

# 7. Check if we can import the agent from different locations
echo "7. Testing Python imports..."
echo "---------------------------"

# Test different import methods
test_import() {
    local path="$1"
    local module="$2"
    echo "Testing import from $path with module $module:"
    
    python3 -c "
import sys
sys.path.insert(0, '$path')
try:
    import $module
    print('   ✅ Import successful')
    if hasattr($module, 'NetworkMapAgent'):
        print('   ✅ NetworkMapAgent class found')
        agent = $module.NetworkMapAgent()
        if hasattr(agent, '__version__') or hasattr($module, '__version__'):
            version = getattr(agent, '__version__', getattr($module, '__version__', 'Unknown'))
            print(f'   ℹ Version: {version}')
        else:
            print('   ⚠ No version info found')
    else:
        print('   ❌ NetworkMapAgent class not found')
except Exception as e:
    print(f'   ❌ Import failed: {e}')
"
    echo
}

# Try different combinations
for location in "${POSSIBLE_LOCATIONS[@]}"; do
    if [ -d "$location" ]; then
        # Try common module names
        for module in "networkmap_agent" "network_agent" "agent" "main"; do
            if [ -f "$location/${module}.py" ]; then
                test_import "$location" "$module"
            fi
        done
    fi
done

echo

# 8. Summary and recommendations
echo "8. Summary and Recommendations"
echo "============================="

echo "Based on the diagnostic above, here are the recommendations:"
echo

# Check if we found any agent files
agent_found=false
for location in "${POSSIBLE_LOCATIONS[@]}"; do
    if [ -d "$location" ] && find "$location" -name "*.py" -type f 2>/dev/null | grep -q "agent\|networkmap"; then
        agent_found=true
        break
    fi
done

if [ "$agent_found" = true ]; then
    echo "✅ Agent files found in at least one location"
    echo "   - Try copying the correct agent file to /opt/networkmap/networkmap_agent.py"
    echo "   - Ensure the file has the correct permissions (chmod 755)"
    echo "   - Verify the Python path includes the agent directory"
else
    echo "❌ No agent files found"
    echo "   - The agent may not be installed"
    echo "   - Try redeploying using the deployment script"
    echo "   - Check if the agent was installed in a non-standard location"
fi

echo
echo "Next steps:"
echo "1. If agent files exist, copy them to the standard location:"
echo "   sudo mkdir -p /opt/networkmap"
echo "   sudo cp /path/to/networkmap_agent.py /opt/networkmap/"
echo "   sudo chmod 755 /opt/networkmap/networkmap_agent.py"
echo
echo "2. Test the import again:"
echo "   python3 -c 'import sys; sys.path.insert(0, \"/opt/networkmap\"); from networkmap_agent import NetworkMapAgent; print(\"Success!\")'"
echo
echo "3. If still failing, check the agent file for syntax errors:"
echo "   python3 -m py_compile /opt/networkmap/networkmap_agent.py"
echo

echo "Diagnostic complete!"
