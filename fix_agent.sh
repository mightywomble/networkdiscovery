#!/bin/bash

# NetworkMap Agent Configuration Fix Script
# Run this on each remote host where the agent is installed but showing as offline

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
CONFIG_FILE="/etc/networkmap/agent.conf"
SERVICE_NAME="networkmap-agent"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

print_info() {
    print_status "$BLUE" "[INFO] $1"
}

print_success() {
    print_status "$GREEN" "[SUCCESS] $1"
}

print_warning() {
    print_status "$YELLOW" "[WARNING] $1"
}

print_error() {
    print_status "$RED" "[ERROR] $1"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root or with sudo"
        exit 1
    fi
}

# Function to get server URL from user
get_server_url() {
    if [[ -z "$1" ]]; then
        echo ""
        print_info "Please enter the correct NetworkMap server URL"
        print_info "Example: http://192.168.1.100:5150"
        read -p "Server URL: " SERVER_URL
        
        # Remove trailing slash
        SERVER_URL=${SERVER_URL%/}
        
        # Validate URL format
        if [[ ! $SERVER_URL =~ ^https?://[^/]+$ ]]; then
            print_error "Invalid URL format. Please use format: http://IP:PORT"
            exit 1
        fi
    else
        SERVER_URL=${1%/}
    fi
    
    print_info "Using server URL: $SERVER_URL"
}

# Function to backup config
backup_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
        print_success "Created backup of existing config"
    fi
}

# Function to check current configuration
check_current_config() {
    print_info "Checking current agent configuration..."
    
    if [[ ! -f "$CONFIG_FILE" ]]; then
        print_error "Configuration file not found: $CONFIG_FILE"
        print_error "Agent may not be properly installed"
        exit 1
    fi
    
    # Show current config (redact sensitive info)
    print_info "Current configuration:"
    cat "$CONFIG_FILE" | python3 -c "
import json
import sys
try:
    config = json.load(sys.stdin)
    print(f'  Server URL: {config.get(\"server_url\", \"NOT SET\")}')
    print(f'  Username: {config.get(\"username\", \"NOT SET\")}')
    print(f'  Agent ID: {config.get(\"agent_id\", \"NOT SET\")}')
    print(f'  Scan Interval: {config.get(\"scan_interval\", \"NOT SET\")}')
    print(f'  Heartbeat Interval: {config.get(\"heartbeat_interval\", \"NOT SET\")}')
except:
    print('  ERROR: Invalid JSON in config file')
"
}

# Function to update server URL in config
update_server_url() {
    print_info "Updating server URL in configuration..."
    
    python3 -c "
import json
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    old_url = config.get('server_url', 'NOT SET')
    config['server_url'] = '$SERVER_URL'
    
    with open('$CONFIG_FILE', 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f'Updated server URL from: {old_url}')
    print(f'Updated server URL to: $SERVER_URL')
except Exception as e:
    print(f'Error updating config: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        print_success "Configuration updated successfully"
    else
        print_error "Failed to update configuration"
        exit 1
    fi
}

# Function to test server connectivity
test_server_connectivity() {
    print_info "Testing connectivity to server..."
    
    # Extract host and port from URL
    HOST_PORT=$(echo "$SERVER_URL" | sed -E 's|^https?://([^/]+).*|\1|')
    HOST=$(echo "$HOST_PORT" | cut -d: -f1)
    PORT=$(echo "$HOST_PORT" | cut -d: -f2)
    
    # Default port if not specified
    if [[ "$HOST" == "$PORT" ]]; then
        PORT=80
        if [[ "$SERVER_URL" =~ ^https ]]; then
            PORT=443
        fi
    fi
    
    # Test basic connectivity
    if timeout 10 bash -c "</dev/tcp/$HOST/$PORT" 2>/dev/null; then
        print_success "Server is reachable at $HOST:$PORT"
    else
        print_warning "Cannot reach server at $HOST:$PORT"
        print_warning "Agent may have connectivity issues"
    fi
    
    # Test HTTP endpoint if curl is available
    if command -v curl >/dev/null 2>&1; then
        if curl -s --connect-timeout 10 "$SERVER_URL/api/hosts" >/dev/null 2>&1; then
            print_success "Server API is responding"
        else
            print_warning "Server API test failed - this might be normal if authentication is required"
        fi
    fi
}

# Function to restart agent service
restart_agent_service() {
    print_info "Restarting NetworkMap agent service..."
    
    # Stop the service
    systemctl stop "$SERVICE_NAME" 2>/dev/null || print_warning "Service was not running"
    
    # Start the service
    if systemctl start "$SERVICE_NAME"; then
        print_success "Service started successfully"
    else
        print_error "Failed to start service"
        return 1
    fi
    
    # Wait a moment for service to initialize
    sleep 3
    
    # Check service status
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        print_success "Service is running"
        
        # Show recent logs
        print_info "Recent service logs:"
        journalctl -u "$SERVICE_NAME" --no-pager -n 10 --since "1 minute ago" | while read line; do
            echo "  $line"
        done
        
        return 0
    else
        print_error "Service failed to start properly"
        print_error "Check logs with: journalctl -u $SERVICE_NAME -f"
        return 1
    fi
}

# Function to perform registration test
test_registration() {
    print_info "Testing agent registration with server..."
    
    # Get agent info from config
    AGENT_INFO=$(python3 -c "
import json
import socket
import platform
import uuid

# Get system info
hostname = socket.gethostname()
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 80))
    ip_address = s.getsockname()[0]
    s.close()
except:
    ip_address = socket.gethostbyname(hostname)

# Load config to get agent_id and username
try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    agent_id = config.get('agent_id', str(uuid.uuid4()))
    username = config.get('username', 'unknown')
except:
    agent_id = str(uuid.uuid4())
    username = 'unknown'

print(f'{agent_id}|{hostname}|{ip_address}|{username}')
")
    
    IFS='|' read -r AGENT_ID HOSTNAME IP_ADDRESS USERNAME <<< "$AGENT_INFO"
    
    print_info "Agent details:"
    print_info "  Agent ID: $AGENT_ID"
    print_info "  Hostname: $HOSTNAME"
    print_info "  IP Address: $IP_ADDRESS"
    print_info "  Username: $USERNAME"
    
    if command -v curl >/dev/null 2>&1; then
        # Test registration
        RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" \
            -H "Content-Type: application/json" \
            -d "{
                \"agent_id\": \"$AGENT_ID\",
                \"hostname\": \"$HOSTNAME\",
                \"ip_address\": \"$IP_ADDRESS\",
                \"username\": \"$USERNAME\",
                \"agent_version\": \"1.0.0\",
                \"platform\": \"$(uname -a)\"
            }" \
            "$SERVER_URL/api/agent/register" 2>/dev/null)
        
        HTTP_CODE=$(echo "$RESPONSE" | tail -n1 | cut -d: -f2)
        RESPONSE_BODY=$(echo "$RESPONSE" | head -n -1)
        
        if [[ "$HTTP_CODE" == "200" ]]; then
            print_success "Registration test successful!"
            echo "  Response: $RESPONSE_BODY"
        else
            print_warning "Registration test failed with HTTP code: $HTTP_CODE"
            echo "  Response: $RESPONSE_BODY"
        fi
    else
        print_warning "curl not available - skipping registration test"
    fi
}

# Main function
main() {
    echo ""
    print_info "NetworkMap Agent Configuration Fix Script"
    print_info "=========================================="
    echo ""
    
    # Check if running as root
    check_root
    
    # Get server URL
    get_server_url "$1"
    
    # Check current configuration
    check_current_config
    
    # Backup configuration
    backup_config
    
    # Update server URL
    update_server_url
    
    # Test server connectivity
    test_server_connectivity
    
    # Restart service
    if restart_agent_service; then
        # Wait a bit for the agent to start up
        print_info "Waiting for agent to initialize..."
        sleep 5
        
        # Test registration
        test_registration
        
        print_success "Agent configuration fix completed!"
        print_info "The agent should now appear as 'Online' in the web UI within 1-2 minutes"
        print_info "You can monitor logs with: journalctl -u $SERVICE_NAME -f"
    else
        print_error "Failed to restart agent service"
        print_error "Please check the service logs: journalctl -u $SERVICE_NAME -f"
        exit 1
    fi
}

# Show usage if no arguments and not interactive
if [[ $# -eq 0 ]] && [[ ! -t 0 ]]; then
    echo "Usage: $0 [server_url]"
    echo "Example: $0 http://192.168.1.100:5150"
    echo "If no server URL is provided, you will be prompted to enter it"
    exit 1
fi

# Run main function
main "$@"
