#!/bin/bash

#
# NetworkMap Agent Deployment Script
# This script automates the deployment of the NetworkMap monitoring agent
# on Ubuntu/Debian systems with proper systemd service configuration.
#

set -e  # Exit on any error

# Script configuration
SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/tmp/networkmap_agent_deploy.log"

# Default configuration
DEFAULT_SERVER_URL="http://localhost:5150"
DEFAULT_AGENT_USER="networkmap-agent"
DEFAULT_INSTALL_DIR="/opt/networkmap-agent"
DEFAULT_LOG_DIR="/var/log/networkmap-agent"
DEFAULT_CONFIG_DIR="/etc/networkmap-agent"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SERVER_URL=""
AGENT_USER=""
INSTALL_DIR=""
LOG_DIR=""
CONFIG_DIR=""
FORCE_INSTALL=false
UNINSTALL=false
START_SERVICE=true

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
}

# Print colored output
print_status() {
    local color="$1"
    shift
    local message="$*"
    echo -e "${color}${message}${NC}"
}

print_success() {
    print_status "$GREEN" "✓ $*"
}

print_error() {
    print_status "$RED" "✗ $*"
}

print_warning() {
    print_status "$YELLOW" "⚠ $*"
}

print_info() {
    print_status "$BLUE" "ℹ $*"
}

# Help function
show_help() {
    cat << EOF
NetworkMap Agent Deployment Script

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    -s, --server-url URL    Server URL (default: $DEFAULT_SERVER_URL)
    -u, --user USER         System user for agent (default: $DEFAULT_AGENT_USER)
    -i, --install-dir DIR   Installation directory (default: $DEFAULT_INSTALL_DIR)
    -l, --log-dir DIR       Log directory (default: $DEFAULT_LOG_DIR)
    -c, --config-dir DIR    Configuration directory (default: $DEFAULT_CONFIG_DIR)
    -f, --force             Force installation (overwrite existing)
    --uninstall             Uninstall the agent and remove all files
    --no-start              Don't start the service after installation
    -h, --help              Show this help message

EXAMPLES:
    # Basic installation with default settings
    sudo $SCRIPT_NAME

    # Install with custom server URL
    sudo $SCRIPT_NAME --server-url http://192.168.1.100:5150

    # Install with custom user and directories
    sudo $SCRIPT_NAME --user myagent --install-dir /usr/local/networkmap

    # Force reinstallation
    sudo $SCRIPT_NAME --force

    # Uninstall the agent
    sudo $SCRIPT_NAME --uninstall

REQUIREMENTS:
    - Ubuntu/Debian Linux system
    - Root privileges (run with sudo)
    - Internet connection for package installation
    - Python 3.6 or later

NOTES:
    - The script will create a dedicated system user for the agent
    - Passwordless sudo will be configured for the agent user
    - The agent will be installed as a systemd service
    - Network monitoring tools will be installed automatically

EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -s|--server-url)
                SERVER_URL="$2"
                shift 2
                ;;
            -u|--user)
                AGENT_USER="$2"
                shift 2
                ;;
            -i|--install-dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -l|--log-dir)
                LOG_DIR="$2"
                shift 2
                ;;
            -c|--config-dir)
                CONFIG_DIR="$2"
                shift 2
                ;;
            -f|--force)
                FORCE_INSTALL=true
                shift
                ;;
            --uninstall)
                UNINSTALL=true
                shift
                ;;
            --no-start)
                START_SERVICE=false
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # Set defaults if not provided
    SERVER_URL="${SERVER_URL:-$DEFAULT_SERVER_URL}"
    AGENT_USER="${AGENT_USER:-$DEFAULT_AGENT_USER}"
    INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_INSTALL_DIR}"
    LOG_DIR="${LOG_DIR:-$DEFAULT_LOG_DIR}"
    CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
}

# Check prerequisites
check_prerequisites() {
    print_info "Checking prerequisites..."

    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi

    # Check OS
    if ! grep -q "Ubuntu\|Debian" /etc/os-release; then
        print_error "This script is designed for Ubuntu/Debian systems"
        exit 1
    fi

    # Check Python 3
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is required but not installed"
        exit 1
    fi

    # Check systemctl
    if ! command -v systemctl &> /dev/null; then
        print_error "systemctl is required (systemd-based system)"
        exit 1
    fi

    print_success "Prerequisites check passed"
}

# Uninstall function
uninstall_agent() {
    print_info "Uninstalling NetworkMap Agent..."

    # Stop and disable service
    if systemctl is-active --quiet networkmap-agent; then
        print_info "Stopping NetworkMap Agent service..."
        systemctl stop networkmap-agent
    fi

    if systemctl is-enabled --quiet networkmap-agent; then
        print_info "Disabling NetworkMap Agent service..."
        systemctl disable networkmap-agent
    fi

    # Remove service file
    if [[ -f /etc/systemd/system/networkmap-agent.service ]]; then
        print_info "Removing systemd service file..."
        rm -f /etc/systemd/system/networkmap-agent.service
        systemctl daemon-reload
    fi

    # Remove directories
    for dir in "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"; do
        if [[ -d "$dir" ]]; then
            print_info "Removing directory: $dir"
            rm -rf "$dir"
        fi
    done

    # Remove user
    if id "$AGENT_USER" &>/dev/null; then
        print_info "Removing user: $AGENT_USER"
        userdel "$AGENT_USER" 2>/dev/null || true
        # Remove user's home directory if it exists
        if [[ -d "/home/$AGENT_USER" ]]; then
            rm -rf "/home/$AGENT_USER"
        fi
    fi

    # Remove sudo configuration
    if [[ -f "/etc/sudoers.d/networkmap-agent" ]]; then
        print_info "Removing sudo configuration..."
        rm -f "/etc/sudoers.d/networkmap-agent"
    fi

    print_success "NetworkMap Agent has been uninstalled"
}

# Check if already installed
check_existing_installation() {
    if [[ -d "$INSTALL_DIR" ]] || systemctl is-active --quiet networkmap-agent 2>/dev/null; then
        if [[ "$FORCE_INSTALL" == "true" ]]; then
            print_warning "Existing installation found, forcing reinstall..."
            # Stop service if running
            if systemctl is-active --quiet networkmap-agent; then
                systemctl stop networkmap-agent
            fi
        else
            print_error "NetworkMap Agent appears to be already installed."
            print_info "Use --force to reinstall or --uninstall to remove"
            exit 1
        fi
    fi
}

# Create system user
create_user() {
    print_info "Creating system user: $AGENT_USER"

    if id "$AGENT_USER" &>/dev/null; then
        print_info "User $AGENT_USER already exists"
    else
        useradd --system --shell /bin/bash --home-dir "$INSTALL_DIR" --create-home "$AGENT_USER"
        print_success "Created user: $AGENT_USER"
    fi

    # Configure passwordless sudo
    print_info "Configuring passwordless sudo for $AGENT_USER"
    cat > "/etc/sudoers.d/networkmap-agent" << EOF
# NetworkMap Agent sudo configuration
# Allow the agent to run network monitoring commands
$AGENT_USER ALL=(ALL) NOPASSWD: ALL
EOF

    chmod 440 "/etc/sudoers.d/networkmap-agent"
    print_success "Configured passwordless sudo"
}

# Install required packages
install_packages() {
    print_info "Installing required packages..."

    export DEBIAN_FRONTEND=noninteractive

    # Update package lists
    print_info "Updating package lists..."
    apt-get update

    # Essential packages
    local packages=(
        "python3"
        "python3-pip"
        "python3-requests"
        "curl"
        "wget"
        "net-tools"
        "iproute2"
    )

    # Network monitoring tools
    local network_tools=(
        "nmap"
        "traceroute"
        "mtr-tiny"
        "fping"
        "arp-scan"
        "tcpdump"
        "iftop"
        "nethogs"
        "iotop"
        "htop"
        "bmon"
        "vnstat"
        "iperf3"
        "snmp"
        "ngrep"
    )

    # Install essential packages
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            print_info "Installing $package..."
            apt-get install -y "$package"
        fi
    done

    # Install network tools (non-critical)
    for tool in "${network_tools[@]}"; do
        if ! dpkg -l | grep -q "^ii  $tool "; then
            print_info "Installing $tool..."
            if ! apt-get install -y "$tool" 2>/dev/null; then
                print_warning "Failed to install $tool (non-critical)"
            fi
        fi
    done

    print_success "Package installation completed"
}

# Create directories
create_directories() {
    print_info "Creating directories..."

    for dir in "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            print_info "Created directory: $dir"
        fi
    done

    # Set ownership
    chown -R "$AGENT_USER:$AGENT_USER" "$INSTALL_DIR" "$LOG_DIR" "$CONFIG_DIR"
    
    # Set permissions
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"

    print_success "Directories created and configured"
}

# Download agent script
download_agent() {
    print_info "Setting up NetworkMap Agent..."

    local agent_script="$INSTALL_DIR/networkmap_agent.py"

    # If the script is in the same directory as this deployment script, copy it
    if [[ -f "$SCRIPT_DIR/networkmap_agent.py" ]]; then
        print_info "Copying agent script from local directory..."
        cp "$SCRIPT_DIR/networkmap_agent.py" "$agent_script"
    elif [[ -f "$SCRIPT_DIR/static/network_agent.py" ]]; then
        print_info "Copying agent script from static directory..."
        cp "$SCRIPT_DIR/static/network_agent.py" "$agent_script"
    else
        # Try to download from server
        print_info "Downloading agent script from server..."
        local download_url="${SERVER_URL}/static/network_agent.py"
        
        if curl -f -o "$agent_script" "$download_url" 2>/dev/null; then
            print_success "Downloaded agent script from server"
        else
            print_error "Failed to download agent script from $download_url"
            print_info "Please ensure the NetworkMap server is running and accessible"
            exit 1
        fi
    fi

    # Make executable
    chmod +x "$agent_script"
    chown "$AGENT_USER:$AGENT_USER" "$agent_script"

    print_success "Agent script installed"
}

# Create configuration file
create_config() {
    print_info "Creating agent configuration..."

    local config_file="$CONFIG_DIR/config.json"

    cat > "$config_file" << EOF
{
    "server_url": "$SERVER_URL",
    "scan_interval": 300,
    "heartbeat_interval": 60,
    "log_collection_enabled": true,
    "log_paths": [
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/kern.log"
    ],
    "scan_enabled": true,
    "agent_user": "$AGENT_USER",
    "log_level": "INFO"
}
EOF

    chown "$AGENT_USER:$AGENT_USER" "$config_file"
    chmod 600 "$config_file"

    print_success "Configuration file created"
}

# Create systemd service
create_service() {
    print_info "Creating systemd service..."

    local service_file="/etc/systemd/system/networkmap-agent.service"
    local agent_script="$INSTALL_DIR/networkmap_agent.py"

    cat > "$service_file" << EOF
[Unit]
Description=NetworkMap Monitoring Agent
Documentation=https://github.com/yourusername/networkmap
After=network.target
Wants=network.target

[Service]
Type=simple
User=$AGENT_USER
Group=$AGENT_USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $agent_script --config $CONFIG_DIR/config.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=networkmap-agent

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$LOG_DIR $CONFIG_DIR
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN

# Environment
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable networkmap-agent

    print_success "Systemd service created and enabled"
}

# Start service
start_service() {
    if [[ "$START_SERVICE" == "true" ]]; then
        print_info "Starting NetworkMap Agent service..."
        
        systemctl start networkmap-agent
        sleep 2

        if systemctl is-active --quiet networkmap-agent; then
            print_success "NetworkMap Agent service started successfully"
        else
            print_error "Failed to start NetworkMap Agent service"
            print_info "Check logs with: journalctl -u networkmap-agent -f"
            exit 1
        fi
    else
        print_info "Service installation completed (not started)"
        print_info "Start manually with: sudo systemctl start networkmap-agent"
    fi
}

# Show installation summary
show_summary() {
    print_success "NetworkMap Agent installation completed!"
    echo
    print_info "Installation Details:"
    echo "  Server URL:      $SERVER_URL"
    echo "  Agent User:      $AGENT_USER"
    echo "  Install Dir:     $INSTALL_DIR"
    echo "  Config Dir:      $CONFIG_DIR"
    echo "  Log Dir:         $LOG_DIR"
    echo
    print_info "Service Management:"
    echo "  Status:          sudo systemctl status networkmap-agent"
    echo "  Start:           sudo systemctl start networkmap-agent"
    echo "  Stop:            sudo systemctl stop networkmap-agent"
    echo "  Restart:         sudo systemctl restart networkmap-agent"
    echo "  Logs:            sudo journalctl -u networkmap-agent -f"
    echo
    print_info "Configuration:"
    echo "  Config File:     $CONFIG_DIR/config.json"
    echo "  Edit config and restart service to apply changes"
    echo
    print_info "Uninstall:"
    echo "  Remove:          sudo $SCRIPT_NAME --uninstall"
    echo
}

# Test connectivity
test_connectivity() {
    print_info "Testing connectivity to server..."
    
    local test_url="${SERVER_URL}/api/agents"
    
    if curl -f -s "$test_url" > /dev/null 2>&1; then
        print_success "Server connectivity test passed"
    else
        print_warning "Could not connect to server at $SERVER_URL"
        print_info "The agent will retry connections automatically when the server is available"
    fi
}

# Main installation function
main_install() {
    print_info "Starting NetworkMap Agent installation..."
    print_info "Server URL: $SERVER_URL"
    print_info "Agent User: $AGENT_USER"
    echo

    check_existing_installation
    create_user
    install_packages
    create_directories
    download_agent
    create_config
    create_service
    start_service
    test_connectivity
    show_summary
}

# Main function
main() {
    # Create log file
    touch "$LOG_FILE"
    chmod 644 "$LOG_FILE"

    log "INFO" "NetworkMap Agent Deployment Script started"
    log "INFO" "Command: $0 $*"

    parse_args "$@"
    check_prerequisites

    if [[ "$UNINSTALL" == "true" ]]; then
        uninstall_agent
    else
        main_install
    fi

    log "INFO" "NetworkMap Agent Deployment Script completed"
}

# Run main function with all arguments
main "$@"
