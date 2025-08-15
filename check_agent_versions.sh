#!/bin/bash

# Network Map Agent Version Checker
# This script verifies that hosts are running Network Map Agent version 1.5.2
# with the enhanced test features

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_success() {
    echo -e "${GREEN}✅ $*${NC}"
}

print_error() {
    echo -e "${RED}❌ $*${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $*${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $*${NC}"
}

# Function to check agent version on a single host
check_host_version() {
    local host="$1"
    local user="${2:-$(whoami)}"
    
    echo
    print_info "Checking Network Map Agent version on $host..."
    
    # Test SSH connectivity first
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$user@$host" "echo 'SSH connection successful'" 2>/dev/null; then
        print_error "Cannot connect to $host via SSH"
        return 1
    fi
    
    # Check if agent file exists
    if ! ssh "$user@$host" "test -f /opt/networkmap/networkmap_agent.py" 2>/dev/null; then
        print_error "Agent file not found on $host at /opt/networkmap/networkmap_agent.py"
        return 1
    fi
    
    # Check version in the agent file
    local version_output
    version_output=$(ssh "$user@$host" "grep -A 2 '__version__' /opt/networkmap/networkmap_agent.py" 2>/dev/null || echo "")
    
    if [[ "$version_output" =~ "1.5.2" ]]; then
        print_success "Agent version 1.5.2 found in source code on $host"
    else
        print_error "Version 1.5.2 not found in agent source on $host"
        echo "Version output: $version_output"
        return 1
    fi
    
    # Check if enhanced test functions exist
    local enhanced_functions_check
    enhanced_functions_check=$(ssh "$user@$host" "python3 -c \"
import sys
sys.path.insert(0, '/opt/networkmap')
try:
    from networkmap_agent import NetworkMapAgent
    agent = NetworkMapAgent()
    has_system_monitoring = hasattr(agent, '_run_system_monitoring_tests')
    has_connectivity = hasattr(agent, '_run_connectivity_tests')
    has_performance = hasattr(agent, '_run_performance_tests')
    has_security = hasattr(agent, '_run_security_tests')
    has_discovery = hasattr(agent, '_run_discovery_tests')
    
    if all([has_system_monitoring, has_connectivity, has_performance, has_security, has_discovery]):
        print('ENHANCED_FUNCTIONS_FOUND')
    else:
        print('ENHANCED_FUNCTIONS_MISSING')
        print(f'System monitoring: {has_system_monitoring}')
        print(f'Connectivity: {has_connectivity}')
        print(f'Performance: {has_performance}')
        print(f'Security: {has_security}')
        print(f'Discovery: {has_discovery}')
except Exception as e:
    print(f'ERROR: {e}')
\"" 2>/dev/null || echo "ERROR: Could not check functions")
    
    if [[ "$enhanced_functions_check" =~ "ENHANCED_FUNCTIONS_FOUND" ]]; then
        print_success "Enhanced v1.5.2 test functions found on $host"
    else
        print_error "Enhanced test functions missing or incomplete on $host"
        echo "Function check result: $enhanced_functions_check"
        return 1
    fi
    
    # Check file modification time
    local file_mod_time
    file_mod_time=$(ssh "$user@$host" "stat -c '%y' /opt/networkmap/networkmap_agent.py" 2>/dev/null || echo "Unknown")
    print_info "Agent file last modified: $file_mod_time"
    
    # Check if service is running
    local service_status
    service_status=$(ssh "$user@$host" "systemctl is-active networkmap-agent 2>/dev/null || echo 'inactive'")
    
    if [[ "$service_status" == "active" ]]; then
        print_success "NetworkMap agent service is running on $host"
        
        # Check service logs for version info
        local version_in_logs
        version_in_logs=$(ssh "$user@$host" "journalctl -u networkmap-agent --since '10 minutes ago' | grep -i 'version\\|v1\\.5\\.2' | tail -5" 2>/dev/null || echo "")
        
        if [[ -n "$version_in_logs" ]]; then
            print_info "Version info from service logs:"
            echo "$version_in_logs"
        fi
    else
        print_warning "NetworkMap agent service is not running on $host (status: $service_status)"
    fi
    
    # Check running processes
    local running_process
    running_process=$(ssh "$user@$host" "ps aux | grep networkmap_agent.py | grep -v grep" 2>/dev/null || echo "")
    
    if [[ -n "$running_process" ]]; then
        print_info "Running agent process: $running_process"
    else
        print_warning "No networkmap_agent.py process found running"
    fi
    
    print_success "Version check completed for $host"
    return 0
}

# Function to restart agent service
restart_agent_service() {
    local host="$1"
    local user="${2:-$(whoami)}"
    
    print_info "Restarting NetworkMap agent service on $host..."
    
    if ssh "$user@$host" "sudo systemctl restart networkmap-agent" 2>/dev/null; then
        print_success "Service restarted successfully on $host"
        
        # Wait a moment and check status
        sleep 3
        local service_status
        service_status=$(ssh "$user@$host" "systemctl is-active networkmap-agent" 2>/dev/null)
        
        if [[ "$service_status" == "active" ]]; then
            print_success "Service is now running on $host"
        else
            print_error "Service failed to start on $host (status: $service_status)"
        fi
    else
        print_error "Failed to restart service on $host"
    fi
}

# Main function
main() {
    echo "Network Map Agent Version Checker v1.5.2"
    echo "=========================================="
    
    if [[ $# -eq 0 ]]; then
        cat << EOF
Usage: $0 [OPTIONS] <host1> [host2] [host3] ...

OPTIONS:
    -u, --user USER     SSH username (default: current user)
    -r, --restart       Restart agent service after version check
    -h, --help          Show this help message

EXAMPLES:
    # Check version on single host
    $0 192.168.1.100
    
    # Check version on multiple hosts with specific user
    $0 -u ubuntu 192.168.1.100 192.168.1.101 192.168.1.102
    
    # Check version and restart services
    $0 -r 192.168.1.100 192.168.1.101

NOTES:
    - SSH key authentication should be set up for the hosts
    - The script checks for agent version 1.5.2 with enhanced test features
    - Use --restart to restart services if needed to pick up new version
EOF
        exit 0
    fi
    
    local ssh_user="$(whoami)"
    local restart_service=false
    local hosts=()
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--user)
                ssh_user="$2"
                shift 2
                ;;
            -r|--restart)
                restart_service=true
                shift
                ;;
            -h|--help)
                main
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                exit 1
                ;;
            *)
                hosts+=("$1")
                shift
                ;;
        esac
    done
    
    if [[ ${#hosts[@]} -eq 0 ]]; then
        print_error "No hosts specified"
        exit 1
    fi
    
    print_info "SSH user: $ssh_user"
    print_info "Hosts to check: ${hosts[*]}"
    print_info "Restart service: $restart_service"
    
    local success_count=0
    local total_hosts=${#hosts[@]}
    
    # Check each host
    for host in "${hosts[@]}"; do
        if check_host_version "$host" "$ssh_user"; then
            ((success_count++))
            
            if [[ "$restart_service" == true ]]; then
                restart_agent_service "$host" "$ssh_user"
            fi
        fi
    done
    
    echo
    echo "Summary:"
    echo "========"
    print_info "Total hosts checked: $total_hosts"
    print_info "Successful checks: $success_count"
    
    if [[ $success_count -eq $total_hosts ]]; then
        print_success "All hosts are running Network Map Agent v1.5.2 with enhanced features!"
    else
        print_warning "Some hosts failed version verification. Check output above for details."
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
