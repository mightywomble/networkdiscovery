#!/usr/bin/env python3
"""
Network Map Agent Version Checker
Verifies that remote hosts are running Network Map Agent version 1.5.2
with enhanced test features
"""

import argparse
import subprocess
import sys
import concurrent.futures
from typing import List, Tuple, Optional


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    NC = '\033[0m'  # No Color


def print_success(message: str) -> None:
    print(f"{Colors.GREEN}✅ {message}{Colors.NC}")


def print_error(message: str) -> None:
    print(f"{Colors.RED}❌ {message}{Colors.NC}")


def print_warning(message: str) -> None:
    print(f"{Colors.YELLOW}⚠ {message}{Colors.NC}")


def print_info(message: str) -> None:
    print(f"{Colors.BLUE}ℹ {message}{Colors.NC}")


def run_ssh_command(host: str, user: str, command: str, timeout: int = 30) -> Tuple[bool, str, str]:
    """Run SSH command on remote host"""
    try:
        full_command = ['ssh', '-o', 'ConnectTimeout=5', '-o', 'BatchMode=yes', 
                       f'{user}@{host}', command]
        
        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "", "SSH command timed out"
    except Exception as e:
        return False, "", str(e)


def check_host_version(host: str, user: str) -> bool:
    """Check agent version on a single host"""
    print()
    print_info(f"Checking Network Map Agent version on {host}...")
    
    # Test SSH connectivity
    success, stdout, stderr = run_ssh_command(host, user, "echo 'SSH connection successful'")
    if not success:
        print_error(f"Cannot connect to {host} via SSH: {stderr}")
        return False
    
    # Check if agent file exists
    success, stdout, stderr = run_ssh_command(host, user, "test -f /opt/networkmap/networkmap_agent.py")
    if not success:
        print_error(f"Agent file not found on {host} at /opt/networkmap/networkmap_agent.py")
        return False
    
    # Check version in the agent file
    success, version_output, stderr = run_ssh_command(
        host, user, "grep -A 2 '__version__' /opt/networkmap/networkmap_agent.py"
    )
    
    if success and "1.5.2" in version_output:
        print_success(f"Agent version 1.5.2 found in source code on {host}")
    else:
        print_error(f"Version 1.5.2 not found in agent source on {host}")
        if version_output:
            print(f"Version output: {version_output}")
        return False
    
    # Check if enhanced test functions exist
    python_check = '''
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
'''
    
    success, enhanced_check, stderr = run_ssh_command(
        host, user, f'python3 -c "{python_check}"'
    )
    
    if success and "ENHANCED_FUNCTIONS_FOUND" in enhanced_check:
        print_success(f"Enhanced v1.5.2 test functions found on {host}")
    else:
        print_error(f"Enhanced test functions missing or incomplete on {host}")
        print(f"Function check result: {enhanced_check}")
        return False
    
    # Check file modification time
    success, mod_time, stderr = run_ssh_command(
        host, user, "stat -c '%y' /opt/networkmap/networkmap_agent.py"
    )
    if success:
        print_info(f"Agent file last modified: {mod_time}")
    
    # Check if service is running
    success, service_status, stderr = run_ssh_command(
        host, user, "systemctl is-active networkmap-agent 2>/dev/null || echo 'inactive'"
    )
    
    if success:
        if "active" in service_status:
            print_success(f"NetworkMap agent service is running on {host}")
            
            # Check service logs for version info
            success, version_logs, stderr = run_ssh_command(
                host, user, "journalctl -u networkmap-agent --since '10 minutes ago' | grep -i 'version\\|v1\\.5\\.2' | tail -5"
            )
            
            if success and version_logs.strip():
                print_info("Version info from service logs:")
                for line in version_logs.split('\n'):
                    if line.strip():
                        print(f"  {line}")
        else:
            print_warning(f"NetworkMap agent service is not running on {host} (status: {service_status})")
    
    # Check running processes
    success, running_process, stderr = run_ssh_command(
        host, user, "ps aux | grep networkmap_agent.py | grep -v grep"
    )
    
    if success and running_process.strip():
        print_info(f"Running agent process found on {host}")
        for line in running_process.split('\n'):
            if line.strip():
                print(f"  {line}")
    else:
        print_warning(f"No networkmap_agent.py process found running on {host}")
    
    print_success(f"Version check completed for {host}")
    return True


def restart_agent_service(host: str, user: str) -> bool:
    """Restart agent service on a host"""
    print_info(f"Restarting NetworkMap agent service on {host}...")
    
    success, stdout, stderr = run_ssh_command(host, user, "sudo systemctl restart networkmap-agent")
    if not success:
        print_error(f"Failed to restart service on {host}: {stderr}")
        return False
    
    print_success(f"Service restart command sent to {host}")
    
    # Wait a moment and check status
    import time
    time.sleep(3)
    
    success, service_status, stderr = run_ssh_command(host, user, "systemctl is-active networkmap-agent")
    if success and "active" in service_status:
        print_success(f"Service is now running on {host}")
        return True
    else:
        print_error(f"Service failed to start on {host} (status: {service_status})")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Network Map Agent Version Checker v1.5.2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check version on single host
  %(prog)s 192.168.1.100
  
  # Check version on multiple hosts with specific user
  %(prog)s -u ubuntu 192.168.1.100 192.168.1.101 192.168.1.102
  
  # Check version and restart services
  %(prog)s -r 192.168.1.100 192.168.1.101

Notes:
  - SSH key authentication should be set up for the hosts
  - The script checks for agent version 1.5.2 with enhanced test features
  - Use --restart to restart services if needed to pick up new version
"""
    )
    
    parser.add_argument('hosts', nargs='+', help='Remote hosts to check')
    parser.add_argument('-u', '--user', default=None, 
                       help='SSH username (default: current user)')
    parser.add_argument('-r', '--restart', action='store_true',
                       help='Restart agent service after version check')
    parser.add_argument('-j', '--jobs', type=int, default=5,
                       help='Number of parallel jobs (default: 5)')
    
    args = parser.parse_args()
    
    # Get current user if not specified
    if args.user is None:
        import getpass
        args.user = getpass.getuser()
    
    print("Network Map Agent Version Checker v1.5.2")
    print("==========================================")
    print_info(f"SSH user: {args.user}")
    print_info(f"Hosts to check: {', '.join(args.hosts)}")
    print_info(f"Restart service: {args.restart}")
    print_info(f"Parallel jobs: {args.jobs}")
    
    success_count = 0
    total_hosts = len(args.hosts)
    
    # Check hosts in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        # Submit version check tasks
        future_to_host = {
            executor.submit(check_host_version, host, args.user): host 
            for host in args.hosts
        }
        
        successful_hosts = []
        
        # Collect results
        for future in concurrent.futures.as_completed(future_to_host):
            host = future_to_host[future]
            try:
                if future.result():
                    success_count += 1
                    successful_hosts.append(host)
            except Exception as exc:
                print_error(f"Host {host} generated an exception: {exc}")
        
        # Restart services if requested and version check was successful
        if args.restart and successful_hosts:
            print()
            print_info("Restarting services on successful hosts...")
            
            restart_futures = {
                executor.submit(restart_agent_service, host, args.user): host
                for host in successful_hosts
            }
            
            restart_success_count = 0
            for future in concurrent.futures.as_completed(restart_futures):
                host = restart_futures[future]
                try:
                    if future.result():
                        restart_success_count += 1
                except Exception as exc:
                    print_error(f"Restart on host {host} generated an exception: {exc}")
            
            print_info(f"Services restarted successfully on {restart_success_count}/{len(successful_hosts)} hosts")
    
    print()
    print("Summary:")
    print("========")
    print_info(f"Total hosts checked: {total_hosts}")
    print_info(f"Successful checks: {success_count}")
    
    if success_count == total_hosts:
        print_success("All hosts are running Network Map Agent v1.5.2 with enhanced features!")
        sys.exit(0)
    else:
        print_warning(f"Some hosts failed version verification ({success_count}/{total_hosts} successful)")
        sys.exit(1)


if __name__ == "__main__":
    main()
