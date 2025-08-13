#!/usr/bin/env python3
"""
Host Manager module for Network Map application
Handles SSH connections and host management operations
"""

import subprocess
import socket
import paramiko
import time
from datetime import datetime
import json
import re

class HostManager:
    def __init__(self, database):
        self.db = database
        
    def add_host(self, name, ip_address, username='root', ssh_port=22, description=''):
        """Add a new host to the database"""
        return self.db.add_host(name, ip_address, username, ssh_port, description)
    
    def remove_host(self, host_id):
        """Remove a host from the database"""
        self.db.remove_host(host_id)
    
    def get_all_hosts(self):
        """Get all hosts from database"""
        return self.db.get_all_hosts()
    
    def get_host(self, host_id):
        """Get specific host"""
        return self.db.get_host(host_id)
    
    def test_connectivity(self, host):
        """Test if a host is reachable via ping and SSH"""
        ip_address = host['ip_address']
        ssh_port = host.get('ssh_port', 22)
        
        # Test ping first
        try:
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '3', ip_address],
                capture_output=True, text=True, timeout=5
            )
            ping_success = result.returncode == 0
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            ping_success = False
        
        # Test SSH connection
        ssh_success = False
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((ip_address, ssh_port))
            ssh_success = result == 0
            sock.close()
        except Exception:
            ssh_success = False
        
        # Update host status
        if ping_success and ssh_success:
            status = 'online'
        elif ping_success:
            status = 'ping_only'
        else:
            status = 'offline'
        
        self.db.update_host_status(host['id'], status)
        return {'ping': ping_success, 'ssh': ssh_success, 'status': status}
    
    def get_ssh_connection(self, host):
        """Establish SSH connection to a host"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Use key-based authentication (passwordless)
            ssh.connect(
                hostname=host['ip_address'],
                port=host.get('ssh_port', 22),
                username=host.get('username', 'root'),
                timeout=10,
                look_for_keys=True,
                allow_agent=True
            )
            
            return ssh
        except Exception as e:
            print(f"SSH connection failed to {host['name']}: {e}")
            return None
    
    def execute_command(self, host, command, timeout=30):
        """Execute a command on a remote host via SSH"""
        ssh = self.get_ssh_connection(host)
        if not ssh:
            return None, f"Could not connect to {host['name']}"
        
        try:
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            
            # Wait for command to complete
            exit_status = stdout.channel.recv_exit_status()
            
            output = stdout.read().decode('utf-8', errors='ignore')
            error = stderr.read().decode('utf-8', errors='ignore')
            
            ssh.close()
            
            return {
                'exit_status': exit_status,
                'stdout': output,
                'stderr': error,
                'success': exit_status == 0
            }, None
            
        except Exception as e:
            ssh.close()
            return None, f"Command execution failed: {e}"
    
    def get_system_info(self, host):
        """Gather system information from a host"""
        commands = {
            'hostname': 'hostname',
            'os_info': 'cat /etc/os-release 2>/dev/null || uname -a',
            'kernel': 'uname -r',
            'cpu_info': 'cat /proc/cpuinfo | grep "model name" | head -1 | cut -d: -f2',
            'memory': 'cat /proc/meminfo | grep MemTotal | awk \'{print $2}\'',
            'uptime': 'uptime',
            'disk_usage': 'df -h',
            'network_interfaces': 'ip addr show 2>/dev/null || ifconfig',
            'processes': 'ps aux --sort=-%cpu | head -10',
            'listening_ports': 'netstat -tlnp 2>/dev/null || ss -tlnp'
        }
        
        system_info = {}
        
        for info_type, command in commands.items():
            result, error = self.execute_command(host, command)
            if result and result['success']:
                system_info[info_type] = result['stdout'].strip()
            else:
                system_info[info_type] = f"Error: {error or result['stderr']}"
        
        # Parse and store structured data
        try:
            # Parse memory info
            memory_str = system_info.get('memory', '0')
            memory_total = int(memory_str) * 1024 if memory_str.isdigit() else 0
            
            # Parse disk info
            disk_info = self._parse_disk_usage(system_info.get('disk_usage', ''))
            
            # Parse network interfaces
            network_interfaces = self._parse_network_interfaces(system_info.get('network_interfaces', ''))
            
            # Save to database
            self.db.save_host_info(
                host['id'],
                system_info.get('hostname', 'unknown'),
                system_info.get('os_info', 'unknown'),
                system_info.get('kernel', 'unknown'),
                system_info.get('cpu_info', 'unknown'),
                memory_total,
                disk_info,
                network_interfaces
            )
            
        except Exception as e:
            print(f"Error parsing system info for {host['name']}: {e}")
        
        return system_info
    
    def get_network_connections(self, host):
        """Get active network connections from a host"""
        # Try different commands for network connections
        commands = [
            "netstat -tuln 2>/dev/null",
            "ss -tuln 2>/dev/null",
            "lsof -i -n 2>/dev/null"
        ]
        
        for command in commands:
            result, error = self.execute_command(host, command)
            if result and result['success']:
                return self._parse_network_connections(result['stdout'])
        
        return []
    
    def get_traffic_stats(self, host):
        """Get network traffic statistics from a host"""
        commands = {
            'rx_tx_bytes': "cat /proc/net/dev | grep -v 'lo:' | tail -n +3",
            'active_connections': "netstat -an 2>/dev/null | grep ESTABLISHED | wc -l",
            'listening_ports': "netstat -tln 2>/dev/null | grep LISTEN | wc -l"
        }
        
        stats = {}
        total_bytes_in = 0
        total_bytes_out = 0
        
        for stat_type, command in commands.items():
            result, error = self.execute_command(host, command)
            if result and result['success']:
                if stat_type == 'rx_tx_bytes':
                    # Parse network interface statistics
                    for line in result['stdout'].strip().split('\n'):
                        if ':' in line:
                            parts = line.split()
                            if len(parts) >= 10:
                                try:
                                    bytes_in = int(parts[1])
                                    bytes_out = int(parts[9])
                                    total_bytes_in += bytes_in
                                    total_bytes_out += bytes_out
                                except (ValueError, IndexError):
                                    continue
                else:
                    try:
                        stats[stat_type] = int(result['stdout'].strip())
                    except ValueError:
                        stats[stat_type] = 0
        
        # Save traffic statistics
        self.db.add_traffic_stats(
            host['id'],
            bytes_in=total_bytes_in,
            bytes_out=total_bytes_out,
            connections_active=stats.get('active_connections', 0)
        )
        
        return {
            'bytes_in': total_bytes_in,
            'bytes_out': total_bytes_out,
            'active_connections': stats.get('active_connections', 0),
            'listening_ports': stats.get('listening_ports', 0)
        }
    
    def _parse_disk_usage(self, disk_output):
        """Parse df -h output into structured data"""
        disks = []
        lines = disk_output.strip().split('\n')
        
        for line in lines[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 6:
                disks.append({
                    'filesystem': parts[0],
                    'size': parts[1],
                    'used': parts[2],
                    'available': parts[3],
                    'use_percent': parts[4],
                    'mountpoint': parts[5]
                })
        
        return disks
    
    def _parse_network_interfaces(self, interface_output):
        """Parse network interface information"""
        interfaces = []
        
        # Simple parsing for ip addr show output
        current_interface = None
        for line in interface_output.split('\n'):
            line = line.strip()
            
            # New interface
            if line.startswith(('1:', '2:', '3:', '4:', '5:', '6:', '7:', '8:', '9:')):
                if ': ' in line:
                    interface_name = line.split(': ')[1].split('@')[0]
                    current_interface = {
                        'name': interface_name,
                        'addresses': []
                    }
                    interfaces.append(current_interface)
            
            # IP address
            elif 'inet ' in line and current_interface:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == 'inet' and i + 1 < len(parts):
                        current_interface['addresses'].append(parts[i + 1])
        
        return interfaces
    
    def _parse_network_connections(self, netstat_output):
        """Parse network connection output"""
        connections = []
        
        for line in netstat_output.split('\n'):
            line = line.strip()
            if 'ESTABLISHED' in line or 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    local_addr = parts[3]
                    foreign_addr = parts[4] if len(parts) > 4 else ''
                    state = parts[5] if len(parts) > 5 else 'UNKNOWN'
                    
                    # Parse addresses
                    if ':' in local_addr:
                        local_ip, local_port = local_addr.rsplit(':', 1)
                    else:
                        local_ip, local_port = local_addr, '0'
                    
                    if ':' in foreign_addr:
                        foreign_ip, foreign_port = foreign_addr.rsplit(':', 1)
                    else:
                        foreign_ip, foreign_port = foreign_addr, '0'
                    
                    connections.append({
                        'local_ip': local_ip,
                        'local_port': local_port,
                        'foreign_ip': foreign_ip,
                        'foreign_port': foreign_port,
                        'state': state
                    })
        
        return connections
