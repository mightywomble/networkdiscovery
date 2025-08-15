#!/usr/bin/env python3
"""
Network Map Agent
Standalone agent for collecting network data and logs from remote hosts
"""

import argparse
import base64
import json
import logging
import os
import platform
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional

import requests
import hashlib

# Agent version and build information
__version__ = "1.6.1"
__build_date__ = "2025-08-15"

VERSION = __version__
BUILD_DATE = __build_date__
CONFIG_FILE = "/etc/networkmap/agent.conf"
# LOG_FILE = "/var/log/networkmap-agent.log"  # Not used when running under systemd
PID_FILE = "/var/run/networkmap-agent.pid"

class NetworkMapAgent:
    def __init__(self, config_file: str = CONFIG_FILE):
        self.config_file = config_file
        self.config = {}
        self.agent_id = None
        self.running = False
        self.logger = None
        self.scan_thread = None
        self.heartbeat_thread = None
        self.log_collection_thread = None
        self.manual_scan_requested = threading.Event()
        
    def setup_basic_logging(self):
        """Setup basic logging before config is loaded"""
        # Setup logger with basic configuration
        self.logger = logging.getLogger('networkmap-agent')
        self.logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
        
        self.logger.info(f"Network Map Agent v{VERSION} starting up")
    
    def setup_logging(self):
        """Setup full logging configuration after config is loaded"""
        log_level = self.config.get('log_level', 'INFO')
        
        # Update logger level
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # When running under systemd, we only use console/stdout logging
        # systemd will capture stdout/stderr and send to journal via StandardOutput=journal
        # Check if we're running under systemd by looking for JOURNAL_STREAM env var
        running_under_systemd = os.environ.get('JOURNAL_STREAM') is not None
        
        if running_under_systemd:
            # Running under systemd - only use console logging, systemd will handle journal
            self.logger.info("Running under systemd - using journal logging via stdout/stderr")
            # Update console handler log level to match config
            for handler in self.logger.handlers:
                if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                    handler.setLevel(getattr(logging, log_level.upper()))
        else:
            # Not running under systemd - try to add file handler if possible
            has_file_handler = any(isinstance(h, logging.FileHandler) for h in self.logger.handlers)
            if not has_file_handler:
                try:
                    # Try to create log file in /var/log first, fallback to /tmp
                    log_files_to_try = ["/var/log/networkmap-agent.log", "/tmp/networkmap-agent.log"]
                    
                    for log_file in log_files_to_try:
                        try:
                            # Create log directory if it doesn't exist
                            log_dir = os.path.dirname(log_file)
                            os.makedirs(log_dir, exist_ok=True)
                            
                            file_handler = logging.FileHandler(log_file)
                            file_handler.setLevel(getattr(logging, log_level.upper()))
                            
                            formatter = logging.Formatter(
                                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                            )
                            file_handler.setFormatter(formatter)
                            
                            self.logger.addHandler(file_handler)
                            self.logger.info(f"Log file handler added: {log_file}")
                            break  # Success, exit the loop
                        except (PermissionError, OSError) as e:
                            if log_file == log_files_to_try[-1]:  # Last attempt
                                self.logger.warning(f"Cannot write to any log file locations, using console logging only: {e}")
                            continue  # Try next location
                except Exception as e:
                    self.logger.warning(f"Failed to setup file logging: {e}")
    
    def load_config(self):
        """Load agent configuration"""
        config_exists = os.path.exists(self.config_file)
        
        if config_exists:
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                self.logger.error(f"Failed to read configuration file: {e}")
                self.config = {}
        else:
            self.logger.warning(f"Configuration file not found: {self.config_file}")
            self.config = {}
        
        # Generate agent ID if not exists
        if 'agent_id' not in self.config:
            self.config['agent_id'] = str(uuid.uuid4())
        
        self.agent_id = self.config['agent_id']
        
        # Check for required config and prompt if missing
        required_config = {
            'server_url': 'Server URL (e.g., http://192.168.1.100:5000)',
            'username': 'Username for authentication'
        }
        
        config_incomplete = False
        for key, description in required_config.items():
            if key not in self.config or not self.config[key]:
                config_incomplete = True
                self.logger.error(f"Missing required configuration: {key} ({description})")
        
        if config_incomplete:
            self.logger.error("Configuration is incomplete. Please create a proper configuration.")
            self.logger.info("You can create a configuration file using:")
            self.logger.info(f"python3 {sys.argv[0]} --create-config --server-url http://your-server:5000 --username your-username")
            raise Exception("Configuration incomplete. Use --create-config to generate a sample configuration.")
        
        # Set default values for optional config
        defaults = {
            'scan_interval': 300,
            'heartbeat_interval': 60,
            'log_collection_enabled': True,
            'log_paths': '/var/log,/var/log/syslog,/var/log/auth.log',
            'scan_enabled': True,
            'log_level': 'INFO'
        }
        
        for key, default_value in defaults.items():
            if key not in self.config:
                self.config[key] = default_value
        
        # Save config if it was missing or incomplete
        if not config_exists or config_incomplete:
            self.save_config()
        
        self.logger.info(f"Loaded configuration for agent {self.agent_id}")
    
    def save_config(self):
        """Save agent configuration"""
        try:
            # Create config directory if it doesn't exist
            config_dir = os.path.dirname(self.config_file)
            os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            # Set appropriate permissions
            os.chmod(self.config_file, 0o600)
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        try:
            hostname = socket.gethostname()
            ip_address = socket.gethostbyname(hostname)
            
            # Try to get better IP address
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
            except:
                pass
            
            return {
                'hostname': hostname,
                'ip_address': ip_address,
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'agent_version': VERSION
            }
        except Exception as e:
            self.logger.error(f"Failed to get system info: {e}")
            return {}
    
    def register_with_server(self):
        """Register agent with the server"""
        try:
            system_info = self.get_system_info()
            
            data = {
                'agent_id': self.agent_id,
                'hostname': system_info.get('hostname'),
                'ip_address': system_info.get('ip_address'),
                'username': self.config['username'],
                'agent_version': VERSION,
                'platform': system_info.get('platform')
            }
            
            url = f"{self.config['server_url']}/api/agent/register"
            response = requests.post(url, json=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            if result.get('success'):
                self.logger.info("Successfully registered with server")
                return True
            else:
                self.logger.error(f"Server registration failed: {result.get('error')}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to register with server: {e}")
            return False
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'status': 'active',
                'timestamp': datetime.now().isoformat(),
                'agent_version': VERSION,
                'build_date': BUILD_DATE
            }
            
            url = f"{self.config['server_url']}/api/agent/heartbeat"
            response = requests.post(url, json=data, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if not result.get('success'):
                self.logger.warning(f"Heartbeat failed: {result.get('error')}")
            
        except Exception as e:
            self.logger.error(f"Failed to send heartbeat: {e}")
    
    def get_server_config(self) -> Optional[Dict]:
        """Get configuration from server"""
        try:
            url = f"{self.config['server_url']}/api/agent/config/{self.agent_id}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            result = response.json()
            if result.get('success'):
                return result.get('config')
            else:
                self.logger.warning(f"Failed to get server config: {result.get('error')}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get server config: {e}")
            return None
    
    def run_network_scan(self) -> Dict[str, Any]:
        """Run comprehensive network scanning and testing with detailed results"""
        scan_start_time = datetime.now()
        scan_results = {
            'timestamp': scan_start_time.isoformat(),
            'hostname': socket.gethostname(),
            'system_info': {},
            'network_interfaces': {},
            'routing_table': [],
            'arp_table': [],
            'listening_ports': [],
            'active_connections': [],
            'network_stats': {},
            'process_network': [],
            'test_results': {},
            'errors': [],
            'scan_duration': None,
            'scan_status': 'running'
        }
        
        try:
            # System information
            scan_results['system_info'] = self.get_system_info()
            
            # Network interfaces
            try:
                result = subprocess.run(['ip', 'addr', 'show'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['network_interfaces']['ip_addr'] = result.stdout
            except Exception as e:
                self.logger.warning(f"Failed to get network interfaces: {e}")
            
            # Routing table
            try:
                result = subprocess.run(['ip', 'route', 'show'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['routing_table'] = result.stdout.strip().split('\n')
            except Exception as e:
                self.logger.warning(f"Failed to get routing table: {e}")
            
            # ARP table
            try:
                result = subprocess.run(['arp', '-a'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['arp_table'] = result.stdout.strip().split('\n')
            except Exception as e:
                self.logger.warning(f"Failed to get ARP table: {e}")
            
            # Listening ports
            try:
                result = subprocess.run(['ss', '-tlnp'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['listening_ports'] = result.stdout.strip().split('\n')
            except Exception as e:
                self.logger.warning(f"Failed to get listening ports: {e}")
            
            # Active connections
            try:
                result = subprocess.run(['ss', '-tuanp'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['active_connections'] = result.stdout.strip().split('\n')
            except Exception as e:
                self.logger.warning(f"Failed to get active connections: {e}")
            
            # Network statistics
            try:
                result = subprocess.run(['cat', '/proc/net/dev'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    scan_results['network_stats']['net_dev'] = result.stdout
            except Exception as e:
                self.logger.warning(f"Failed to get network stats: {e}")
            
            # Process network connections
            try:
                result = subprocess.run(['lsof', '-i', '-P', '-n'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    scan_results['process_network'] = result.stdout.strip().split('\n')
            except Exception as e:
                self.logger.warning(f"Failed to get process network info: {e}")
            
            # Run comprehensive network tests
            scan_results['test_results'] = self._run_network_tests(scan_results)
            
            # Calculate scan duration
            scan_end_time = datetime.now()
            scan_duration = (scan_end_time - scan_start_time).total_seconds()
            scan_results['scan_duration'] = f"{scan_duration:.2f} seconds"
            scan_results['scan_status'] = 'completed'
            
            self.logger.info(f"Network scan completed successfully in {scan_duration:.2f} seconds")
            
        except Exception as e:
            scan_results['errors'].append(f"Network scan failed: {str(e)}")
            scan_results['scan_status'] = 'failed'
            self.logger.error(f"Network scan failed: {e}")
        
        return scan_results
    
    def _run_network_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run comprehensive network tests and return structured results"""
        test_results = {}
        
        # System Monitoring Tests
        test_results['System Monitoring'] = self._run_system_monitoring_tests(scan_data)
        
        # Network Discovery Tests
        test_results['Network Discovery'] = self._run_network_discovery_tests(scan_data)
        
        # Connection Monitoring Tests
        test_results['Connection Monitoring'] = self._run_connection_monitoring_tests(scan_data)
        
        # Port Scanning Tests
        test_results['Port Scanning'] = self._run_port_scanning_tests(scan_data)
        
        return test_results
    
    def _run_system_monitoring_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run system monitoring tests"""
        tests = {}
        
        # Network Interfaces Test
        interfaces = scan_data.get('network_interfaces', {})
        ip_addr_data = interfaces.get('ip_addr', '')
        active_interfaces = []
        loopback_interfaces = []
        
        if ip_addr_data:
            # Parse interface data for meaningful details
            lines = ip_addr_data.split('\n')
            current_interface = None
            for line in lines:
                if line.strip() and not line.startswith(' '):
                    # Interface line (e.g., "1: lo: <LOOPBACK,UP,LOWER_UP>")
                    if ':' in line:
                        interface_name = line.split(':')[1].strip()
                        current_interface = interface_name
                        if 'UP' in line:
                            if 'LOOPBACK' in line:
                                loopback_interfaces.append(interface_name)
                            else:
                                active_interfaces.append(interface_name)
        
        interfaces_count = len(active_interfaces) + len(loopback_interfaces)
        tests['Network Interfaces'] = {
            'success': interfaces_count > 0,
            'description': f'Found {interfaces_count} network interfaces ({len(active_interfaces)} active, {len(loopback_interfaces)} loopback)',
            'details': f"Interface data collected at {scan_data['timestamp']}\n" +
                      f"Active interfaces: {', '.join(active_interfaces) if active_interfaces else 'None'}\n" +
                      f"Loopback interfaces: {', '.join(loopback_interfaces) if loopback_interfaces else 'None'}\n" +
                      f"Total interfaces detected: {interfaces_count}"
        }
        
        # System Info Test
        system_info = scan_data.get('system_info', {})
        tests['System Information'] = {
            'success': bool(system_info),
            'description': f'Collected system information for {system_info.get("hostname", "unknown")}',
            'details': f"Hostname: {system_info.get('hostname', 'Unknown')}\n" +
                      f"IP Address: {system_info.get('ip_address', 'Unknown')}\n" +
                      f"Platform: {system_info.get('platform', 'Unknown')}\n" +
                      f"Python Version: {system_info.get('python_version', 'Unknown')}\n" +
                      f"Agent Version: {system_info.get('agent_version', 'Unknown')}"
        }
        
        # Network Statistics Test
        net_stats = scan_data.get('network_stats', {})
        net_dev_data = net_stats.get('net_dev', '')
        interface_stats = []
        
        if net_dev_data:
            # Parse network device statistics
            lines = net_dev_data.strip().split('\n')[2:]  # Skip header lines
            for line in lines:
                if ':' in line:
                    interface_name = line.split(':')[0].strip()
                    stats_part = line.split(':')[1].strip().split()
                    if len(stats_part) >= 8:
                        rx_bytes = stats_part[0]
                        tx_bytes = stats_part[8]
                        interface_stats.append(f"{interface_name}: RX {rx_bytes} bytes, TX {tx_bytes} bytes")
        
        tests['Network Statistics'] = {
            'success': bool(net_stats.get('net_dev')),
            'description': f'Collected network statistics for {len(interface_stats)} interfaces',
            'details': f"Statistics collected at {scan_data['timestamp']}\n" +
                      "\n".join(interface_stats[:5]) +  # Show first 5 interfaces
                      (f"\n... and {len(interface_stats) - 5} more" if len(interface_stats) > 5 else "")
        }
        
        return tests
    
    def _run_network_discovery_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run network discovery tests"""
        tests = {}
        
        # ARP Table Analysis
        arp_data = scan_data.get('arp_table', [])
        arp_entries = [entry for entry in arp_data if entry.strip() and '(' in entry]
        unique_hosts = set()
        mac_addresses = set()
        
        for entry in arp_entries:
            # Parse ARP entries like "192.168.1.1 (192.168.1.1) at aa:bb:cc:dd:ee:ff [ether] on eth0"
            if '(' in entry and 'at' in entry:
                parts = entry.split()
                for part in parts:
                    if '(' in part and ')' in part:
                        ip = part.strip('()')
                        unique_hosts.add(ip)
                    elif ':' in part and len(part.replace(':', '')) == 12:  # MAC address format
                        mac_addresses.add(part)
        
        tests['ARP Table Analysis'] = {
            'success': len(arp_entries) > 0,
            'description': f'Found {len(arp_entries)} ARP entries revealing {len(unique_hosts)} unique hosts',
            'details': f"ARP data collected at {scan_data['timestamp']}\n" +
                      f"ARP entries found: {len(arp_entries)}\n" +
                      f"Unique hosts discovered: {len(unique_hosts)}\n" +
                      f"MAC addresses seen: {len(mac_addresses)}\n" +
                      f"Sample hosts: {', '.join(list(unique_hosts)[:3])}" + 
                      (f" and {len(unique_hosts) - 3} more" if len(unique_hosts) > 3 else "")
        }
        
        # Routing Table Analysis
        routing_data = scan_data.get('routing_table', [])
        routing_entries = [route for route in routing_data if route.strip()]
        default_routes = [route for route in routing_entries if 'default' in route]
        local_routes = [route for route in routing_entries if any(net in route for net in ['192.168.', '10.', '172.'])]
        
        tests['Routing Table Analysis'] = {
            'success': len(routing_entries) > 0,
            'description': f'Found {len(routing_entries)} routing entries ({len(default_routes)} default, {len(local_routes)} local)',
            'details': f"Routing data collected at {scan_data['timestamp']}\n" +
                      f"Total routing entries: {len(routing_entries)}\n" +
                      f"Default routes: {len(default_routes)}\n" +
                      f"Local network routes: {len(local_routes)}\n" +
                      f"Sample routes:\n" + "\n".join(routing_entries[:3]) +
                      (f"\n... and {len(routing_entries) - 3} more" if len(routing_entries) > 3 else "")
        }
        
        # Network Topology Test
        tests['Network Topology Mapping'] = {
            'success': len(arp_entries) > 0 or len(routing_entries) > 0,
            'description': f'Network topology analysis: {len(unique_hosts)} hosts, {len(routing_entries)} routes',
            'details': f"Network topology analysis completed at {scan_data['timestamp']}\n" +
                      f"ARP-discovered hosts: {len(unique_hosts)}\n" +
                      f"Routing table entries: {len(routing_entries)}\n" +
                      f"Network segments identified: {len(local_routes)}\n" +
                      f"Gateway routes: {len(default_routes)}"
        }
        
        return tests
    
    def _run_connection_monitoring_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run connection monitoring tests"""
        tests = {}
        
        # Active Connections Analysis
        connections = scan_data.get('active_connections', [])
        valid_connections = [conn for conn in connections if conn.strip() and not conn.startswith('State')]
        tcp_connections = [conn for conn in valid_connections if 'tcp' in conn.lower()]
        udp_connections = [conn for conn in valid_connections if 'udp' in conn.lower()]
        established_connections = [conn for conn in tcp_connections if 'ESTAB' in conn or 'ESTABLISHED' in conn]
        listening_connections = [conn for conn in valid_connections if 'LISTEN' in conn]
        
        # Extract unique remote hosts
        remote_hosts = set()
        for conn in established_connections:
            parts = conn.split()
            for part in parts:
                if ':' in part and not part.startswith('127.') and not part.startswith('0.0.0.0'):
                    host = part.split(':')[0]
                    if '.' in host:  # IP address
                        remote_hosts.add(host)
        
        tests['Connection Monitoring'] = {
            'success': len(valid_connections) > 0,
            'description': f'Monitoring {len(valid_connections)} active connections ({len(established_connections)} established)',
            'details': f"Connections monitored at {scan_data['timestamp']}\n" +
                      f"TCP connections: {len(tcp_connections)}\n" +
                      f"UDP connections: {len(udp_connections)}\n" +
                      f"Established connections: {len(established_connections)}\n" +
                      f"Listening connections: {len(listening_connections)}\n" +
                      f"Remote hosts connected: {len(remote_hosts)}\n" +
                      f"Total active connections: {len(valid_connections)}"
        }
        
        # Process Network Analysis
        process_net = scan_data.get('process_network', [])
        valid_processes = [proc for proc in process_net if proc.strip() and not proc.startswith('COMMAND')]
        unique_processes = set()
        network_protocols = {'TCP': 0, 'UDP': 0, 'IPv4': 0, 'IPv6': 0}
        
        for proc_line in valid_processes:
            parts = proc_line.split()
            if len(parts) >= 1:
                process_name = parts[0]
                unique_processes.add(process_name)
                
                # Count protocols
                if 'TCP' in proc_line:
                    network_protocols['TCP'] += 1
                if 'UDP' in proc_line:
                    network_protocols['UDP'] += 1
                if 'IPv4' in proc_line or '.' in proc_line:
                    network_protocols['IPv4'] += 1
                if 'IPv6' in proc_line or ':' in proc_line and '::' in proc_line:
                    network_protocols['IPv6'] += 1
        
        tests['Process Network Analysis'] = {
            'success': len(valid_processes) > 0,
            'description': f'Found {len(unique_processes)} unique processes with {len(valid_processes)} network connections',
            'details': f"Process network data collected at {scan_data['timestamp']}\n" +
                      f"Total network connections: {len(valid_processes)}\n" +
                      f"Unique processes with network activity: {len(unique_processes)}\n" +
                      f"TCP connections: {network_protocols['TCP']}\n" +
                      f"UDP connections: {network_protocols['UDP']}\n" +
                      f"Top processes: {', '.join(list(unique_processes)[:5])}" +
                      (f" and {len(unique_processes) - 5} more" if len(unique_processes) > 5 else "")
        }
        
        return tests
    
    def _run_port_scanning_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run port scanning tests"""
        tests = {}
        
        # Listening Ports Analysis
        ports = scan_data.get('listening_ports', [])
        valid_ports = [port for port in ports if port.strip() and not port.startswith('State')]
        listening_ports = [port for port in valid_ports if 'LISTEN' in port]
        tcp_ports = [port for port in listening_ports if 'tcp' in port.lower()]
        udp_ports = [port for port in valid_ports if 'udp' in port.lower()]
        
        # Extract port numbers and addresses
        port_details = []
        unique_port_numbers = set()
        for port_line in listening_ports:
            # Parse lines like "LISTEN 0 128 0.0.0.0:22 0.0.0.0:*"
            parts = port_line.split()
            for part in parts:
                if ':' in part and not part.endswith(':*'):
                    try:
                        addr_port = part.split(':')
                        if len(addr_port) >= 2:
                            port_num = addr_port[-1]
                            if port_num.isdigit():
                                unique_port_numbers.add(port_num)
                                port_details.append(f"Port {port_num} on {addr_port[0]}")
                    except:
                        continue
        
        tests['Port Scanning'] = {
            'success': len(listening_ports) > 0,
            'description': f'Found {len(listening_ports)} listening ports across {len(unique_port_numbers)} unique port numbers',
            'details': f"Ports scanned at {scan_data['timestamp']}\n" +
                      f"TCP listening ports: {len(tcp_ports)}\n" +
                      f"UDP ports detected: {len(udp_ports)}\n" +
                      f"Unique port numbers: {len(unique_port_numbers)}\n" +
                      f"Total listening entries: {len(listening_ports)}\n" +
                      f"Sample port details:\n" + "\n".join(port_details[:5]) +
                      (f"\n... and {len(port_details) - 5} more" if len(port_details) > 5 else "")
        }
        
        # Service Discovery
        services_found = []
        service_ports = {}
        
        if listening_ports:
            for port_line in listening_ports:
                # Enhanced service detection
                if ':22' in port_line or ' 22 ' in port_line:
                    services_found.append('SSH (22)')
                    service_ports['SSH'] = '22'
                elif ':80' in port_line or ' 80 ' in port_line:
                    services_found.append('HTTP (80)')
                    service_ports['HTTP'] = '80'
                elif ':443' in port_line or ' 443 ' in port_line:
                    services_found.append('HTTPS (443)')
                    service_ports['HTTPS'] = '443'
                elif ':53' in port_line or ' 53 ' in port_line:
                    services_found.append('DNS (53)')
                    service_ports['DNS'] = '53'
                elif ':25' in port_line or ' 25 ' in port_line:
                    services_found.append('SMTP (25)')
                    service_ports['SMTP'] = '25'
                elif ':5150' in port_line or ' 5150 ' in port_line:
                    services_found.append('NetworkMap (5150)')
                    service_ports['NetworkMap'] = '5150'
                elif ':3306' in port_line or ' 3306 ' in port_line:
                    services_found.append('MySQL (3306)')
                    service_ports['MySQL'] = '3306'
                elif ':5432' in port_line or ' 5432 ' in port_line:
                    services_found.append('PostgreSQL (5432)')
                    service_ports['PostgreSQL'] = '5432'
                elif ':21' in port_line or ' 21 ' in port_line:
                    services_found.append('FTP (21)')
                    service_ports['FTP'] = '21'
        
        # Classify service types
        web_services = [s for s in services_found if any(web in s for web in ['HTTP', 'HTTPS'])]
        database_services = [s for s in services_found if any(db in s for db in ['MySQL', 'PostgreSQL'])]
        system_services = [s for s in services_found if any(sys in s for sys in ['SSH', 'DNS', 'FTP'])]
        
        tests['Service Discovery'] = {
            'success': len(services_found) > 0,
            'description': f'Identified {len(services_found)} services ({len(web_services)} web, {len(database_services)} database, {len(system_services)} system)',
            'details': f"Service discovery completed at {scan_data['timestamp']}\n" +
                      f"Total services identified: {len(services_found)}\n" +
                      f"Web services: {', '.join(web_services) if web_services else 'None'}\n" +
                      f"Database services: {', '.join(database_services) if database_services else 'None'}\n" +
                      f"System services: {', '.join(system_services) if system_services else 'None'}\n" +
                      f"All services: {', '.join(services_found) if services_found else 'None'}"
        }
        
        return tests
    
    def collect_logs(self) -> List[Dict[str, Any]]:
        """Collect system logs"""
        logs = []
        log_paths = self.config.get('log_paths', '/var/log').split(',')
        
        try:
            # Collect from journalctl
            try:
                result = subprocess.run([
                    'journalctl', '--since', '1 hour ago', '--no-pager', 
                    '--output', 'json-pretty'
                ], capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            try:
                                entry = json.loads(line)
                                logs.append({
                                    'source': 'journalctl',
                                    'level': entry.get('PRIORITY', 'info'),
                                    'message': entry.get('MESSAGE', ''),
                                    'timestamp': entry.get('__REALTIME_TIMESTAMP'),
                                    'unit': entry.get('_SYSTEMD_UNIT')
                                })
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                self.logger.warning(f"Failed to collect journalctl logs: {e}")
            
            # Collect from log files
            for log_path in log_paths:
                log_path = log_path.strip()
                if not log_path:
                    continue
                    
                try:
                    if os.path.isdir(log_path):
                        # Scan directory for log files
                        for file_path in Path(log_path).glob('*.log'):
                            logs.extend(self._read_log_file(str(file_path)))
                    elif os.path.isfile(log_path):
                        logs.extend(self._read_log_file(log_path))
                except Exception as e:
                    self.logger.warning(f"Failed to collect logs from {log_path}: {e}")
            
            self.logger.info(f"Collected {len(logs)} log entries")
            
        except Exception as e:
            self.logger.error(f"Log collection failed: {e}")
        
        return logs[-1000:]  # Limit to last 1000 entries
    
    def _read_log_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Read entries from a log file"""
        logs = []
        
        try:
            # Get file modification time to filter recent entries
            mod_time = datetime.fromtimestamp(os.path.getmtime(file_path))
            cutoff_time = datetime.now() - timedelta(hours=1)
            
            if mod_time < cutoff_time:
                return logs  # Skip old files
            
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                
                # Get last 100 lines to avoid memory issues
                for line in lines[-100:]:
                    line = line.strip()
                    if line:
                        logs.append({
                            'source': file_path,
                            'level': self._extract_log_level(line),
                            'message': line,
                            'timestamp': datetime.now().isoformat()
                        })
        
        except Exception as e:
            self.logger.warning(f"Failed to read log file {file_path}: {e}")
        
        return logs
    
    def get_log_level(self, log_line: str) -> str:
        """Extract log level from log line"""
        log_line_lower = log_line.lower()
        
        if any(level in log_line_lower for level in ['error', 'err', 'fatal']):
            return 'error'
        elif any(level in log_line_lower for level in ['warn', 'warning']):
            return 'warning'
        elif any(level in log_line_lower for level in ['info', 'information']):
            return 'info'
        elif any(level in log_line_lower for level in ['debug', 'trace']):
            return 'debug'
        else:
            return 'info'
    
    def _extract_log_level(self, log_line: str) -> str:
        """Extract log level from log line (alias for get_log_level)"""
        return self.get_log_level(log_line)
    
    def _run_connectivity_tests(self) -> Dict[str, Any]:
        """Run connectivity tests"""
        tests = {
            'ping_gateway': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'dns_resolution': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'internet_connectivity': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'port_connectivity': {'status': 'unknown', 'details': '', 'execution_time': 0}
        }
        
        try:
            # Ping gateway test
            start_time = time.time()
            try:
                result = subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    tests['ping_gateway']['status'] = 'pass'
                    tests['ping_gateway']['details'] = 'Gateway reachable'
                else:
                    tests['ping_gateway']['status'] = 'fail'
                    tests['ping_gateway']['details'] = 'Gateway unreachable'
            except Exception as e:
                tests['ping_gateway']['status'] = 'error'
                tests['ping_gateway']['details'] = str(e)
            tests['ping_gateway']['execution_time'] = round(time.time() - start_time, 3)
            
            # DNS resolution test
            start_time = time.time()
            try:
                socket.gethostbyname('google.com')
                tests['dns_resolution']['status'] = 'pass'
                tests['dns_resolution']['details'] = 'DNS resolution working'
            except Exception as e:
                tests['dns_resolution']['status'] = 'fail'
                tests['dns_resolution']['details'] = f'DNS resolution failed: {e}'
            tests['dns_resolution']['execution_time'] = round(time.time() - start_time, 3)
            
            # Internet connectivity test
            start_time = time.time()
            try:
                response = requests.get('http://google.com', timeout=10)
                if response.status_code == 200:
                    tests['internet_connectivity']['status'] = 'pass'
                    tests['internet_connectivity']['details'] = 'Internet connectivity working'
                else:
                    tests['internet_connectivity']['status'] = 'fail'
                    tests['internet_connectivity']['details'] = f'HTTP request failed: {response.status_code}'
            except Exception as e:
                tests['internet_connectivity']['status'] = 'fail'
                tests['internet_connectivity']['details'] = f'Internet connectivity failed: {e}'
            tests['internet_connectivity']['execution_time'] = round(time.time() - start_time, 3)
            
            # Port connectivity test (check common ports)
            start_time = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex(('google.com', 80))
                sock.close()
                if result == 0:
                    tests['port_connectivity']['status'] = 'pass'
                    tests['port_connectivity']['details'] = 'Port 80 accessible'
                else:
                    tests['port_connectivity']['status'] = 'fail'
                    tests['port_connectivity']['details'] = 'Port 80 not accessible'
            except Exception as e:
                tests['port_connectivity']['status'] = 'error'
                tests['port_connectivity']['details'] = str(e)
            tests['port_connectivity']['execution_time'] = round(time.time() - start_time, 3)
            
        except Exception as e:
            self.logger.error(f"Error running connectivity tests: {e}")
            
        return tests
    
    def _run_performance_tests(self) -> Dict[str, Any]:
        """Run performance tests"""
        tests = {
            'bandwidth_test': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'latency_test': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'throughput_test': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'cpu_usage': {'status': 'unknown', 'details': '', 'execution_time': 0}
        }
        
        try:
            # Bandwidth test (simplified)
            start_time = time.time()
            try:
                # Simple download test to estimate bandwidth
                response = requests.get('http://google.com', timeout=15)
                if response.status_code == 200:
                    download_time = time.time() - start_time
                    size_kb = len(response.content) / 1024
                    bandwidth = size_kb / download_time if download_time > 0 else 0
                    tests['bandwidth_test']['status'] = 'pass'
                    tests['bandwidth_test']['details'] = f'Estimated bandwidth: {bandwidth:.2f} KB/s'
                else:
                    tests['bandwidth_test']['status'] = 'fail'
                    tests['bandwidth_test']['details'] = 'Bandwidth test failed'
            except Exception as e:
                tests['bandwidth_test']['status'] = 'error'
                tests['bandwidth_test']['details'] = str(e)
            tests['bandwidth_test']['execution_time'] = round(time.time() - start_time, 3)
            
            # Latency test
            start_time = time.time()
            try:
                result = subprocess.run(['ping', '-c', '3', '8.8.8.8'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0 and 'avg' in result.stdout:
                    tests['latency_test']['status'] = 'pass'
                    tests['latency_test']['details'] = 'Latency measured via ping'
                else:
                    tests['latency_test']['status'] = 'fail'
                    tests['latency_test']['details'] = 'Latency test failed'
            except Exception as e:
                tests['latency_test']['status'] = 'error'
                tests['latency_test']['details'] = str(e)
            tests['latency_test']['execution_time'] = round(time.time() - start_time, 3)
            
            # Throughput test (basic CPU performance)
            start_time = time.time()
            try:
                # Simple CPU test
                result = 0
                for i in range(100000):
                    result += i * 2
                tests['throughput_test']['status'] = 'pass'
                tests['throughput_test']['details'] = 'CPU throughput test completed'
            except Exception as e:
                tests['throughput_test']['status'] = 'error'
                tests['throughput_test']['details'] = str(e)
            tests['throughput_test']['execution_time'] = round(time.time() - start_time, 3)
            
            # CPU usage check
            start_time = time.time()
            try:
                # Get load average
                if hasattr(os, 'getloadavg'):
                    load_avg = os.getloadavg()[0]
                    tests['cpu_usage']['status'] = 'pass'
                    tests['cpu_usage']['details'] = f'Load average: {load_avg:.2f}'
                else:
                    tests['cpu_usage']['status'] = 'pass'
                    tests['cpu_usage']['details'] = 'CPU usage check completed (load avg not available)'
            except Exception as e:
                tests['cpu_usage']['status'] = 'error'
                tests['cpu_usage']['details'] = str(e)
            tests['cpu_usage']['execution_time'] = round(time.time() - start_time, 3)
            
        except Exception as e:
            self.logger.error(f"Error running performance tests: {e}")
            
        return tests
    
    def _run_security_tests(self) -> Dict[str, Any]:
        """Run security tests"""
        tests = {
            'open_ports': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'firewall_status': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'ssh_config': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'file_permissions': {'status': 'unknown', 'details': '', 'execution_time': 0}
        }
        
        try:
            # Open ports scan
            start_time = time.time()
            try:
                result = subprocess.run(['netstat', '-tuln'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    open_ports = len([line for line in result.stdout.split('\n') if 'LISTEN' in line])
                    tests['open_ports']['status'] = 'pass'
                    tests['open_ports']['details'] = f'Found {open_ports} listening ports'
                else:
                    tests['open_ports']['status'] = 'fail'
                    tests['open_ports']['details'] = 'Could not scan ports'
            except Exception as e:
                tests['open_ports']['status'] = 'error'
                tests['open_ports']['details'] = str(e)
            tests['open_ports']['execution_time'] = round(time.time() - start_time, 3)
            
            # Firewall status
            start_time = time.time()
            try:
                # Check for common firewall tools
                firewall_found = False
                for fw_cmd in ['ufw', 'iptables', 'firewalld']:
                    try:
                        result = subprocess.run(['which', fw_cmd], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            firewall_found = True
                            tests['firewall_status']['status'] = 'pass'
                            tests['firewall_status']['details'] = f'Firewall tool found: {fw_cmd}'
                            break
                    except:
                        continue
                
                if not firewall_found:
                    tests['firewall_status']['status'] = 'warning'
                    tests['firewall_status']['details'] = 'No common firewall tools found'
                    
            except Exception as e:
                tests['firewall_status']['status'] = 'error'
                tests['firewall_status']['details'] = str(e)
            tests['firewall_status']['execution_time'] = round(time.time() - start_time, 3)
            
            # SSH config check
            start_time = time.time()
            try:
                if os.path.exists('/etc/ssh/sshd_config'):
                    tests['ssh_config']['status'] = 'pass'
                    tests['ssh_config']['details'] = 'SSH config file found'
                else:
                    tests['ssh_config']['status'] = 'warning'
                    tests['ssh_config']['details'] = 'SSH config file not found'
            except Exception as e:
                tests['ssh_config']['status'] = 'error'
                tests['ssh_config']['details'] = str(e)
            tests['ssh_config']['execution_time'] = round(time.time() - start_time, 3)
            
            # File permissions check
            start_time = time.time()
            try:
                # Check permissions on sensitive files
                sensitive_files = ['/etc/passwd', '/etc/shadow', '/etc/sudoers']
                issues = []
                for file_path in sensitive_files:
                    if os.path.exists(file_path):
                        stat_info = os.stat(file_path)
                        mode = stat_info.st_mode
                        if file_path == '/etc/shadow' and (mode & 0o077) != 0:
                            issues.append(f'{file_path} has overly permissive permissions')
                        elif file_path == '/etc/sudoers' and (mode & 0o022) != 0:
                            issues.append(f'{file_path} has overly permissive permissions')
                
                if issues:
                    tests['file_permissions']['status'] = 'warning'
                    tests['file_permissions']['details'] = f'Permission issues: {", ".join(issues)}'
                else:
                    tests['file_permissions']['status'] = 'pass'
                    tests['file_permissions']['details'] = 'File permissions look secure'
            except Exception as e:
                tests['file_permissions']['status'] = 'error'
                tests['file_permissions']['details'] = str(e)
            tests['file_permissions']['execution_time'] = round(time.time() - start_time, 3)
            
        except Exception as e:
            self.logger.error(f"Error running security tests: {e}")
            
        return tests
    
    def _run_discovery_tests(self) -> Dict[str, Any]:
        """Run discovery tests"""
        tests = {
            'network_scan': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'arp_table': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'route_table': {'status': 'unknown', 'details': '', 'execution_time': 0},
            'interface_discovery': {'status': 'unknown', 'details': '', 'execution_time': 0}
        }
        
        try:
            # Network scan (ping sweep)
            start_time = time.time()
            try:
                # Get local network info
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                network_base = '.'.join(local_ip.split('.')[:-1]) + '.'
                
                # Simple ping sweep (first 10 IPs)
                reachable_hosts = 0
                for i in range(1, 11):
                    try:
                        result = subprocess.run(['ping', '-c', '1', '-W', '1', f'{network_base}{i}'], 
                                              capture_output=True, text=True, timeout=3)
                        if result.returncode == 0:
                            reachable_hosts += 1
                    except:
                        continue
                
                tests['network_scan']['status'] = 'pass'
                tests['network_scan']['details'] = f'Found {reachable_hosts} reachable hosts in network'
            except Exception as e:
                tests['network_scan']['status'] = 'error'
                tests['network_scan']['details'] = str(e)
            tests['network_scan']['execution_time'] = round(time.time() - start_time, 3)
            
            # ARP table
            start_time = time.time()
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    arp_entries = len([line for line in result.stdout.split('\n') if line.strip()])
                    tests['arp_table']['status'] = 'pass'
                    tests['arp_table']['details'] = f'ARP table has {arp_entries} entries'
                else:
                    tests['arp_table']['status'] = 'fail'
                    tests['arp_table']['details'] = 'Could not read ARP table'
            except Exception as e:
                tests['arp_table']['status'] = 'error'
                tests['arp_table']['details'] = str(e)
            tests['arp_table']['execution_time'] = round(time.time() - start_time, 3)
            
            # Route table
            start_time = time.time()
            try:
                result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    route_entries = len([line for line in result.stdout.split('\n') if line.strip() and not line.startswith('Kernel')])
                    tests['route_table']['status'] = 'pass'
                    tests['route_table']['details'] = f'Route table has {route_entries} entries'
                else:
                    tests['route_table']['status'] = 'fail'
                    tests['route_table']['details'] = 'Could not read route table'
            except Exception as e:
                tests['route_table']['status'] = 'error'
                tests['route_table']['details'] = str(e)
            tests['route_table']['execution_time'] = round(time.time() - start_time, 3)
            
            # Interface discovery
            start_time = time.time()
            try:
                result = subprocess.run(['ip', 'addr', 'show'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    interfaces = len([line for line in result.stdout.split('\n') if ': ' in line and 'inet ' in result.stdout])
                    tests['interface_discovery']['status'] = 'pass'
                    tests['interface_discovery']['details'] = f'Found {interfaces} network interfaces'
                else:
                    # Fallback to ifconfig
                    result = subprocess.run(['ifconfig'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        interfaces = len([line for line in result.stdout.split('\n') if 'inet ' in line])
                        tests['interface_discovery']['status'] = 'pass'
                        tests['interface_discovery']['details'] = f'Found {interfaces} network interfaces'
                    else:
                        tests['interface_discovery']['status'] = 'fail'
                        tests['interface_discovery']['details'] = 'Could not discover interfaces'
            except Exception as e:
                tests['interface_discovery']['status'] = 'error'
                tests['interface_discovery']['details'] = str(e)
            tests['interface_discovery']['execution_time'] = round(time.time() - start_time, 3)
            
        except Exception as e:
            self.logger.error(f"Error running discovery tests: {e}")
            
        return tests
    
    def send_scan_results(self, scan_data: Dict[str, Any]):
        """Send scan results to server"""
        try:
            data = {
                'agent_id': self.agent_id,
                'scan_type': 'network_scan',
                'scan_data': scan_data
            }
            
            url = f"{self.config['server_url']}/api/agent/scan_results"
            response = requests.post(url, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            if result.get('success'):
                self.logger.info("Scan results sent successfully")
            else:
                self.logger.error(f"Failed to send scan results: {result.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Failed to send scan results: {e}")
    
    def send_logs(self, logs: List[Dict[str, Any]]):
        """Send logs to server"""
        if not logs:
            return
            
        try:
            data = {
                'agent_id': self.agent_id,
                'logs': logs
            }
            
            url = f"{self.config['server_url']}/api/agent/logs"
            response = requests.post(url, json=data, timeout=60)
            response.raise_for_status()
            
            result = response.json()
            if result.get('success'):
                self.logger.info(f"Sent {len(logs)} log entries successfully")
            else:
                self.logger.error(f"Failed to send logs: {result.get('error')}")
                
        except Exception as e:
            self.logger.error(f"Failed to send logs: {e}")
    
    def signal_handler(self, signum, frame):
        """Handle signals for immediate scan requests"""
        if signum == signal.SIGUSR1:
            self.logger.info("🚀 Received USR1 signal - triggering immediate network scan")
            self.manual_scan_requested.set()
        elif signum == signal.SIGTERM:
            self.logger.info("Received TERM signal - stopping agent")
            self.stop()
        elif signum == signal.SIGINT:
            self.logger.info("Received INT signal - stopping agent")
            self.stop()
    
    def setup_signal_handlers(self):
        """Setup signal handlers for immediate scan triggering"""
        signal.signal(signal.SIGUSR1, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)
        self.logger.info("Signal handlers configured - send USR1 to trigger immediate scan")
    
    def scan_worker(self):
        """Background thread for periodic scanning with immediate scan support"""
        while self.running:
            try:
                # Check if manual scan was requested
                if self.manual_scan_requested.is_set():
                    self.logger.info("🔥 MANUAL SCAN TRIGGERED - Starting immediate network scan")
                    self.manual_scan_requested.clear()
                    
                    if self.config.get('scan_enabled', True):
                        scan_results = self.run_network_scan()
                        self.send_scan_results(scan_results)
                        self.logger.info("✅ Manual scan completed and results sent to server")
                    else:
                        self.logger.warning("⚠️ Manual scan requested but scanning is disabled in configuration")
                
                # Regular periodic scan
                elif self.config.get('scan_enabled', True):
                    self.logger.info("Starting periodic network scan")
                    scan_results = self.run_network_scan()
                    self.send_scan_results(scan_results)
                
                # Sleep for scan interval, but check for manual scans every second
                scan_interval = self.config.get('scan_interval', 300)  # 5 minutes default
                for _ in range(scan_interval):
                    if not self.running:
                        break
                    if self.manual_scan_requested.is_set():
                        break  # Break out of sleep to handle manual scan immediately
                    time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Scan worker error: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def heartbeat_worker(self):
        """Background thread for periodic heartbeats"""
        while self.running:
            try:
                self.send_heartbeat()
                
                # Check for updated config from server
                server_config = self.get_server_config()
                if server_config:
                    # Update local config if needed
                    config_changed = False
                    for key, value in server_config.items():
                        if key in ['scan_interval', 'heartbeat_interval', 'log_collection_enabled', 
                                  'log_paths', 'scan_enabled']:
                            if self.config.get(key) != value:
                                self.config[key] = value
                                config_changed = True
                    
                    if config_changed:
                        self.save_config()
                        self.logger.info("Configuration updated from server")
                
                # Sleep for heartbeat interval
                heartbeat_interval = self.config.get('heartbeat_interval', 60)  # 1 minute default
                time.sleep(heartbeat_interval)
                
            except Exception as e:
                self.logger.error(f"Heartbeat worker error: {e}")
                time.sleep(60)  # Wait 1 minute before retrying
    
    def log_collection_worker(self):
        """Background thread for periodic log collection"""
        while self.running:
            try:
                if self.config.get('log_collection_enabled', True):
                    self.logger.info("Collecting logs")
                    logs = self.collect_logs()
                    if logs:
                        self.send_logs(logs)
                
                # Sleep for log collection interval (same as heartbeat)
                log_interval = self.config.get('heartbeat_interval', 60)
                time.sleep(log_interval * 5)  # Collect logs every 5 heartbeats
                
            except Exception as e:
                self.logger.error(f"Log collection worker error: {e}")
                time.sleep(300)  # Wait 5 minutes before retrying
    
    def create_pid_file(self):
        """Create PID file"""
        try:
            pid_dir = os.path.dirname(PID_FILE)
            os.makedirs(pid_dir, exist_ok=True)
            
            with open(PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
            
            self.logger.info(f"PID file created: {PID_FILE}")
            
        except Exception as e:
            self.logger.error(f"Failed to create PID file: {e}")
    
    def remove_pid_file(self):
        """Remove PID file"""
        try:
            if os.path.exists(PID_FILE):
                os.remove(PID_FILE)
                self.logger.info("PID file removed")
        except Exception as e:
            self.logger.error(f"Failed to remove PID file: {e}")
    
    def start(self):
        """Start the agent"""
        try:
            # Setup basic logging first
            self.setup_basic_logging()
            
            # Load configuration
            self.load_config()
            
            # Setup full logging with config
            self.setup_logging()
            
            # Check if agent is already running
            if os.path.exists(PID_FILE):
                with open(PID_FILE, 'r') as f:
                    old_pid = int(f.read().strip())
                
                try:
                    os.kill(old_pid, 0)  # Check if process exists
                    self.logger.error(f"Agent already running with PID {old_pid}")
                    return False
                except OSError:
                    # Process doesn't exist, remove stale PID file
                    os.remove(PID_FILE)
            
            self.create_pid_file()
            
            # Setup signal handlers for immediate scans
            self.setup_signal_handlers()
            
            # Register with server
            if not self.register_with_server():
                self.logger.error("Failed to register with server")
                return False
            
            self.running = True
            
            # Start background threads
            self.heartbeat_thread = threading.Thread(target=self.heartbeat_worker, daemon=True)
            self.heartbeat_thread.start()
            
            self.log_collection_thread = threading.Thread(target=self.log_collection_worker, daemon=True)
            self.log_collection_thread.start()
            
            self.scan_thread = threading.Thread(target=self.scan_worker, daemon=True)
            self.scan_thread.start()
            
            self.logger.info("Network Map Agent started successfully")
            
            # Main loop
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                self.logger.info("Received interrupt signal")
                self.stop()
            
        except Exception as e:
            self.logger.error(f"Failed to start agent: {e}")
            return False
        
        return True
    
    def stop(self):
        """Stop the agent"""
        self.logger.info("Stopping Network Map Agent")
        self.running = False
        
        # Wait for threads to finish
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=5)
        
        if self.heartbeat_thread and self.heartbeat_thread.is_alive():
            self.heartbeat_thread.join(timeout=5)
        
        if self.log_collection_thread and self.log_collection_thread.is_alive():
            self.log_collection_thread.join(timeout=5)
        
        self.remove_pid_file()
        self.logger.info("Network Map Agent stopped")


def create_sample_config(config_file: str, server_url: str, username: str):
    """Create a sample configuration file"""
    config = {
        "server_url": server_url,
        "username": username,
        "scan_interval": 300,
        "heartbeat_interval": 60,
        "log_collection_enabled": True,
        "log_paths": "/var/log,/var/log/syslog,/var/log/auth.log",
        "scan_enabled": True,
        "log_level": "INFO"
    }
    
    # Create config directory
    config_dir = os.path.dirname(config_file)
    os.makedirs(config_dir, exist_ok=True)
    
    # Write config file
    with open(config_file, 'w') as f:
        json.dump(config, f, indent=2)
    
    # Set appropriate permissions
    os.chmod(config_file, 0o600)
    
    print(f"Sample configuration created: {config_file}")
    print("Please review and modify the configuration as needed.")


def main():
    parser = argparse.ArgumentParser(description='Network Map Agent')
    parser.add_argument('--config', '-c', default=CONFIG_FILE,
                       help=f'Configuration file path (default: {CONFIG_FILE})')
    parser.add_argument('--create-config', action='store_true',
                       help='Create sample configuration file')
    parser.add_argument('--server-url', 
                       help='Server URL for configuration creation')
    parser.add_argument('--username', 
                       help='Username for configuration creation')
    parser.add_argument('--daemon', '-d', action='store_true',
                       help='Run as daemon')
    parser.add_argument('--version', action='version', version=f'Network Map Agent {VERSION}')
    
    args = parser.parse_args()
    
    # Create configuration if requested
    if args.create_config:
        if not args.server_url or not args.username:
            print("Error: --server-url and --username are required for --create-config")
            sys.exit(1)
        
        create_sample_config(args.config, args.server_url, args.username)
        sys.exit(0)
    
    # Check if running as root (required for some network commands)
    if os.getuid() != 0:
        print("Warning: Agent is not running as root. Some network scanning features may not work.")
    
    # Run as daemon if requested
    if args.daemon:
        # Simple daemon implementation
        if os.fork() > 0:
            sys.exit(0)
        
        os.setsid()
        
        if os.fork() > 0:
            sys.exit(0)
        
        # Redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        
        with open('/dev/null', 'r') as f:
            os.dup2(f.fileno(), sys.stdin.fileno())
        
        with open('/dev/null', 'w') as f:
            os.dup2(f.fileno(), sys.stdout.fileno())
            os.dup2(f.fileno(), sys.stderr.fileno())
    
    # Start agent
    agent = NetworkMapAgent(args.config)
    success = agent.start()
    
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
