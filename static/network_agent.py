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

VERSION = "1.5.0"
CONFIG_FILE = "/etc/networkmap/agent.conf"
LOG_FILE = "/var/log/networkmap-agent.log"
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
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_level = self.config.get('log_level', 'INFO')
        
        # Create log directory if it doesn't exist
        log_dir = os.path.dirname(LOG_FILE)
        os.makedirs(log_dir, exist_ok=True)
        
        # Setup logger
        self.logger = logging.getLogger('networkmap-agent')
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(getattr(logging, log_level.upper()))
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
        
        self.logger.info(f"Network Map Agent v{VERSION} starting up")
    
    def load_config(self):
        """Load agent configuration"""
        if not os.path.exists(self.config_file):
            raise FileNotFoundError(f"Configuration file not found: {self.config_file}")
        
        try:
            with open(self.config_file, 'r') as f:
                self.config = json.load(f)
            
            # Generate agent ID if not exists
            if 'agent_id' not in self.config:
                self.config['agent_id'] = str(uuid.uuid4())
                self.save_config()
            
            self.agent_id = self.config['agent_id']
            
            # Validate required config
            required_keys = ['server_url', 'username']
            for key in required_keys:
                if key not in self.config:
                    raise ValueError(f"Missing required configuration key: {key}")
            
            self.logger.info(f"Loaded configuration for agent {self.agent_id}")
            
        except Exception as e:
            raise Exception(f"Failed to load configuration: {e}")
    
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
                'timestamp': datetime.now().isoformat()
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
        interfaces_count = len(interfaces.get('ip_addr', '').split('\n')) if interfaces.get('ip_addr') else 0
        tests['Network Interfaces'] = {
            'success': interfaces_count > 0,
            'description': f'Found {interfaces_count} network interface entries',
            'details': f"Interface data collected at {scan_data['timestamp']}\nInterfaces detected: {interfaces_count}"
        }
        
        # System Info Test
        system_info = scan_data.get('system_info', {})
        tests['System Information'] = {
            'success': bool(system_info),
            'description': f'Collected system information for {system_info.get("hostname", "unknown")}',
            'details': f"Platform: {system_info.get('platform', 'Unknown')}\nAgent version: {system_info.get('agent_version', 'Unknown')}"
        }
        
        # Network Statistics Test
        net_stats = scan_data.get('network_stats', {})
        tests['Network Statistics'] = {
            'success': bool(net_stats.get('net_dev')),
            'description': 'Network interface statistics collected',
            'details': f"Statistics collected at {scan_data['timestamp']}"
        }
        
        return tests
    
    def _run_network_discovery_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run network discovery tests"""
        tests = {}
        
        # ARP Table Analysis
        arp_data = scan_data.get('arp_table', [])
        arp_count = len([entry for entry in arp_data if entry.strip()]) if arp_data else 0
        tests['ARP Table Analysis'] = {
            'success': arp_count > 0,
            'description': f'Found {arp_count} entries in ARP table',
            'details': f"ARP data collected at {scan_data['timestamp']}\nEntries found: {arp_count}\nHosts discovered via ARP"
        }
        
        # Routing Table Analysis
        routing_data = scan_data.get('routing_table', [])
        routing_count = len([route for route in routing_data if route.strip()]) if routing_data else 0
        tests['Routing Table Analysis'] = {
            'success': routing_count > 0,
            'description': f'Found {routing_count} routing entries',
            'details': f"Routing data collected at {scan_data['timestamp']}\nRoutes analyzed: {routing_count}"
        }
        
        # Network Topology Test
        tests['Network Topology Mapping'] = {
            'success': arp_count > 0 or routing_count > 0,
            'description': f'Network topology analysis based on ARP and routing data',
            'details': f"Combined ARP ({arp_count}) and routing ({routing_count}) entries for topology mapping"
        }
        
        return tests
    
    def _run_connection_monitoring_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run connection monitoring tests"""
        tests = {}
        
        # Active Connections Analysis
        connections = scan_data.get('active_connections', [])
        connection_count = len([conn for conn in connections if conn.strip()]) if connections else 0
        tcp_connections = len([conn for conn in connections if 'tcp' in conn.lower()]) if connections else 0
        udp_connections = len([conn for conn in connections if 'udp' in conn.lower()]) if connections else 0
        
        tests['Connection Monitoring'] = {
            'success': connection_count > 0,
            'description': f'Found {connection_count} active connections',
            'details': f"Connections monitored at {scan_data['timestamp']}\nTCP connections: {tcp_connections}\nUDP connections: {udp_connections}\nTotal active: {connection_count}"
        }
        
        # Process Network Analysis
        process_net = scan_data.get('process_network', [])
        process_count = len([proc for proc in process_net if proc.strip()]) if process_net else 0
        tests['Process Network Analysis'] = {
            'success': process_count > 0,
            'description': f'Found {process_count} processes with network connections',
            'details': f"Process network data collected at {scan_data['timestamp']}\nProcesses with network activity: {process_count}"
        }
        
        return tests
    
    def _run_port_scanning_tests(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Run port scanning tests"""
        tests = {}
        
        # Listening Ports Analysis
        ports = scan_data.get('listening_ports', [])
        port_count = len([port for port in ports if port.strip() and 'LISTEN' in port]) if ports else 0
        tcp_ports = len([port for port in ports if 'tcp' in port.lower() and 'LISTEN' in port]) if ports else 0
        
        tests['Port Scanning'] = {
            'success': port_count > 0,
            'description': f'Found {port_count} listening ports',
            'details': f"Ports scanned at {scan_data['timestamp']}\nTCP listening ports: {tcp_ports}\nTotal listening: {port_count}"
        }
        
        # Service Discovery
        services_found = []
        if ports:
            for port_line in ports:
                if 'LISTEN' in port_line:
                    # Extract service information from port line
                    if '22' in port_line:
                        services_found.append('SSH')
                    elif '80' in port_line:
                        services_found.append('HTTP')
                    elif '443' in port_line:
                        services_found.append('HTTPS')
                    elif '5150' in port_line:
                        services_found.append('NetworkMap')
        
        tests['Service Discovery'] = {
            'success': len(services_found) > 0,
            'description': f'Identified {len(services_found)} common services',
            'details': f"Services discovered: {', '.join(set(services_found))}\nService detection completed at {scan_data['timestamp']}"
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
    
    def _extract_log_level(self, log_line: str) -> str:
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
    
    def scan_worker(self):
        """Background thread for periodic scanning"""
        while self.running:
            try:
                if self.config.get('scan_enabled', True):
                    self.logger.info("Starting network scan")
                    scan_results = self.run_network_scan()
                    self.send_scan_results(scan_results)
                
                # Sleep for scan interval
                scan_interval = self.config.get('scan_interval', 300)  # 5 minutes default
                time.sleep(scan_interval)
                
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
            self.load_config()
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
