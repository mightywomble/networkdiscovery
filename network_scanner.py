#!/usr/bin/env python3
"""
Network Scanner module for Network Map application
Handles port scanning, network discovery, and connection mapping
"""

import socket
import subprocess
import threading
import time
from datetime import datetime
import ipaddress
import xml.etree.ElementTree as ET
from network_discovery import EnhancedNetworkDiscovery
from topology_analyzer import TopologyAnalyzer

class NetworkScanner:
    def __init__(self, host_manager, database):
        self.host_manager = host_manager
        self.db = database
        self.enhanced_discovery = EnhancedNetworkDiscovery(host_manager, database)
        self.topology_analyzer = TopologyAnalyzer(database)
        self.progress_callback = None
    
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, message):
        """Update progress via callback if available"""
        print(message)  # Still print to console
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan_host(self, host):
        """Perform comprehensive scan of a single host"""
        self._update_progress(f"Scanning host: {host['name']} ({host['ip_address']})")
        
        # Test connectivity first
        connectivity = self.host_manager.test_connectivity(host)
        if not connectivity['ssh']:
            self._update_progress(f"Host {host['name']} is not accessible via SSH")
            return
        
        # Get system information
        try:
            system_info = self.host_manager.get_system_info(host)
            self._update_progress(f"Collected system info for {host['name']}")
        except Exception as e:
            self._update_progress(f"Error collecting system info for {host['name']}: {e}")
        
        # Get network connections
        try:
            connections = self.host_manager.get_network_connections(host)
            self._process_connections(host, connections)
            self._update_progress(f"Found {len(connections)} network connections on {host['name']}")
        except Exception as e:
            self._update_progress(f"Error getting network connections for {host['name']}: {e}")
        
        # Get traffic statistics
        try:
            traffic_stats = self.host_manager.get_traffic_stats(host)
            self._update_progress(f"Collected traffic stats for {host['name']}")
        except Exception as e:
            self._update_progress(f"Error collecting traffic stats for {host['name']}: {e}")
        
        # Perform port scan on the host
        try:
            ports = self._port_scan_host(host)
            if ports:
                self.db.save_port_scan(host['id'], ports)
                self._update_progress(f"Found {len(ports)} open ports on {host['name']}")
        except Exception as e:
            self._update_progress(f"Error port scanning {host['name']}: {e}")
        
        # Discover local network from this host
        try:
            self._discover_local_network(host)
        except Exception as e:
            self._update_progress(f"Error discovering local network from {host['name']}: {e}")
        
        # Enhanced comprehensive discovery
        try:
            enhanced_data = self.enhanced_discovery.collect_comprehensive_data(host)
            self._update_progress(f"Enhanced discovery completed for {host['name']}")
        except Exception as e:
            self._update_progress(f"Error in enhanced discovery for {host['name']}: {e}")
    
    def _port_scan_host(self, host, ports=None):
        """Scan common ports on a host"""
        if ports is None:
            # Common ports to scan
            ports = [
                21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200
            ]
        
        open_ports = []
        ip_address = host['ip_address']
        
        # Use nmap if available, fallback to socket scanning
        nmap_result = self._nmap_scan(ip_address, ports)
        if nmap_result:
            return nmap_result
        
        # Fallback to socket scanning
        self._update_progress(f"Using socket scan for {host['name']}")
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip_address, port))
                if result == 0:
                    # Try to get service banner
                    service_info = self._get_service_banner(ip_address, port)
                    open_ports.append({
                        'port': port,
                        'state': 'open',
                        'service': service_info.get('service', 'unknown'),
                        'version': service_info.get('version', '')
                    })
                sock.close()
            except Exception:
                pass
        
        # Scan ports in parallel
        threads = []
        for port in ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        return open_ports
    
    def _nmap_scan(self, ip_address, ports):
        """Use nmap for port scanning if available"""
        try:
            port_range = ','.join(map(str, ports))
            cmd = [
                'nmap', '-p', port_range, '--open', '-sS', '-O', '-sV', 
                '--version-intensity', '5', '-T4', ip_address
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                return self._parse_nmap_output(result.stdout)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # nmap not available or timeout
            pass
        
        return None
    
    def _parse_nmap_output(self, nmap_output):
        """Parse nmap output to extract port information"""
        ports = []
        
        lines = nmap_output.split('\n')
        for line in lines:
            line = line.strip()
            
            # Look for port lines (e.g., "80/tcp open http nginx 1.18.0")
            if '/tcp' in line and 'open' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_str = parts[0]
                    port = int(port_str.split('/')[0])
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else 'unknown'
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                    
                    ports.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'version': version
                    })
        
        return ports
    
    def _get_service_banner(self, ip_address, port):
        """Try to get service banner/version information"""
        service_info = {'service': 'unknown', 'version': ''}
        
        # Common service identification
        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            993: 'imaps',
            995: 'pop3s',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-alt',
            8443: 'https-alt',
            9200: 'elasticsearch'
        }
        
        service_info['service'] = service_map.get(port, 'unknown')
        
        # Try to get banner for some services
        try:
            if port in [21, 22, 25, 110, 143]:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((ip_address, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                service_info['version'] = banner[:100]  # Limit banner length
                sock.close()
        except Exception:
            pass
        
        return service_info
    
    def _process_connections(self, host, connections):
        """Process network connections and store in database"""
        for conn in connections:
            if conn['state'] == 'ESTABLISHED' and conn['foreign_ip'] not in ['0.0.0.0', '127.0.0.1']:
                # Try to find destination host
                dest_host_id = self._find_host_by_ip(conn['foreign_ip'])
                
                # Store connection
                try:
                    self.db.add_connection(
                        source_host_id=host['id'],
                        dest_host_id=dest_host_id,
                        dest_ip=conn['foreign_ip'],
                        dest_port=int(conn['foreign_port']) if conn['foreign_port'].isdigit() else 0,
                        protocol='tcp'  # Assuming TCP for now
                    )
                except Exception as e:
                    print(f"Error storing connection: {e}")
    
    def _find_host_by_ip(self, ip_address):
        """Find host ID by IP address"""
        hosts = self.host_manager.get_all_hosts()
        for host in hosts:
            if host['ip_address'] == ip_address:
                return host['id']
        return None
    
    def _discover_local_network(self, host):
        """Discover other hosts on the local network from this host"""
        # Get network interfaces to determine subnets
        result, error = self.host_manager.execute_command(
            host, "ip route show 2>/dev/null | grep -E '^[0-9]+\\.' | head -5"
        )
        
        if not result or not result['success']:
            return
        
        # Parse routing table to find local networks
        networks = []
        for line in result['stdout'].strip().split('\n'):
            if '/' in line:
                parts = line.split()
                if parts and '/' in parts[0]:
                    try:
                        network = ipaddress.IPv4Network(parts[0], strict=False)
                        if network.is_private:
                            networks.append(network)
                    except (ipaddress.AddressValueError, ValueError):
                        continue
        
        # Discover hosts in local networks
        for network in networks[:2]:  # Limit to first 2 networks
            self._discover_network_hosts(host, network)
    
    def _discover_network_hosts(self, scanning_host, network):
        """Discover hosts in a specific network"""
        self._update_progress(f"Discovering hosts in network {network} from {scanning_host['name']}")
        
        # Use nmap for network discovery if available
        try:
            cmd = ['nmap', '-sn', str(network)]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                discovered_ips = self._parse_nmap_discovery(result.stdout)
                
                # Check if discovered IPs are already in database
                existing_hosts = {host['ip_address']: host for host in self.host_manager.get_all_hosts()}
                
                for ip in discovered_ips:
                    if ip not in existing_hosts and ip != scanning_host['ip_address']:
                        self._update_progress(f"Discovered new host: {ip}")
                        # Could optionally auto-add discovered hosts
                        # For now, just log them
        
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # Fallback to ping sweep
            self._ping_sweep(scanning_host, network)
    
    def _parse_nmap_discovery(self, nmap_output):
        """Parse nmap host discovery output"""
        ips = []
        for line in nmap_output.split('\n'):
            if 'Nmap scan report for' in line:
                parts = line.split()
                if len(parts) >= 5 and parts[-1].startswith('(') and parts[-1].endswith(')'):
                    ip = parts[-1][1:-1]  # Remove parentheses
                    ips.append(ip)
                elif len(parts) >= 5:
                    ip = parts[4]
                    ips.append(ip)
        return ips
    
    def _ping_sweep(self, scanning_host, network):
        """Perform ping sweep of network from scanning host"""
        self._update_progress(f"Performing ping sweep of {network} from {scanning_host['name']}")
        
        # Generate list of IPs to ping (limit to reasonable size)
        if network.num_addresses > 254:
            return  # Skip very large networks
        
        ips_to_ping = [str(ip) for ip in network.hosts()][:50]  # Limit to first 50 IPs
        
        # Use parallel ping from remote host
        ping_commands = []
        for ip in ips_to_ping:
            ping_commands.append(f"ping -c 1 -W 1 {ip} >/dev/null 2>&1 && echo {ip}")
        
        command = '; '.join(ping_commands)
        result, error = self.host_manager.execute_command(scanning_host, command, timeout=30)
        
        if result and result['success']:
            discovered_ips = [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
            existing_hosts = {host['ip_address']: host for host in self.host_manager.get_all_hosts()}
            
            for ip in discovered_ips:
                if ip not in existing_hosts and ip != scanning_host['ip_address']:
                    self._update_progress(f"Discovered new host via ping: {ip}")
    
    def scan_all_hosts(self):
        """Scan all registered hosts"""
        hosts = self.host_manager.get_all_hosts()
        
        for host in hosts:
            try:
                self.scan_host(host)
                time.sleep(2)  # Brief pause between hosts
            except Exception as e:
                print(f"Error scanning host {host['name']}: {e}")
    
    def get_network_topology(self):
        """Generate network topology data for visualization"""
        hosts = self.host_manager.get_all_hosts()
        connections = self.db.get_recent_connections(hours=24)
        
        # Create nodes and edges for network graph
        nodes = []
        edges = []
        
        for host in hosts:
            nodes.append({
                'id': host['id'],
                'label': host['name'],
                'ip': host['ip_address'],
                'status': host.get('status', 'unknown'),
                'group': self._determine_host_group(host)
            })
        
        for conn in connections:
            if conn['source_host_id'] and conn['dest_host_id']:
                edges.append({
                    'from': conn['source_host_id'],
                    'to': conn['dest_host_id'],
                    'label': f":{conn['dest_port']}",
                    'title': f"{conn['protocol'].upper()} connection to port {conn['dest_port']}\nConnections: {conn['connection_count']}"
                })
        
        return {'nodes': nodes, 'edges': edges}
    
    def _determine_host_group(self, host):
        """Determine host group for visualization coloring"""
        ip = host['ip_address']
        
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            
            if ip_obj.is_private:
                if ip.startswith('192.168.'):
                    return 'local'
                elif ip.startswith('10.'):
                    return 'corporate'
                elif ip.startswith('172.'):
                    return 'private'
            else:
                return 'internet'
        except ipaddress.AddressValueError:
            return 'unknown'
        
        return 'local'
