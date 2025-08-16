#!/usr/bin/env python3
"""
Enhanced Topology Builder
Comprehensive network topology analysis and visualization data generator.

This module processes enhanced network scan data to create rich topology information
including server interconnections, protocol analysis, internet services mapping,
and device role classification.
"""

import json
import ipaddress
import re
from typing import Dict, List, Any, Tuple, Set, Optional
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import socket
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedTopologyBuilder:
    """
    Enhanced Network Topology Builder
    
    Creates comprehensive network topology data from enhanced scan results,
    including device classification, protocol analysis, and interconnection mapping.
    """
    
    def __init__(self, db_manager, host_manager):
        self.db = db_manager
        self.host_manager = host_manager
        
        # Network classification patterns
        self.private_ranges = [
            ipaddress.IPv4Network('192.168.0.0/16'),
            ipaddress.IPv4Network('10.0.0.0/8'),
            ipaddress.IPv4Network('172.16.0.0/12')
        ]
        
        self.cgnat_ranges = [
            ipaddress.IPv4Network('100.64.0.0/10')
        ]
        
        # Port to service mapping
        self.port_services = {
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
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb',
            3389: 'rdp',
            5900: 'vnc'
        }
        
        # Known cloud/internet service domains and IPs
        self.internet_services = {
            'google.com': 'search',
            'googleapis.com': 'api',
            'amazonaws.com': 'cloud',
            'azure.com': 'cloud',
            'cloudfront.net': 'cdn',
            'github.com': 'development',
            'stackoverflow.com': 'development',
            'docker.com': 'containerization',
            'ubuntu.com': 'os',
            'cloudflare.com': 'dns/cdn'
        }
        
    def build_comprehensive_topology(self) -> Dict[str, Any]:
        """
        Build comprehensive network topology from all available data sources.
        
        Returns:
            Dict containing nodes, edges, and analysis metadata
        """
        logger.info("Building comprehensive network topology...")
        
        try:
            # Gather all data sources
            hosts = self.host_manager.get_all_hosts()
            enhanced_scan_data = self._get_enhanced_scan_data()
            network_connections = self._get_network_connections()
            
            # Build topology components
            nodes = self._build_nodes(hosts, enhanced_scan_data)
            edges = self._build_edges(network_connections, enhanced_scan_data, nodes)
            
            # Enhance with analysis
            nodes = self._enhance_nodes_with_analysis(nodes, edges)
            edges = self._enhance_edges_with_analysis(edges, nodes)
            
            # Add internet and cloud services
            internet_nodes, internet_edges = self._discover_internet_services(enhanced_scan_data)
            nodes.extend(internet_nodes)
            edges.extend(internet_edges)
            
            # Generate statistics
            statistics = self._generate_topology_statistics(nodes, edges)
            
            topology = {
                'nodes': nodes,
                'edges': edges,
                'statistics': statistics,
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'data_sources': ['hosts', 'enhanced_scans', 'network_connections'],
                    'total_nodes': len(nodes),
                    'total_edges': len(edges)
                }
            }
            
            # Store topology analysis in database
            self._store_topology_analysis(topology)
            
            logger.info(f"Generated comprehensive topology: {len(nodes)} nodes, {len(edges)} edges")
            return topology
            
        except Exception as e:
            logger.error(f"Error building comprehensive topology: {str(e)}")
            return self._get_fallback_topology()
    
    def _get_enhanced_scan_data(self) -> List[Dict]:
        """Retrieve enhanced scan data from database."""
        try:
            # Try to get enhanced scan results table first
            query = """
                SELECT host_id, scan_type, scan_data, created_at
                FROM enhanced_scan_results 
                WHERE created_at > ? 
                ORDER BY created_at DESC
            """
            
            cutoff_date = (datetime.now() - timedelta(hours=24)).isoformat()
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.execute(query, (cutoff_date,))
                    results = [dict(row) for row in cursor.fetchall()]
            except:
                # Fallback to empty list if table doesn't exist
                results = []
            
            scan_data = []
            for result in results:
                try:
                    data = json.loads(result['scan_data'])
                    data['host_id'] = result['host_id']
                    data['scan_type'] = result['scan_type']
                    data['scan_time'] = result['created_at']
                    scan_data.append(data)
                except (json.JSONDecodeError, KeyError):
                    continue
            
            return scan_data
            
        except Exception as e:
            logger.warning(f"Error retrieving enhanced scan data: {str(e)}")
            return []
    
    def _get_network_connections(self) -> List[Dict]:
        """Retrieve network connection data from database."""
        try:
            query = """
                SELECT source_host_id, dest_host_id, dest_ip, dest_port, 
                       protocol, connection_count, first_seen, last_seen
                FROM network_connections 
                WHERE last_seen > ? 
                ORDER BY connection_count DESC
            """
            
            cutoff_date = (datetime.now() - timedelta(hours=24)).isoformat()
            
            try:
                with self.db.get_connection() as conn:
                    cursor = conn.execute(query, (cutoff_date,))
                    return [dict(row) for row in cursor.fetchall()]
            except:
                return []
            
        except Exception as e:
            logger.warning(f"Error retrieving network connections: {str(e)}")
            return []
    
    def _build_nodes(self, hosts: List[Dict], scan_data: List[Dict]) -> List[Dict]:
        """Build comprehensive node list with enhanced attributes."""
        nodes = []
        scan_data_by_host = defaultdict(list)
        
        # Group scan data by host
        for data in scan_data:
            scan_data_by_host[data.get('host_id')].append(data)
        
        for host in hosts:
            host_scan_data = scan_data_by_host.get(host['id'], [])
            
            # Determine device type and role
            device_type, device_subtype = self._classify_device(host, host_scan_data)
            
            # Extract services and protocols
            services = self._extract_services(host_scan_data)
            protocols = self._extract_protocols(host_scan_data)
            
            # Classify network group
            network_group = self._classify_network_group(host['ip_address'])
            
            # Determine status
            status = self._determine_node_status(host, host_scan_data)
            
            node = {
                'id': str(host['id']),
                'label': host['name'],
                'ip': host['ip_address'],
                'type': device_type,
                'subtype': device_subtype,
                'status': status,
                'group': network_group,
                'protocols': protocols,
                'services': services,
                'connections': 0,  # Will be calculated later
                'metadata': {
                    'hostname': host.get('hostname', ''),
                    'os': self._detect_os(host_scan_data),
                    'last_seen': host.get('last_seen').isoformat() if host.get('last_seen') else None,
                    'scan_count': len(host_scan_data),
                    'open_ports': self._get_open_ports(host_scan_data)
                }
            }
            
            nodes.append(node)
        
        return nodes
    
    def _build_edges(self, connections: List[Dict], scan_data: List[Dict], nodes: List[Dict]) -> List[Dict]:
        """Build comprehensive edge list with enhanced attributes."""
        edges = []
        node_lookup = {node['id']: node for node in nodes}
        
        for conn in connections:
            source_id = str(conn['source_host_id'])
            dest_id = str(conn.get('dest_host_id', ''))
            
            # Skip if we don't have the source node
            if source_id not in node_lookup:
                continue
            
            # Handle external connections
            if not dest_id or dest_id not in node_lookup:
                # Create external node if needed
                external_node = self._create_external_node(conn.get('dest_ip', ''))
                if external_node:
                    nodes.append(external_node)
                    node_lookup[external_node['id']] = external_node
                    dest_id = external_node['id']
                else:
                    continue
            
            # Determine connection type and security
            conn_type = self._classify_connection_type(conn)
            security_level = self._assess_connection_security(conn)
            
            # Get protocol details
            protocol = conn.get('protocol', 'tcp').lower()
            port = conn.get('dest_port', 0)
            
            edge = {
                'id': f"{source_id}-{dest_id}-{port}",
                'from': source_id,
                'to': dest_id,
                'type': conn_type,
                'protocol': protocol,
                'port': port,
                'label': self._get_service_label(port, protocol),
                'weight': conn.get('connection_count', 1),
                'bandwidth': self._estimate_bandwidth(conn),
                'security_level': security_level,
                'metadata': {
                    'first_seen': conn.get('first_seen'),
                    'last_seen': conn.get('last_seen'),
                    'connection_count': conn.get('connection_count', 1)
                }
            }
            
            edges.append(edge)
        
        return edges
    
    def _classify_device(self, host: Dict, scan_data: List[Dict]) -> Tuple[str, str]:
        """Classify device type and subtype based on host data and scans."""
        # Default classification - assume server unless we have evidence otherwise
        device_type = 'server'
        device_subtype = 'unknown'
        
        # Check for specific indicators in scan data
        open_ports = self._get_open_ports(scan_data)
        services = self._extract_services(scan_data)
        
        # If we have open ports data, use it for classification
        if open_ports:
            # Database server indicators
            if any(port in [3306, 5432, 1521, 27017, 6379] for port in open_ports):
                device_type = 'server'
                device_subtype = 'database'
            
            # Web server indicators
            elif any(port in [80, 443, 8080, 8443] for port in open_ports):
                device_type = 'server'
                device_subtype = 'web'
            
            # Mail server indicators
            elif any(port in [25, 110, 143, 993, 995] for port in open_ports):
                device_type = 'server'
                device_subtype = 'mail'
            
            # DNS server indicators
            elif 53 in open_ports:
                device_type = 'server'
                device_subtype = 'dns'
            
            # Router/Gateway indicators (check services first)
            elif any(service in ['router', 'gateway'] for service in services):
                device_type = 'router'
                device_subtype = 'gateway'
            
            # Workstation indicators (few ports, no server services, all high ports)
            elif len(open_ports) < 3 and all(port > 1024 for port in open_ports):
                device_type = 'workstation'
                device_subtype = 'client'
            
            # Server with unidentified services
            else:
                device_type = 'server'
                device_subtype = 'general'
        
        # If no open ports data available, use name/hostname hints
        else:
            hostname = host.get('name', '').lower()
            if any(keyword in hostname for keyword in ['server', 'srv', 'app', 'web', 'db', 'mail', 'dns']):
                device_type = 'server'
                device_subtype = 'general'
            elif any(keyword in hostname for keyword in ['router', 'gateway', 'gw']):
                device_type = 'router'
                device_subtype = 'gateway'
            # Default: assume it's a server if we don't know
            else:
                device_type = 'server'
                device_subtype = 'general'
        
        return device_type, device_subtype
    
    def _classify_network_group(self, ip_address: str) -> str:
        """Classify network group based on IP address."""
        try:
            ip = ipaddress.IPv4Address(ip_address)
            
            # Check private ranges
            for network in self.private_ranges:
                if ip in network:
                    if network == ipaddress.IPv4Network('192.168.0.0/16'):
                        return 'local'
                    elif network == ipaddress.IPv4Network('10.0.0.0/8'):
                        return 'corporate'
                    else:
                        return 'private'
            
            # Check CGNAT
            for network in self.cgnat_ranges:
                if ip in network:
                    return 'cgnat'
            
            # Public IP
            return 'internet'
            
        except ipaddress.AddressValueError:
            return 'unknown'
    
    def _extract_services(self, scan_data: List[Dict]) -> List[str]:
        """Extract detected services from scan data."""
        services = set()
        
        for data in scan_data:
            if 'open_ports' in data:
                for port_info in data['open_ports']:
                    if isinstance(port_info, dict) and 'service' in port_info:
                        services.add(port_info['service'])
            
            if 'services' in data:
                services.update(data['services'])
        
        return list(services)
    
    def _extract_protocols(self, scan_data: List[Dict]) -> List[str]:
        """Extract detected protocols from scan data."""
        protocols = set()
        
        for data in scan_data:
            if 'protocols' in data:
                protocols.update(data['protocols'])
            
            if 'network_connections' in data:
                for conn in data['network_connections']:
                    if 'protocol' in conn:
                        protocols.add(conn['protocol'])
        
        return list(protocols)
    
    def _get_open_ports(self, scan_data: List[Dict]) -> List[int]:
        """Get list of open ports from scan data."""
        ports = set()
        
        for data in scan_data:
            if 'open_ports' in data:
                for port_info in data['open_ports']:
                    if isinstance(port_info, dict) and 'port' in port_info:
                        ports.add(port_info['port'])
                    elif isinstance(port_info, int):
                        ports.add(port_info)
        
        return list(ports)
    
    def _detect_os(self, scan_data: List[Dict]) -> str:
        """Detect operating system from scan data."""
        for data in scan_data:
            if 'os_detection' in data and data['os_detection']:
                return data['os_detection']
            
            if 'system_info' in data and 'os' in data['system_info']:
                return data['system_info']['os']
        
        return 'unknown'
    
    def _determine_node_status(self, host: Dict, scan_data: List[Dict]) -> str:
        """Determine node status based on host data and recent scans."""
        # Check if we have recent scan data
        if scan_data:
            recent_scan = max(scan_data, key=lambda x: x.get('scan_time', ''))
            try:
                scan_time = datetime.fromisoformat(recent_scan['scan_time'].replace('Z', '+00:00'))
                if datetime.now() - scan_time.replace(tzinfo=None) < timedelta(hours=1):
                    return 'online'
                elif datetime.now() - scan_time.replace(tzinfo=None) < timedelta(hours=6):
                    return 'warning'
                else:
                    return 'offline'
            except:
                pass
        
        # Fallback to host status
        return host.get('status', 'unknown')
    
    def _create_external_node(self, ip_address: str) -> Optional[Dict]:
        """Create node for external IP address."""
        if not ip_address:
            return None
        
        try:
            # Try to resolve hostname
            hostname = self._reverse_dns_lookup(ip_address)
            
            # Classify as internet service
            service_type = self._classify_internet_service(ip_address, hostname)
            
            node = {
                'id': f"ext_{ip_address.replace('.', '_')}",
                'label': hostname or ip_address,
                'ip': ip_address,
                'type': 'internet' if self._is_public_ip(ip_address) else 'external',
                'subtype': service_type,
                'status': 'unknown',
                'group': 'internet' if self._is_public_ip(ip_address) else 'external',
                'protocols': [],
                'services': [service_type] if service_type != 'unknown' else [],
                'connections': 0,
                'metadata': {
                    'hostname': hostname,
                    'resolved_at': datetime.now().isoformat()
                }
            }
            
            return node
            
        except Exception as e:
            logger.warning(f"Error creating external node for {ip_address}: {str(e)}")
            return None
    
    def _reverse_dns_lookup(self, ip_address: str) -> Optional[str]:
        """Perform reverse DNS lookup for IP address."""
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except:
            return None
    
    def _is_public_ip(self, ip_address: str) -> bool:
        """Check if IP address is public."""
        try:
            ip = ipaddress.IPv4Address(ip_address)
            return ip.is_global
        except:
            return False
    
    def _classify_internet_service(self, ip_address: str, hostname: str = None) -> str:
        """Classify internet service type."""
        if hostname:
            hostname_lower = hostname.lower()
            for domain, service_type in self.internet_services.items():
                if domain in hostname_lower:
                    return service_type
        
        # Default classification
        return 'unknown'
    
    def _classify_connection_type(self, connection: Dict) -> str:
        """Classify connection type based on connection data."""
        protocol = connection.get('protocol', '').lower()
        port = connection.get('dest_port', 0)
        
        if protocol in ['tcp', 'udp']:
            if port in [80, 443, 8080, 8443]:
                return 'web'
            elif port == 22:
                return 'ssh'
            elif port in [25, 110, 143, 993, 995]:
                return 'mail'
            elif port in [3306, 5432, 1521, 27017]:
                return 'database'
            elif port == 53:
                return 'dns'
        
        return protocol or 'unknown'
    
    def _assess_connection_security(self, connection: Dict) -> str:
        """Assess connection security level."""
        protocol = connection.get('protocol', '').lower()
        port = connection.get('dest_port', 0)
        
        # High security (encrypted protocols)
        if port in [22, 443, 993, 995] or 'ssl' in protocol or 'tls' in protocol:
            return 'high'
        
        # Low security (unencrypted protocols)
        elif port in [23, 21, 80, 110, 143] or protocol in ['telnet', 'ftp', 'http']:
            return 'low'
        
        # Medium security (other protocols)
        return 'medium'
    
    def _get_service_label(self, port: int, protocol: str) -> str:
        """Get service label for port/protocol combination."""
        if port in self.port_services:
            return f"{self.port_services[port]}:{port}"
        else:
            return f"{protocol}:{port}"
    
    def _estimate_bandwidth(self, connection: Dict) -> str:
        """Estimate bandwidth usage for connection."""
        count = connection.get('connection_count', 1)
        
        if count > 1000:
            return 'high'
        elif count > 100:
            return 'medium'
        else:
            return 'low'
    
    def _enhance_nodes_with_analysis(self, nodes: List[Dict], edges: List[Dict]) -> List[Dict]:
        """Enhance nodes with connection analysis and role classification."""
        # Count connections per node
        connection_counts = defaultdict(int)
        for edge in edges:
            connection_counts[edge['from']] += 1
            connection_counts[edge['to']] += 1
        
        # Update nodes with connection counts
        for node in nodes:
            node['connections'] = connection_counts.get(node['id'], 0)
        
        return nodes
    
    def _enhance_edges_with_analysis(self, edges: List[Dict], nodes: List[Dict]) -> List[Dict]:
        """Enhance edges with traffic analysis and security assessment."""
        # Currently just return edges as-is
        return edges
    
    def _discover_internet_services(self, scan_data: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
        """Discover and categorize internet services from scan data."""
        # For now, return empty lists
        return [], []
    
    def _generate_topology_statistics(self, nodes: List[Dict], edges: List[Dict]) -> Dict[str, Any]:
        """Generate comprehensive topology statistics."""
        # Node statistics
        node_types = Counter(node['type'] for node in nodes)
        node_statuses = Counter(node['status'] for node in nodes)
        network_groups = Counter(node['group'] for node in nodes)
        
        # Edge statistics
        protocols = Counter(edge['protocol'] for edge in edges)
        security_levels = Counter(edge['security_level'] for edge in edges)
        connection_types = Counter(edge['type'] for edge in edges)
        
        # Connection analysis
        total_weight = sum(edge.get('weight', 1) for edge in edges)
        avg_connections_per_node = len(edges) / len(nodes) if nodes else 0
        
        # Security analysis
        insecure_connections = len([e for e in edges if e['security_level'] == 'low'])
        secure_connections = len([e for e in edges if e['security_level'] == 'high'])
        
        return {
            'node_summary': {
                'total': len(nodes),
                'by_type': dict(node_types),
                'by_status': dict(node_statuses),
                'by_group': dict(network_groups)
            },
            'edge_summary': {
                'total': len(edges),
                'by_protocol': dict(protocols),
                'by_security': dict(security_levels),
                'by_type': dict(connection_types),
                'total_weight': total_weight
            },
            'analysis': {
                'avg_connections_per_node': round(avg_connections_per_node, 2),
                'security_ratio': {
                    'secure': secure_connections,
                    'insecure': insecure_connections,
                    'percentage_secure': round(secure_connections / len(edges) * 100, 1) if edges else 0
                },
                'internet_connectivity': len([n for n in nodes if n['group'] == 'internet']),
                'internal_servers': len([n for n in nodes if n['type'] == 'server' and n['group'] != 'internet'])
            }
        }
    
    def _store_topology_analysis(self, topology: Dict[str, Any]) -> None:
        """Store topology analysis in database."""
        try:
            # Use the database's save_topology_analysis method (it handles JSON encoding)
            self.db.save_topology_analysis('enhanced_topology', topology)
            
            logger.info("Topology analysis stored in database")
            
        except Exception as e:
            logger.error(f"Error storing topology analysis: {str(e)}")
    
    def _get_fallback_topology(self) -> Dict[str, Any]:
        """Get fallback topology when main build fails."""
        try:
            hosts = self.host_manager.get_all_hosts()
            connections = self._get_network_connections()
            
            # Simple topology with basic nodes and edges
            nodes = []
            for host in hosts:
                nodes.append({
                    'id': str(host['id']),
                    'label': host['name'],
                    'ip': host['ip_address'],
                    'type': 'server',
                    'subtype': 'unknown',
                    'status': host.get('status', 'unknown'),
                    'group': self._classify_network_group(host['ip_address']),
                    'protocols': [],
                    'services': [],
                    'connections': 0
                })
            
            edges = []
            for conn in connections[:50]:  # Limit for fallback
                if conn.get('dest_host_id'):
                    edges.append({
                        'id': f"{conn['source_host_id']}-{conn.get('dest_host_id')}",
                        'from': str(conn['source_host_id']),
                        'to': str(conn.get('dest_host_id')),
                        'type': 'tcp',
                        'protocol': conn.get('protocol', 'tcp'),
                        'port': conn.get('dest_port', 0),
                        'label': f":{conn.get('dest_port', 0)}",
                        'weight': conn.get('connection_count', 1),
                        'bandwidth': 'unknown',
                        'security_level': 'medium'
                    })
            
            return {
                'nodes': nodes,
                'edges': edges,
                'statistics': {},
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'fallback': True
                }
            }
            
        except Exception as e:
            logger.error(f"Error creating fallback topology: {str(e)}")
            return {
                'nodes': [],
                'edges': [],
                'statistics': {},
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'error': str(e)
                }
            }
