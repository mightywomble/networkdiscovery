#!/usr/bin/env python3
"""
Network Topology Analyzer
Processes comprehensive network discovery data to build detailed topology insights
"""

import json
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import re

class TopologyAnalyzer:
    def __init__(self, database):
        self.db = database
        
    def analyze_network_topology(self):
        """Analyze all collected data to build comprehensive topology"""
        print("Analyzing network topology from collected data...")
        
        # Get all discovery data
        discovery_data = self._get_all_discovery_data()
        
        # Build comprehensive analysis
        topology = {
            'network_segments': self._identify_network_segments(discovery_data),
            'device_roles': self._classify_device_roles(discovery_data),
            'interconnections': self._map_interconnections(discovery_data),
            'traffic_patterns': self._analyze_traffic_patterns(discovery_data),
            'infrastructure_map': self._build_infrastructure_map(discovery_data),
            'security_zones': self._identify_security_zones(discovery_data),
            'performance_insights': self._analyze_performance_data(discovery_data)
        }
        
        # Store topology analysis results
        self._store_topology_analysis(topology)
        
        return topology
    
    def _get_all_discovery_data(self):
        """Retrieve all network discovery data from database"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('''
                SELECT h.id, h.name, h.ip_address, h.status, 
                       ndd.discovery_type, ndd.data_json, ndd.timestamp
                FROM hosts h
                LEFT JOIN network_discovery_data ndd ON h.id = ndd.host_id
                ORDER BY h.id, ndd.timestamp DESC
            ''')
            
            discovery_data = defaultdict(dict)
            for row in cursor.fetchall():
                host_data = {
                    'id': row['id'],
                    'name': row['name'],
                    'ip_address': row['ip_address'],
                    'status': row['status']
                }
                
                if row['discovery_type'] and row['data_json']:
                    try:
                        parsed_data = json.loads(row['data_json'])
                        discovery_data[row['id']][row['discovery_type']] = parsed_data
                    except json.JSONDecodeError:
                        continue
                
                discovery_data[row['id']]['host_info'] = host_data
            
            return dict(discovery_data)
    
    def _identify_network_segments(self, discovery_data):
        """Identify distinct network segments and their characteristics"""
        segments = {}
        segment_hosts = defaultdict(list)
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            routing_info = data.get('routing_table', {})
            interface_info = data.get('network_interfaces', {})
            
            # Extract networks from routing table
            ipv4_routes = routing_info.get('ipv4', [])
            for route in ipv4_routes:
                destination = route.get('destination')
                if destination and '/' in destination:
                    try:
                        network = ipaddress.IPv4Network(destination, strict=False)
                        if network.is_private:
                            segment_key = str(network.network_address) + '/' + str(network.prefixlen)
                            
                            if segment_key not in segments:
                                segments[segment_key] = {
                                    'network': str(network),
                                    'type': self._classify_network_type(network),
                                    'hosts': [],
                                    'gateways': set(),
                                    'subnets': set()
                                }
                            
                            segments[segment_key]['hosts'].append({
                                'host_id': host_id,
                                'name': host_info.get('name'),
                                'ip': host_info.get('ip_address')
                            })
                            
                            if route.get('gateway'):
                                segments[segment_key]['gateways'].add(route['gateway'])
                                
                    except (ipaddress.AddressValueError, ValueError):
                        continue
            
            # Extract networks from interfaces
            interfaces = interface_info.get('interfaces', {})
            if isinstance(interfaces, dict) and 'raw_output' not in interfaces:
                for interface_data in interfaces:
                    if isinstance(interface_data, dict):
                        addresses = interface_data.get('addresses', [])
                        for addr in addresses:
                            if '/' in addr:
                                try:
                                    network = ipaddress.IPv4Network(addr, strict=False)
                                    if network.is_private:
                                        segment_key = str(network.supernet(new_prefix=24))
                                        segment_hosts[segment_key].append(host_id)
                                except:
                                    continue
        
        # Convert sets to lists for JSON serialization
        for segment in segments.values():
            segment['gateways'] = list(segment['gateways'])
            segment['subnets'] = list(segment['subnets'])
        
        return segments
    
    def _classify_device_roles(self, discovery_data):
        """Classify devices based on their network roles"""
        device_roles = {}
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            roles = []
            confidence = {}
            
            # Analyze routing data
            routing_data = data.get('routing_table', {})
            if routing_data.get('default_gateway'):
                roles.append('router')
                confidence['router'] = 0.7
            
            # Analyze listening services
            services = data.get('listening_services', [])
            service_analysis = self._analyze_services(services)
            roles.extend(service_analysis['roles'])
            confidence.update(service_analysis['confidence'])
            
            # Analyze DHCP data
            dhcp_data = data.get('dhcp_leases', [])
            if dhcp_data:
                roles.append('dhcp_server')
                confidence['dhcp_server'] = 0.9
            
            # Analyze DNS data
            dns_data = data.get('dns_info', {})
            if dns_data.get('dns_cache') or any('bind' in str(dns_data).lower() for d in dns_data.values() if d):
                roles.append('dns_server')
                confidence['dns_server'] = 0.8
            
            # Analyze bridge/switch data
            bridge_data = data.get('bridge_info', [])
            if bridge_data:
                roles.append('bridge_switch')
                confidence['bridge_switch'] = 0.8
            
            # Analyze wireless data
            wireless_data = data.get('wireless_info', {})
            if wireless_data.get('hostapd_status') or 'hostapd' in str(wireless_data):
                roles.append('wireless_access_point')
                confidence['wireless_access_point'] = 0.9
            
            # Analyze firewall data
            firewall_data = data.get('firewall_rules', {})
            if any(fw_data for fw_data in firewall_data.values() if fw_data and 'DROP' in fw_data):
                roles.append('firewall')
                confidence['firewall'] = 0.7
            
            # Analyze topology hints
            topology_hints = data.get('topology_hints', {})
            hint_roles = self._extract_roles_from_hints(topology_hints)
            roles.extend(hint_roles['roles'])
            confidence.update(hint_roles['confidence'])
            
            device_roles[host_id] = {
                'host_info': host_info,
                'roles': list(set(roles)),
                'confidence': confidence,
                'primary_role': self._determine_primary_role(roles, confidence)
            }
        
        return device_roles
    
    def _map_interconnections(self, discovery_data):
        """Map network interconnections between devices"""
        interconnections = []
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            
            # Analyze ARP table for direct connections
            arp_table = data.get('arp_table', [])
            for arp_entry in arp_table:
                if arp_entry.get('ip') and arp_entry.get('mac'):
                    # Find if this IP belongs to another monitored host
                    target_host = self._find_host_by_ip(arp_entry['ip'], discovery_data)
                    if target_host:
                        interconnections.append({
                            'type': 'layer2',
                            'source_host_id': host_id,
                            'target_host_id': target_host['id'],
                            'source_ip': host_info.get('ip_address'),
                            'target_ip': arp_entry['ip'],
                            'mac_address': arp_entry['mac'],
                            'interface': arp_entry.get('interface'),
                            'evidence': 'arp_table'
                        })
            
            # Analyze routing table for network paths
            routing_data = data.get('routing_table', {})
            for route in routing_data.get('ipv4', []):
                if route.get('gateway'):
                    target_host = self._find_host_by_ip(route['gateway'], discovery_data)
                    if target_host:
                        interconnections.append({
                            'type': 'layer3',
                            'source_host_id': host_id,
                            'target_host_id': target_host['id'],
                            'source_ip': host_info.get('ip_address'),
                            'target_ip': route['gateway'],
                            'network': route.get('destination'),
                            'interface': route.get('interface'),
                            'metric': route.get('metric'),
                            'evidence': 'routing_table'
                        })
            
            # Analyze active connections
            connections = data.get('active_connections', {})
            for conn_type, conn_list in connections.items():
                if isinstance(conn_list, list):
                    for conn in conn_list:
                        remote_addr = conn.get('remote_address', '')
                        if ':' in remote_addr:
                            remote_ip = remote_addr.split(':')[0]
                            target_host = self._find_host_by_ip(remote_ip, discovery_data)
                            if target_host:
                                interconnections.append({
                                    'type': 'application',
                                    'source_host_id': host_id,
                                    'target_host_id': target_host['id'],
                                    'source_address': conn.get('local_address'),
                                    'target_address': remote_addr,
                                    'protocol': conn.get('protocol'),
                                    'state': conn.get('state'),
                                    'process': conn.get('process'),
                                    'evidence': 'active_connection'
                                })
        
        return interconnections
    
    def _analyze_traffic_patterns(self, discovery_data):
        """Analyze traffic patterns and usage"""
        traffic_patterns = {}
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            
            # Analyze bandwidth usage
            bandwidth_data = data.get('bandwidth_usage', {})
            interface_stats = self._parse_interface_bytes(bandwidth_data.get('interface_bytes', ''))
            
            # Analyze network statistics
            net_stats = data.get('network_statistics', {})
            interface_dev_stats = self._parse_proc_net_dev(net_stats.get('interface_stats', ''))
            
            # Combine traffic data
            traffic_patterns[host_id] = {
                'host_info': host_info,
                'interface_stats': interface_stats,
                'traffic_summary': interface_dev_stats,
                'bandwidth_sample': bandwidth_data.get('sample_traffic', '')[:500],  # Limit size
                'analysis': self._analyze_host_traffic_role(interface_stats, interface_dev_stats)
            }
        
        return traffic_patterns
    
    def _build_infrastructure_map(self, discovery_data):
        """Build comprehensive infrastructure map"""
        infrastructure = {
            'network_layers': {
                'physical': [],
                'data_link': [],
                'network': [],
                'application': []
            },
            'critical_infrastructure': [],
            'network_services': [],
            'security_devices': []
        }
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            
            # Physical layer analysis
            interface_data = data.get('network_interfaces', {})
            physical_info = self._extract_physical_info(interface_data)
            if physical_info:
                infrastructure['network_layers']['physical'].append({
                    'host_id': host_id,
                    'host_info': host_info,
                    'physical_interfaces': physical_info
                })
            
            # Data link layer analysis
            bridge_data = data.get('bridge_info', [])
            vlan_data = data.get('vlan_info', [])
            if bridge_data or vlan_data:
                infrastructure['network_layers']['data_link'].append({
                    'host_id': host_id,
                    'host_info': host_info,
                    'bridges': bridge_data,
                    'vlans': vlan_data
                })
            
            # Network layer analysis
            routing_data = data.get('routing_table', {})
            if routing_data.get('ipv4') or routing_data.get('ipv6'):
                infrastructure['network_layers']['network'].append({
                    'host_id': host_id,
                    'host_info': host_info,
                    'routing_info': routing_data
                })
            
            # Identify critical infrastructure
            roles = self._get_host_roles(data)
            if any(role in ['router', 'dhcp_server', 'dns_server'] for role in roles):
                infrastructure['critical_infrastructure'].append({
                    'host_id': host_id,
                    'host_info': host_info,
                    'roles': roles,
                    'criticality': self._assess_criticality(roles, data)
                })
        
        return infrastructure
    
    def _identify_security_zones(self, discovery_data):
        """Identify security zones and trust boundaries"""
        security_zones = {
            'dmz_hosts': [],
            'internal_hosts': [],
            'management_hosts': [],
            'guest_networks': [],
            'trust_boundaries': []
        }
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            host_ip = host_info.get('ip_address', '')
            
            # Classify based on IP ranges
            try:
                ip_obj = ipaddress.IPv4Address(host_ip)
                if str(ip_obj).startswith('192.168.'):
                    zone = 'internal_hosts'
                elif str(ip_obj).startswith('10.'):
                    zone = 'management_hosts'
                elif str(ip_obj).startswith('172.'):
                    zone = 'internal_hosts'
                else:
                    zone = 'dmz_hosts'
                
                security_zones[zone].append({
                    'host_id': host_id,
                    'host_info': host_info,
                    'ip_address': host_ip
                })
            except:
                continue
            
            # Analyze firewall rules for trust boundaries
            firewall_data = data.get('firewall_rules', {})
            if firewall_data:
                boundaries = self._analyze_firewall_boundaries(firewall_data, host_info)
                security_zones['trust_boundaries'].extend(boundaries)
        
        return security_zones
    
    def _analyze_performance_data(self, discovery_data):
        """Analyze network performance characteristics"""
        performance = {}
        
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            
            # Analyze interface statistics
            net_stats = data.get('network_statistics', {})
            interface_stats = net_stats.get('interface_stats', '')
            
            # Parse performance metrics
            performance_metrics = self._extract_performance_metrics(interface_stats)
            
            # Analyze packet drops and errors
            packet_analysis = self._analyze_packet_statistics(net_stats)
            
            performance[host_id] = {
                'host_info': host_info,
                'performance_metrics': performance_metrics,
                'packet_analysis': packet_analysis,
                'health_score': self._calculate_health_score(performance_metrics, packet_analysis)
            }
        
        return performance
    
    # Helper methods for analysis
    def _classify_network_type(self, network):
        """Classify network type based on address range"""
        if str(network).startswith('192.168.'):
            return 'home_network'
        elif str(network).startswith('10.'):
            return 'corporate_network'
        elif str(network).startswith('172.'):
            return 'private_network'
        elif network.is_link_local:
            return 'link_local'
        else:
            return 'unknown'
    
    def _analyze_services(self, services):
        """Analyze listening services to determine roles"""
        roles = []
        confidence = {}
        
        for service in services:
            port = service.get('port', '')
            protocol = service.get('protocol', '')
            
            # Common service port mappings
            if port == '53':
                roles.append('dns_server')
                confidence['dns_server'] = 0.9
            elif port == '67' or port == '68':
                roles.append('dhcp_server')
                confidence['dhcp_server'] = 0.9
            elif port == '80' or port == '443':
                roles.append('web_server')
                confidence['web_server'] = 0.8
            elif port == '22':
                roles.append('ssh_server')
                confidence['ssh_server'] = 0.7
            elif port == '21':
                roles.append('ftp_server')
                confidence['ftp_server'] = 0.8
            elif port == '25' or port == '587':
                roles.append('mail_server')
                confidence['mail_server'] = 0.8
        
        return {'roles': roles, 'confidence': confidence}
    
    def _extract_roles_from_hints(self, topology_hints):
        """Extract device roles from topology hints"""
        roles = []
        confidence = {}
        
        system_role = topology_hints.get('system_role', '')
        running_services = topology_hints.get('running_services', '')
        routing_daemons = topology_hints.get('routing_daemons', '')
        
        if 'dhcp' in system_role.lower() or 'dhcp' in running_services.lower():
            roles.append('dhcp_server')
            confidence['dhcp_server'] = 0.9
        
        if 'dns' in system_role.lower() or 'dns' in running_services.lower():
            roles.append('dns_server')
            confidence['dns_server'] = 0.9
        
        if routing_daemons.strip():
            roles.append('router')
            confidence['router'] = 0.9
        
        return {'roles': roles, 'confidence': confidence}
    
    def _determine_primary_role(self, roles, confidence):
        """Determine primary role based on confidence scores"""
        if not roles:
            return 'unknown'
        
        if not confidence:
            return roles[0]
        
        # Return role with highest confidence
        primary_role = max(confidence.items(), key=lambda x: x[1])
        return primary_role[0]
    
    def _find_host_by_ip(self, ip_address, discovery_data):
        """Find host by IP address in discovery data"""
        for host_id, data in discovery_data.items():
            host_info = data.get('host_info', {})
            if host_info.get('ip_address') == ip_address:
                return {'id': host_id, 'info': host_info}
        return None
    
    def _parse_interface_bytes(self, interface_bytes_output):
        """Parse interface byte statistics"""
        stats = {}
        for line in interface_bytes_output.split('\n'):
            if ':' in line and 'bytes' in line:
                parts = line.split(':')
                if len(parts) == 2:
                    path = parts[0].strip()
                    value = parts[1].strip()
                    if value.isdigit():
                        interface_name = path.split('/')[-2] if '/' in path else 'unknown'
                        stat_type = path.split('/')[-1] if '/' in path else 'unknown'
                        
                        if interface_name not in stats:
                            stats[interface_name] = {}
                        stats[interface_name][stat_type] = int(value)
        
        return stats
    
    def _parse_proc_net_dev(self, proc_net_dev_output):
        """Parse /proc/net/dev statistics"""
        stats = []
        lines = proc_net_dev_output.strip().split('\n')
        
        for line in lines[2:]:  # Skip header lines
            if ':' in line:
                parts = line.split(':')
                if len(parts) == 2:
                    interface = parts[0].strip()
                    values = parts[1].split()
                    if len(values) >= 16:
                        stats.append({
                            'interface': interface,
                            'rx_bytes': int(values[0]) if values[0].isdigit() else 0,
                            'rx_packets': int(values[1]) if values[1].isdigit() else 0,
                            'rx_errors': int(values[2]) if values[2].isdigit() else 0,
                            'tx_bytes': int(values[8]) if values[8].isdigit() else 0,
                            'tx_packets': int(values[9]) if values[9].isdigit() else 0,
                            'tx_errors': int(values[10]) if values[10].isdigit() else 0
                        })
        
        return stats
    
    def _analyze_host_traffic_role(self, interface_stats, dev_stats):
        """Analyze host's role based on traffic patterns"""
        analysis = {'role_indicators': [], 'traffic_level': 'low'}
        
        total_rx = sum(stat.get('rx_bytes', 0) for stat in dev_stats)
        total_tx = sum(stat.get('tx_bytes', 0) for stat in dev_stats)
        
        if total_rx > 1000000000:  # > 1GB
            analysis['traffic_level'] = 'high'
            analysis['role_indicators'].append('high_traffic_server')
        elif total_rx > 100000000:  # > 100MB
            analysis['traffic_level'] = 'medium'
            analysis['role_indicators'].append('active_host')
        
        if total_tx > total_rx * 2:
            analysis['role_indicators'].append('server_role')
        elif total_rx > total_tx * 2:
            analysis['role_indicators'].append('client_role')
        
        return analysis
    
    def _extract_physical_info(self, interface_data):
        """Extract physical interface information"""
        physical_info = []
        
        interfaces = interface_data.get('interfaces', [])
        if isinstance(interfaces, list):
            for interface in interfaces:
                if isinstance(interface, dict):
                    physical_info.append({
                        'name': interface.get('name'),
                        'state': interface.get('state'),
                        'mtu': interface.get('mtu'),
                        'addresses': interface.get('addresses', [])
                    })
        
        return physical_info
    
    def _get_host_roles(self, host_data):
        """Get roles identified for a host"""
        topology_hints = host_data.get('topology_hints', {})
        services = host_data.get('listening_services', [])
        
        roles = []
        
        # Extract from services
        service_analysis = self._analyze_services(services)
        roles.extend(service_analysis['roles'])
        
        # Extract from hints
        hint_analysis = self._extract_roles_from_hints(topology_hints)
        roles.extend(hint_analysis['roles'])
        
        return list(set(roles))
    
    def _assess_criticality(self, roles, host_data):
        """Assess host criticality based on roles and data"""
        criticality_score = 0
        
        critical_roles = ['router', 'dhcp_server', 'dns_server', 'firewall']
        for role in roles:
            if role in critical_roles:
                criticality_score += 3
            else:
                criticality_score += 1
        
        return min(criticality_score, 10)  # Max score of 10
    
    def _analyze_firewall_boundaries(self, firewall_data, host_info):
        """Analyze firewall rules to identify trust boundaries"""
        boundaries = []
        
        for fw_type, rules in firewall_data.items():
            if rules and 'DROP' in rules:
                boundaries.append({
                    'host_id': host_info.get('id'),
                    'type': fw_type,
                    'boundary_type': 'security_boundary',
                    'rules_summary': rules[:200]  # Limit size
                })
        
        return boundaries
    
    def _extract_performance_metrics(self, interface_stats):
        """Extract performance metrics from interface statistics"""
        metrics = {
            'total_interfaces': 0,
            'active_interfaces': 0,
            'total_throughput': 0,
            'error_rate': 0
        }
        
        stats = self._parse_proc_net_dev(interface_stats)
        
        metrics['total_interfaces'] = len(stats)
        
        for stat in stats:
            if stat.get('rx_bytes', 0) > 0 or stat.get('tx_bytes', 0) > 0:
                metrics['active_interfaces'] += 1
            
            metrics['total_throughput'] += stat.get('rx_bytes', 0) + stat.get('tx_bytes', 0)
            
            total_packets = stat.get('rx_packets', 0) + stat.get('tx_packets', 0)
            total_errors = stat.get('rx_errors', 0) + stat.get('tx_errors', 0)
            
            if total_packets > 0:
                metrics['error_rate'] += (total_errors / total_packets) * 100
        
        if metrics['total_interfaces'] > 0:
            metrics['error_rate'] /= metrics['total_interfaces']
        
        return metrics
    
    def _analyze_packet_statistics(self, network_stats):
        """Analyze packet statistics for performance insights"""
        analysis = {
            'packet_drops': 0,
            'retransmissions': 0,
            'congestion_indicators': []
        }
        
        # This would parse detailed packet statistics
        # Implementation depends on the specific format of network_stats
        
        return analysis
    
    def _calculate_health_score(self, performance_metrics, packet_analysis):
        """Calculate network health score for a host"""
        score = 100
        
        # Penalize high error rates
        error_rate = performance_metrics.get('error_rate', 0)
        score -= min(error_rate * 10, 50)
        
        # Penalize packet drops
        packet_drops = packet_analysis.get('packet_drops', 0)
        if packet_drops > 100:
            score -= 20
        elif packet_drops > 10:
            score -= 10
        
        return max(score, 0)
    
    def _store_topology_analysis(self, topology):
        """Store topology analysis results in database"""
        with self.db.get_connection() as conn:
            # Create topology analysis table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS topology_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_type TEXT,
                    analysis_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Store each analysis type
            for analysis_type, analysis_data in topology.items():
                conn.execute('''
                    INSERT OR REPLACE INTO topology_analysis 
                    (analysis_type, analysis_data)
                    VALUES (?, ?)
                ''', (analysis_type, json.dumps(analysis_data, default=str)))
            
            conn.commit()
