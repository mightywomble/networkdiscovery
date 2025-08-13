#!/usr/bin/env python3
"""
Enhanced Topology Builder
Creates comprehensive network diagrams with infrastructure elements like routers, gateways, subnets, and VPN connections
"""

import ipaddress
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import re


class EnhancedTopologyBuilder:
    def __init__(self, database, host_manager):
        self.db = database
        self.host_manager = host_manager
        self.network_topology = {
            'nodes': [],
            'edges': [],
            'subnets': [],
            'gateways': [],
            'infrastructure': []
        }
    
    def build_comprehensive_topology(self):
        """Build a comprehensive network topology with infrastructure elements"""
        print("Building comprehensive network topology...")
        
        # Get all hosts and their discovery data
        hosts = self.host_manager.get_all_hosts()
        
        # Analyze network infrastructure
        network_analysis = self._analyze_network_infrastructure(hosts)
        
        # Build network topology
        topology = self._build_network_topology(hosts, network_analysis)
        
        # Add infrastructure nodes
        topology = self._add_infrastructure_nodes(topology, network_analysis)
        
        # Add routing connections
        topology = self._add_routing_connections(topology, network_analysis)
        
        # Add subnet groupings
        topology = self._add_subnet_groupings(topology, network_analysis)
        
        # Add VPN connections
        topology = self._add_vpn_connections(topology, network_analysis)
        
        # Store the topology
        self.db.save_topology_analysis('enhanced_topology', topology)
        
        return topology
    
    def _analyze_network_infrastructure(self, hosts):
        """Analyze network infrastructure from discovery data"""
        infrastructure = {
            'subnets': defaultdict(set),
            'gateways': {},
            'routers': set(),
            'dns_servers': set(),
            'dhcp_servers': set(),
            'vpn_endpoints': set(),
            'internet_gateways': set(),
            'bridges': set(),
            'vlans': defaultdict(list),
            'routes': defaultdict(list),
            'arp_tables': defaultdict(list)
        }
        
        for host in hosts:
            if host.get('status') != 'online':
                continue
                
            print(f"Analyzing infrastructure for {host['name']}")
            
            # Get discovery data for this host
            discovery_data = self.db.get_network_discovery(host['id'], hours=48)
            
            for data in discovery_data:
                discovery_info = data.get('discovery_data', {})
                
                # Analyze routing table
                routing_table = discovery_info.get('routing_table', {})
                self._analyze_routing_table(host, routing_table, infrastructure)
                
                # Analyze ARP table
                arp_table = discovery_info.get('arp_table', [])
                self._analyze_arp_table(host, arp_table, infrastructure)
                
                # Analyze network interfaces
                interfaces = discovery_info.get('network_interfaces', {})
                self._analyze_interfaces(host, interfaces, infrastructure)
                
                # Analyze network services
                services = discovery_info.get('listening_services', [])
                self._analyze_services(host, services, infrastructure)
                
                # Analyze DHCP leases
                dhcp_leases = discovery_info.get('dhcp_leases', [])
                if dhcp_leases:
                    infrastructure['dhcp_servers'].add(host['ip_address'])
                
                # Analyze DNS configuration
                dns_info = discovery_info.get('dns_info', {})
                if dns_info:
                    self._analyze_dns_info(host, dns_info, infrastructure)
                
                # Analyze VPN information
                self._analyze_vpn_info(host, discovery_info, infrastructure)
        
        return infrastructure
    
    def _analyze_routing_table(self, host, routing_table, infrastructure):
        """Analyze routing table to identify gateways and subnets"""
        ipv4_routes = routing_table.get('ipv4', [])
        
        for route in ipv4_routes:
            destination = route.get('destination', '')
            gateway = route.get('gateway')
            interface = route.get('interface')
            
            # Store route information
            infrastructure['routes'][host['ip_address']].append(route)
            
            # Identify default gateway
            if destination in ['0.0.0.0/0', 'default'] and gateway:
                infrastructure['gateways'][host['ip_address']] = gateway
                infrastructure['internet_gateways'].add(gateway)
                
                # Check if gateway is also a managed host
                for other_host in self.host_manager.get_all_hosts():
                    if other_host['ip_address'] == gateway:
                        infrastructure['routers'].add(gateway)
            
            # Identify subnet routes
            if '/' in destination and gateway != '0.0.0.0':
                try:
                    network = ipaddress.IPv4Network(destination, strict=False)
                    if network.is_private:
                        infrastructure['subnets'][str(network)].add(host['ip_address'])
                except:
                    pass
    
    def _analyze_arp_table(self, host, arp_table, infrastructure):
        """Analyze ARP table to identify local network neighbors"""
        for entry in arp_table:
            infrastructure['arp_tables'][host['ip_address']].append(entry)
            
            # Identify potential routers/gateways by MAC address patterns
            mac = entry.get('mac', '').lower()
            ip = entry.get('ip')
            
            # Common router/gateway MAC prefixes
            router_prefixes = [
                '00:0c:29',  # VMware
                '00:50:56',  # VMware
                '08:00:27',  # VirtualBox
                '00:1b:21',  # Cisco
                '00:23:04',  # Cisco
                '00:24:c4',  # Mikrotik
                '6c:3b:6b',  # Ubiquiti
                'fc:ec:da'   # Ubiquiti
            ]
            
            for prefix in router_prefixes:
                if mac.startswith(prefix) and ip:
                    infrastructure['routers'].add(ip)
    
    def _analyze_interfaces(self, host, interfaces_data, infrastructure):
        """Analyze network interfaces to identify subnets and VLANs"""
        interfaces_info = interfaces_data.get('interfaces', '')
        
        # Parse interface information for IP addresses and subnets
        ip_pattern = r'inet (\d+\.\d+\.\d+\.\d+)/(\d+)'
        matches = re.findall(ip_pattern, interfaces_info)
        
        for ip_str, prefix_len in matches:
            try:
                network = ipaddress.IPv4Network(f"{ip_str}/{prefix_len}", strict=False)
                if network.is_private:
                    infrastructure['subnets'][str(network)].add(host['ip_address'])
            except:
                pass
        
        # Check for VLAN interfaces
        vlan_pattern = r'(\w+\.\d+)'
        vlan_matches = re.findall(vlan_pattern, interfaces_info)
        for vlan_if in vlan_matches:
            infrastructure['vlans'][host['ip_address']].append(vlan_if)
        
        # Check for bridge interfaces
        if 'br' in interfaces_info.lower() or 'bridge' in interfaces_info.lower():
            infrastructure['bridges'].add(host['ip_address'])
    
    def _analyze_services(self, host, services, infrastructure):
        """Analyze running services to identify infrastructure roles"""
        for service in services:
            port = service.get('port')
            service_name = service.get('service', '').lower()
            
            # DNS servers (port 53)
            if port == 53:
                infrastructure['dns_servers'].add(host['ip_address'])
            
            # DHCP servers (port 67)
            elif port == 67:
                infrastructure['dhcp_servers'].add(host['ip_address'])
            
            # VPN services
            elif port in [1194, 1723, 500, 4500]:  # OpenVPN, PPTP, IPSec
                infrastructure['vpn_endpoints'].add(host['ip_address'])
            
            # Router/gateway services
            elif 'router' in service_name or 'gateway' in service_name:
                infrastructure['routers'].add(host['ip_address'])
    
    def _analyze_dns_info(self, host, dns_info, infrastructure):
        """Analyze DNS configuration"""
        nameservers = dns_info.get('nameservers', [])
        for ns in nameservers:
            if self._is_local_ip(ns):
                infrastructure['dns_servers'].add(ns)
    
    def _analyze_vpn_info(self, host, discovery_info, infrastructure):
        """Analyze VPN configuration and connections"""
        # Look for VPN-related processes and interfaces
        processes = discovery_info.get('topology_hints', {}).get('running_services', [])
        interfaces = discovery_info.get('network_interfaces', {}).get('interfaces', '')
        
        vpn_indicators = ['openvpn', 'wireguard', 'ipsec', 'strongswan', 'tun', 'tap']
        
        for indicator in vpn_indicators:
            if any(indicator in str(process).lower() for process in processes):
                infrastructure['vpn_endpoints'].add(host['ip_address'])
                break
            if indicator in interfaces.lower():
                infrastructure['vpn_endpoints'].add(host['ip_address'])
                break
    
    def _build_network_topology(self, hosts, infrastructure):
        """Build the basic network topology with hosts"""
        topology = {
            'nodes': [],
            'edges': [],
            'groups': {}
        }
        
        # Add host nodes
        for host in hosts:
            ip = host['ip_address']
            node_type = self._determine_node_type(host, infrastructure)
            group = self._determine_network_group(ip)
            
            topology['nodes'].append({
                'id': f"host_{host['id']}",
                'label': host['name'],
                'ip': ip,
                'type': 'host',
                'subtype': node_type,
                'status': host.get('status', 'unknown'),
                'group': group,
                'size': self._get_node_size(node_type),
                'shape': self._get_node_shape(node_type),
                'color': self._get_node_color(node_type, host.get('status'))
            })
        
        return topology
    
    def _add_infrastructure_nodes(self, topology, infrastructure):
        """Add infrastructure nodes (gateways, routers, etc.)"""
        
        # Add internet gateway nodes
        for gateway in infrastructure['internet_gateways']:
            if not self._node_exists(topology, f"gateway_{gateway}"):
                topology['nodes'].append({
                    'id': f"gateway_{gateway}",
                    'label': 'Internet Gateway',
                    'ip': gateway,
                    'type': 'infrastructure',
                    'subtype': 'internet_gateway',
                    'status': 'online',
                    'group': 'infrastructure',
                    'size': 40,
                    'shape': 'diamond',
                    'color': self._get_infrastructure_color('internet_gateway')
                })
        
        # Add router nodes (that aren't already hosts)
        for router in infrastructure['routers']:
            if not self._is_managed_host(router) and not self._node_exists(topology, f"router_{router}"):
                topology['nodes'].append({
                    'id': f"router_{router}",
                    'label': 'Router',
                    'ip': router,
                    'type': 'infrastructure',
                    'subtype': 'router',
                    'status': 'unknown',
                    'group': 'infrastructure',
                    'size': 35,
                    'shape': 'square',
                    'color': self._get_infrastructure_color('router')
                })
        
        # Add subnet nodes
        subnet_counter = 1
        for subnet_cidr, hosts_in_subnet in infrastructure['subnets'].items():
            if len(hosts_in_subnet) > 1:  # Only show subnets with multiple hosts
                topology['nodes'].append({
                    'id': f"subnet_{subnet_counter}",
                    'label': f"Subnet\n{subnet_cidr}",
                    'ip': subnet_cidr,
                    'type': 'infrastructure',
                    'subtype': 'subnet',
                    'status': 'active',
                    'group': 'infrastructure',
                    'size': 25,
                    'shape': 'ellipse',
                    'color': self._get_infrastructure_color('subnet'),
                    'hosts': list(hosts_in_subnet)
                })
                subnet_counter += 1
        
        # Add internet node
        topology['nodes'].append({
            'id': 'internet',
            'label': 'Internet',
            'ip': '0.0.0.0',
            'type': 'infrastructure',
            'subtype': 'internet',
            'status': 'active',
            'group': 'external',
            'size': 50,
            'shape': 'star',
            'color': self._get_infrastructure_color('internet')
        })
        
        return topology
    
    def _add_routing_connections(self, topology, infrastructure):
        """Add routing connections between nodes"""
        
        # Connect hosts to their default gateways
        for host_ip, gateway_ip in infrastructure['gateways'].items():
            host_node = self._find_node_by_ip(topology, host_ip)
            gateway_node = self._find_node_by_ip(topology, gateway_ip)
            
            if host_node and gateway_node:
                topology['edges'].append({
                    'id': f"route_{host_node['id']}_{gateway_node['id']}",
                    'from': host_node['id'],
                    'to': gateway_node['id'],
                    'type': 'routing',
                    'label': 'Default Route',
                    'width': 3,
                    'color': '#007bff',
                    'dashes': False,
                    'arrows': {'to': True}
                })
        
        # Connect internet gateways to internet
        for gateway in infrastructure['internet_gateways']:
            gateway_node = self._find_node_by_ip(topology, gateway)
            internet_node = self._find_node_by_id(topology, 'internet')
            
            if gateway_node and internet_node:
                topology['edges'].append({
                    'id': f"internet_{gateway_node['id']}",
                    'from': gateway_node['id'],
                    'to': 'internet',
                    'type': 'internet',
                    'label': 'Internet',
                    'width': 5,
                    'color': '#fd7e14',
                    'dashes': False,
                    'arrows': {'to': True}
                })
        
        return topology
    
    def _add_subnet_groupings(self, topology, infrastructure):
        """Add connections between hosts and subnet nodes"""
        
        for node in topology['nodes']:
            if node['type'] == 'infrastructure' and node['subtype'] == 'subnet':
                subnet_hosts = node.get('hosts', [])
                
                for host_ip in subnet_hosts:
                    host_node = self._find_node_by_ip(topology, host_ip)
                    if host_node:
                        topology['edges'].append({
                            'id': f"subnet_{node['id']}_{host_node['id']}",
                            'from': node['id'],
                            'to': host_node['id'],
                            'type': 'subnet',
                            'label': 'Subnet Member',
                            'width': 2,
                            'color': '#6c757d',
                            'dashes': True,
                            'arrows': {'to': False}
                        })
        
        return topology
    
    def _add_vpn_connections(self, topology, infrastructure):
        """Add VPN connections between endpoints"""
        
        vpn_endpoints = list(infrastructure['vpn_endpoints'])
        
        # Create VPN connections between all endpoints (mesh)
        for i, endpoint1 in enumerate(vpn_endpoints):
            for endpoint2 in vpn_endpoints[i+1:]:
                node1 = self._find_node_by_ip(topology, endpoint1)
                node2 = self._find_node_by_ip(topology, endpoint2)
                
                if node1 and node2:
                    topology['edges'].append({
                        'id': f"vpn_{node1['id']}_{node2['id']}",
                        'from': node1['id'],
                        'to': node2['id'],
                        'type': 'vpn',
                        'label': 'VPN Tunnel',
                        'width': 4,
                        'color': '#28a745',
                        'dashes': [10, 5],
                        'arrows': {'to': True, 'from': True}
                    })
        
        return topology
    
    def _determine_node_type(self, host, infrastructure):
        """Determine the type of network node based on its role"""
        ip = host['ip_address']
        
        if ip in infrastructure['routers']:
            return 'router'
        elif ip in infrastructure['dns_servers']:
            return 'dns_server'
        elif ip in infrastructure['dhcp_servers']:
            return 'dhcp_server'
        elif ip in infrastructure['vpn_endpoints']:
            return 'vpn_endpoint'
        elif ip in infrastructure['bridges']:
            return 'bridge'
        else:
            return 'server'
    
    def _determine_network_group(self, ip):
        """Determine which network group an IP belongs to"""
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
                    return 'private'
            else:
                return 'internet'
        except:
            return 'unknown'
    
    def _get_node_size(self, node_type):
        """Get node size based on type"""
        sizes = {
            'router': 40,
            'dns_server': 35,
            'dhcp_server': 35,
            'vpn_endpoint': 30,
            'bridge': 30,
            'server': 25
        }
        return sizes.get(node_type, 25)
    
    def _get_node_shape(self, node_type):
        """Get node shape based on type"""
        shapes = {
            'router': 'square',
            'dns_server': 'triangle',
            'dhcp_server': 'triangle',
            'vpn_endpoint': 'hexagon',
            'bridge': 'diamond',
            'server': 'dot'
        }
        return shapes.get(node_type, 'dot')
    
    def _get_node_color(self, node_type, status):
        """Get node color based on type and status"""
        base_colors = {
            'router': {'background': '#ffc107', 'border': '#f0ad4e'},
            'dns_server': {'background': '#17a2b8', 'border': '#138496'},
            'dhcp_server': {'background': '#6f42c1', 'border': '#5a32a3'},
            'vpn_endpoint': {'background': '#28a745', 'border': '#1e7e34'},
            'bridge': {'background': '#fd7e14', 'border': '#e55a00'},
            'server': {'background': '#007bff', 'border': '#0056b3'}
        }
        
        color = base_colors.get(node_type, {'background': '#6c757d', 'border': '#545b62'})
        
        # Modify based on status
        if status == 'offline':
            color['background'] = '#f8d7da'
            color['border'] = '#dc3545'
        elif status == 'ping_only':
            color['background'] = '#fff3cd'
            color['border'] = '#ffc107'
        
        return color
    
    def _get_infrastructure_color(self, infra_type):
        """Get color for infrastructure nodes"""
        colors = {
            'internet_gateway': {'background': '#fd7e14', 'border': '#e55a00'},
            'router': {'background': '#ffc107', 'border': '#f0ad4e'},
            'subnet': {'background': '#e9ecef', 'border': '#6c757d'},
            'internet': {'background': '#dc3545', 'border': '#c82333'}
        }
        return colors.get(infra_type, {'background': '#6c757d', 'border': '#545b62'})
    
    def _node_exists(self, topology, node_id):
        """Check if a node already exists"""
        return any(node['id'] == node_id for node in topology['nodes'])
    
    def _is_managed_host(self, ip):
        """Check if an IP is a managed host"""
        hosts = self.host_manager.get_all_hosts()
        return any(host['ip_address'] == ip for host in hosts)
    
    def _find_node_by_ip(self, topology, ip):
        """Find a node by IP address"""
        for node in topology['nodes']:
            if node['ip'] == ip:
                return node
        return None
    
    def _find_node_by_id(self, topology, node_id):
        """Find a node by ID"""
        for node in topology['nodes']:
            if node['id'] == node_id:
                return node
        return None
    
    def _is_local_ip(self, ip):
        """Check if an IP is in local network ranges"""
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            return ip_obj.is_private
        except:
            return False
