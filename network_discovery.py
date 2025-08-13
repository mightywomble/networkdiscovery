#!/usr/bin/env python3
"""
Enhanced Network Discovery Module
Collects comprehensive network interconnectivity data for detailed mapping
"""

import subprocess
import re
import json
import ipaddress
import socket
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import threading
import time

class EnhancedNetworkDiscovery:
    def __init__(self, host_manager, database):
        self.host_manager = host_manager
        self.db = database
        self.discovery_data = defaultdict(dict)
        
    def collect_comprehensive_data(self, host):
        """Collect all available network interconnectivity data from a host"""
        print(f"Enhanced discovery for {host['name']} ({host['ip_address']})")
        
        data = {
            'host_id': host['id'],
            'timestamp': datetime.now(),
            'routing_table': self._get_routing_table(host),
            'arp_table': self._get_arp_table(host),
            'network_interfaces': self._get_detailed_interfaces(host),
            'active_connections': self._get_detailed_connections(host),
            'listening_services': self._get_listening_services(host),
            'network_neighbors': self._discover_network_neighbors(host),
            'bridge_info': self._get_bridge_info(host),
            'vlan_info': self._get_vlan_info(host),
            'wireless_info': self._get_wireless_info(host),
            'dns_info': self._get_dns_info(host),
            'dhcp_leases': self._get_dhcp_leases(host),
            'firewall_rules': self._get_firewall_info(host),
            'network_statistics': self._get_network_statistics(host),
            'bandwidth_usage': self._get_bandwidth_usage(host),
            'packet_analysis': self._analyze_packet_flows(host),
            'topology_hints': self._get_topology_hints(host)
        }
        
        # Store comprehensive data
        self._store_discovery_data(host['id'], data)
        return data
    
    def _get_routing_table(self, host):
        """Get detailed routing table information"""
        commands = [
            "ip route show table all 2>/dev/null || route -n",
            "ip -6 route show 2>/dev/null || route -6 -n 2>/dev/null"
        ]
        
        routing_info = {'ipv4': [], 'ipv6': [], 'default_gateway': None}
        
        for cmd in commands:
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                routes = self._parse_routing_table(result['stdout'])
                if 'ip -6' in cmd or 'route -6' in cmd:
                    routing_info['ipv6'].extend(routes)
                else:
                    routing_info['ipv4'].extend(routes)
                    # Find default gateway
                    for route in routes:
                        if route.get('destination') in ['0.0.0.0/0', 'default']:
                            routing_info['default_gateway'] = route.get('gateway')
        
        return routing_info
    
    def _get_arp_table(self, host):
        """Get ARP table for network neighbor discovery"""
        result, _ = self.host_manager.execute_command(host, "arp -a 2>/dev/null || ip neigh show")
        
        arp_entries = []
        if result and result['success']:
            for line in result['stdout'].strip().split('\n'):
                if line.strip():
                    entry = self._parse_arp_entry(line)
                    if entry:
                        arp_entries.append(entry)
        
        return arp_entries
    
    def _get_detailed_interfaces(self, host):
        """Get comprehensive network interface information"""
        commands = {
            'interfaces': "ip addr show 2>/dev/null || ifconfig -a",
            'interface_stats': "ip -s link show 2>/dev/null || netstat -i",
            'ethtool_info': "for iface in $(ls /sys/class/net/ 2>/dev/null); do echo \"=== $iface ===\"; ethtool $iface 2>/dev/null; done",
            'wireless_scan': "iwlist scan 2>/dev/null | grep -E 'Cell|ESSID|Quality|Frequency'",
            'bonding_info': "cat /proc/net/bonding/* 2>/dev/null",
            'bridge_info': "brctl show 2>/dev/null || bridge link show 2>/dev/null"
        }
        
        interface_data = {}
        for info_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                interface_data[info_type] = self._parse_interface_data(info_type, result['stdout'])
        
        return interface_data
    
    def _get_detailed_connections(self, host):
        """Get detailed network connection information"""
        commands = {
            'tcp_connections': "ss -tuln4p 2>/dev/null || netstat -tulnp4 2>/dev/null",
            'tcp6_connections': "ss -tuln6p 2>/dev/null || netstat -tulnp6 2>/dev/null",
            'established_connections': "ss -tup 2>/dev/null || netstat -tup 2>/dev/null",
            'socket_stats': "ss -s 2>/dev/null",
            'connection_tracking': "cat /proc/net/nf_conntrack 2>/dev/null | head -20"
        }
        
        connection_data = {}
        for conn_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                connection_data[conn_type] = self._parse_connection_data(conn_type, result['stdout'])
        
        return connection_data
    
    def _get_listening_services(self, host):
        """Get detailed information about listening services"""
        result, _ = self.host_manager.execute_command(host, 
            "ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null")
        
        services = []
        if result and result['success']:
            for line in result['stdout'].strip().split('\n'):
                service = self._parse_service_line(line)
                if service:
                    services.append(service)
        
        return services
    
    def _discover_network_neighbors(self, host):
        """Discover network neighbors through multiple methods"""
        neighbors = {
            'ping_sweep': [],
            'arp_discovery': [],
            'broadcast_discovery': [],
            'multicast_discovery': []
        }
        
        # Get network ranges from interfaces
        interfaces_result, _ = self.host_manager.execute_command(host, "ip route show 2>/dev/null")
        if interfaces_result and interfaces_result['success']:
            networks = self._extract_network_ranges(interfaces_result['stdout'])
            
            for network in networks[:3]:  # Limit to first 3 networks
                try:
                    net = ipaddress.IPv4Network(network, strict=False)
                    if net.is_private and net.num_addresses <= 256:  # Only scan small networks
                        # Ping sweep
                        neighbors['ping_sweep'].extend(self._ping_sweep_network(host, str(net)))
                        
                        # ARP-based discovery
                        neighbors['arp_discovery'].extend(self._arp_scan_network(host, str(net)))
                except:
                    continue
        
        # Broadcast discovery
        neighbors['broadcast_discovery'] = self._broadcast_discovery(host)
        
        # Multicast discovery
        neighbors['multicast_discovery'] = self._multicast_discovery(host)
        
        return neighbors
    
    def _get_bridge_info(self, host):
        """Get bridge and switching information"""
        commands = [
            "brctl show 2>/dev/null",
            "bridge fdb show 2>/dev/null",
            "bridge link show 2>/dev/null",
            "ovs-vsctl show 2>/dev/null"
        ]
        
        bridge_data = []
        for cmd in commands:
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success'] and result['stdout'].strip():
                bridge_data.append({
                    'type': cmd.split()[0],
                    'data': result['stdout']
                })
        
        return bridge_data
    
    def _get_vlan_info(self, host):
        """Get VLAN configuration information"""
        commands = [
            "cat /proc/net/vlan/config 2>/dev/null",
            "ip link show type vlan 2>/dev/null",
            "vconfig 2>/dev/null"
        ]
        
        vlan_data = []
        for cmd in commands:
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success'] and result['stdout'].strip():
                vlan_data.append({
                    'source': cmd,
                    'vlans': self._parse_vlan_data(result['stdout'])
                })
        
        return vlan_data
    
    def _get_wireless_info(self, host):
        """Get wireless network information"""
        commands = {
            'wireless_interfaces': "iwconfig 2>/dev/null",
            'access_points': "iwlist scan 2>/dev/null",
            'wireless_stats': "cat /proc/net/wireless 2>/dev/null",
            'hostapd_status': "systemctl status hostapd 2>/dev/null || service hostapd status 2>/dev/null"
        }
        
        wireless_data = {}
        for info_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                wireless_data[info_type] = result['stdout']
        
        return wireless_data
    
    def _get_dns_info(self, host):
        """Get DNS configuration and cache information"""
        commands = {
            'resolv_conf': "cat /etc/resolv.conf 2>/dev/null",
            'dns_cache': "systemd-resolve --statistics 2>/dev/null || dig +stats . 2>/dev/null",
            'hosts_file': "cat /etc/hosts 2>/dev/null",
            'dns_queries': "journalctl -u systemd-resolved --no-pager -n 50 2>/dev/null"
        }
        
        dns_data = {}
        for info_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                dns_data[info_type] = result['stdout']
        
        return dns_data
    
    def _get_dhcp_leases(self, host):
        """Get DHCP lease information"""
        commands = [
            "cat /var/lib/dhcp/dhcpd.leases 2>/dev/null",
            "cat /var/lib/dhcpcd5/dhcpcd.leases 2>/dev/null",
            "cat /var/db/dhcpd.leases 2>/dev/null",
            "systemctl status isc-dhcp-server 2>/dev/null | grep -A 20 'Active:'"
        ]
        
        dhcp_data = []
        for cmd in commands:
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success'] and result['stdout'].strip():
                dhcp_data.append({
                    'source': cmd,
                    'data': result['stdout']
                })
        
        return dhcp_data
    
    def _get_firewall_info(self, host):
        """Get firewall rules and network filtering information"""
        commands = {
            'iptables_rules': "iptables -L -n -v 2>/dev/null",
            'ip6tables_rules': "ip6tables -L -n -v 2>/dev/null",
            'ufw_status': "ufw status verbose 2>/dev/null",
            'firewalld_zones': "firewall-cmd --list-all-zones 2>/dev/null",
            'nftables_rules': "nft list ruleset 2>/dev/null"
        }
        
        firewall_data = {}
        for fw_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                firewall_data[fw_type] = result['stdout']
        
        return firewall_data
    
    def _get_network_statistics(self, host):
        """Get detailed network statistics and performance data"""
        commands = {
            'interface_stats': "cat /proc/net/dev 2>/dev/null",
            'tcp_stats': "ss -i 2>/dev/null",
            'netstat_summary': "netstat -s 2>/dev/null",
            'bandwidth_info': "cat /sys/class/net/*/speed 2>/dev/null",
            'packet_drops': "cat /proc/net/softnet_stat 2>/dev/null"
        }
        
        stats_data = {}
        for stat_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                stats_data[stat_type] = result['stdout']
        
        return stats_data
    
    def _get_bandwidth_usage(self, host):
        """Monitor bandwidth usage patterns"""
        # Sample network traffic for a short period
        result, _ = self.host_manager.execute_command(host, 
            "timeout 10 tcpdump -i any -c 100 -n 2>/dev/null | head -50 2>/dev/null || echo 'tcpdump not available'")
        
        bandwidth_data = {'sample_traffic': ''}
        if result and result['success']:
            bandwidth_data['sample_traffic'] = result['stdout']
        
        # Get interface utilization
        result, _ = self.host_manager.execute_command(host, 
            "for i in /sys/class/net/*/statistics/*_bytes; do echo \"$i: $(cat $i 2>/dev/null)\"; done | head -20")
        
        if result and result['success']:
            bandwidth_data['interface_bytes'] = result['stdout']
        
        return bandwidth_data
    
    def _analyze_packet_flows(self, host):
        """Analyze packet flows and connection patterns"""
        commands = {
            'conntrack_flows': "cat /proc/net/nf_conntrack 2>/dev/null | head -50",
            'socket_summary': "ss -s 2>/dev/null",
            'active_flows': "ss -tuap 2>/dev/null | head -50"
        }
        
        flow_data = {}
        for flow_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                flow_data[flow_type] = result['stdout']
        
        return flow_data
    
    def _get_topology_hints(self, host):
        """Collect topology hints and network role indicators"""
        commands = {
            'system_role': "systemctl list-unit-files | grep -E 'dhcp|dns|router|bridge|firewall' | grep enabled",
            'running_services': "systemctl list-units --type=service --state=running | grep -E 'network|dhcp|dns|router'",
            'proc_sys_net': "find /proc/sys/net -name 'forwarding' -exec sh -c 'echo \"{}: $(cat {})\"' \\;",
            'routing_daemons': "ps aux | grep -E 'quagga|bird|zebra|ospf|bgp' | grep -v grep"
        }
        
        topology_data = {}
        for hint_type, cmd in commands.items():
            result, _ = self.host_manager.execute_command(host, cmd)
            if result and result['success']:
                topology_data[hint_type] = result['stdout']
        
        return topology_data
    
    # Parsing helper methods
    def _parse_routing_table(self, output):
        """Parse routing table output"""
        routes = []
        for line in output.strip().split('\n'):
            if not line.strip() or line.startswith('Kernel') or line.startswith('Destination'):
                continue
            
            # Parse different route formats
            parts = line.split()
            if len(parts) >= 3:
                route = {
                    'destination': parts[0],
                    'gateway': parts[1] if parts[1] != '*' else None,
                    'interface': parts[-1] if parts else None,
                    'metric': None
                }
                
                # Extract metric if present
                for part in parts:
                    if part.isdigit():
                        route['metric'] = int(part)
                        break
                
                routes.append(route)
        
        return routes
    
    def _parse_arp_entry(self, line):
        """Parse ARP table entry"""
        # Handle different ARP output formats
        if '(' in line and ')' in line:
            # Format: hostname (ip) at mac [interface]
            match = re.search(r'(\S+)\s+\(([^)]+)\)\s+at\s+([a-fA-F0-9:]+)', line)
            if match:
                return {
                    'hostname': match.group(1),
                    'ip': match.group(2),
                    'mac': match.group(3),
                    'interface': None
                }
        else:
            # Format: ip dev interface lladdr mac
            parts = line.split()
            if len(parts) >= 4:
                return {
                    'ip': parts[0],
                    'interface': parts[2] if 'dev' in parts else None,
                    'mac': parts[4] if 'lladdr' in parts else None,
                    'hostname': None
                }
        
        return None
    
    def _parse_interface_data(self, info_type, output):
        """Parse interface information based on type"""
        if info_type == 'interfaces':
            return self._parse_ip_addr_output(output)
        elif info_type == 'interface_stats':
            return self._parse_interface_stats(output)
        else:
            return {'raw_output': output[:1000]}  # Limit size
    
    def _parse_ip_addr_output(self, output):
        """Parse ip addr show output"""
        interfaces = []
        current_interface = None
        
        for line in output.split('\n'):
            if re.match(r'^\d+:', line):
                # New interface
                if current_interface:
                    interfaces.append(current_interface)
                
                parts = line.split(': ')
                if len(parts) >= 2:
                    current_interface = {
                        'name': parts[1].split('@')[0],
                        'state': 'UP' if 'UP' in line else 'DOWN',
                        'addresses': [],
                        'mtu': None
                    }
                    
                    # Extract MTU
                    mtu_match = re.search(r'mtu (\d+)', line)
                    if mtu_match:
                        current_interface['mtu'] = int(mtu_match.group(1))
            
            elif current_interface and line.strip().startswith('inet'):
                # IP address
                addr_match = re.search(r'inet6?\s+([^\s]+)', line)
                if addr_match:
                    current_interface['addresses'].append(addr_match.group(1))
        
        if current_interface:
            interfaces.append(current_interface)
        
        return interfaces
    
    def _parse_interface_stats(self, output):
        """Parse interface statistics"""
        stats = []
        for line in output.strip().split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 10:
                stats.append({
                    'interface': parts[0],
                    'rx_packets': int(parts[2]) if parts[2].isdigit() else 0,
                    'tx_packets': int(parts[6]) if parts[6].isdigit() else 0,
                    'rx_bytes': int(parts[1]) if parts[1].isdigit() else 0,
                    'tx_bytes': int(parts[5]) if parts[5].isdigit() else 0
                })
        
        return stats
    
    def _parse_connection_data(self, conn_type, output):
        """Parse connection data based on type"""
        connections = []
        for line in output.strip().split('\n'):
            if 'LISTEN' in line or 'ESTABLISHED' in line:
                conn = self._parse_connection_line(line)
                if conn:
                    connections.append(conn)
        
        return connections[:50]  # Limit results
    
    def _parse_connection_line(self, line):
        """Parse individual connection line"""
        parts = line.split()
        if len(parts) >= 4:
            return {
                'protocol': parts[0],
                'local_address': parts[3],
                'remote_address': parts[4] if len(parts) > 4 else '',
                'state': parts[5] if len(parts) > 5 else '',
                'process': parts[-1] if len(parts) > 6 else ''
            }
        
        return None
    
    def _parse_service_line(self, line):
        """Parse service listening line"""
        if 'LISTEN' not in line:
            return None
        
        parts = line.split()
        if len(parts) >= 4:
            local_addr = parts[3]
            if ':' in local_addr:
                ip, port = local_addr.rsplit(':', 1)
                return {
                    'protocol': parts[0],
                    'ip': ip,
                    'port': port,
                    'process': parts[-1] if len(parts) > 6 else ''
                }
        
        return None
    
    def _extract_network_ranges(self, route_output):
        """Extract network ranges from routing output"""
        networks = []
        for line in route_output.strip().split('\n'):
            if '/' in line:
                parts = line.split()
                for part in parts:
                    if '/' in part and not part.startswith('fe80'):
                        try:
                            ipaddress.IPv4Network(part, strict=False)
                            networks.append(part)
                        except:
                            continue
        
        return list(set(networks))
    
    def _ping_sweep_network(self, host, network):
        """Perform ping sweep of network"""
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            if net.num_addresses > 256:
                return []  # Skip large networks
            
            # Generate ping command for first 50 IPs
            ips = list(net.hosts())[:50]
            ping_cmd = '; '.join([f"ping -c 1 -W 1 {ip} >/dev/null 2>&1 && echo {ip}" for ip in ips])
            
            result, _ = self.host_manager.execute_command(host, f"timeout 30 sh -c '{ping_cmd}'")
            
            if result and result['success']:
                return [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
        except:
            pass
        
        return []
    
    def _arp_scan_network(self, host, network):
        """Perform ARP scan of network"""
        result, _ = self.host_manager.execute_command(host, f"nmap -sn {network} 2>/dev/null | grep -oE '([0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}' || echo ''")
        
        if result and result['success']:
            return [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
        
        return []
    
    def _broadcast_discovery(self, host):
        """Discover hosts via broadcast"""
        result, _ = self.host_manager.execute_command(host, "ping -b -c 3 255.255.255.255 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -10 || echo ''")
        
        if result and result['success']:
            return [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
        
        return []
    
    def _multicast_discovery(self, host):
        """Discover hosts via multicast"""
        result, _ = self.host_manager.execute_command(host, "ping -c 2 224.0.0.1 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -5 || echo ''")
        
        if result and result['success']:
            return [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
        
        return []
    
    def _parse_vlan_data(self, output):
        """Parse VLAN configuration data"""
        vlans = []
        for line in output.split('\n'):
            if 'vlan' in line.lower() or '.' in line:
                vlans.append(line.strip())
        
        return vlans
    
    def _store_discovery_data(self, host_id, data):
        """Store comprehensive discovery data in database"""
        # Store in a new table for extended network data
        with self.db.get_connection() as conn:
            # Create extended data table if it doesn't exist
            conn.execute('''
                CREATE TABLE IF NOT EXISTS network_discovery_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    discovery_type TEXT,
                    data_json TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Store each type of discovery data
            for data_type, discovery_data in data.items():
                if data_type not in ['host_id', 'timestamp'] and discovery_data:
                    conn.execute('''
                        INSERT OR REPLACE INTO network_discovery_data 
                        (host_id, discovery_type, data_json)
                        VALUES (?, ?, ?)
                    ''', (host_id, data_type, json.dumps(discovery_data, default=str)))
            
            conn.commit()
    
    def get_network_topology_insights(self):
        """Analyze collected data to provide topology insights"""
        insights = {
            'network_segments': [],
            'potential_routers': [],
            'dhcp_servers': [],
            'dns_servers': [],
            'wireless_access_points': [],
            'bridges_switches': [],
            'firewall_hosts': [],
            'interconnections': []
        }
        
        # This would analyze all collected data to build insights
        # Implementation would be quite extensive, analyzing routing tables,
        # ARP data, service information, etc.
        
        return insights
