#!/usr/bin/env python3
"""
Enhanced Network Scanner
Leverages all installed network analysis tools for comprehensive discovery and mapping:
- nmap, traceroute, mtr, arp-scan, fping, masscan
- tcpdump, tshark, wireshark-common
- iftop, nethogs, bmon, vnstat, htop, iotop
- iperf3, netperf, speedtest-cli
- snmp, snmp-mibs-downloader
- ngrep, p0f
"""

import subprocess
import json
import socket
import ipaddress
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time
import random
import tempfile
import os

class EnhancedNetworkScanner:
    def __init__(self, host_manager, database):
        self.host_manager = host_manager
        self.db = database
        self.progress_callback = None
        self.scan_data = {}
        
    def set_progress_callback(self, callback):
        """Set callback function for progress updates"""
        self.progress_callback = callback
    
    def _update_progress(self, message):
        """Update progress via callback if available"""
        print(f"[ENHANCED SCAN] {message}")
        if self.progress_callback:
            self.progress_callback(message)
    
    def comprehensive_network_scan(self, host):
        """Perform comprehensive scan using all available tools"""
        self._update_progress(f"🚀 Starting comprehensive scan of {host['name']} ({host['ip_address']})")
        
        scan_results = {
            'host_info': host,
            'timestamp': datetime.now().isoformat(),
            'tools_used': [],
            'network_topology': {},
            'traffic_analysis': {},
            'performance_metrics': {},
            'security_info': {},
            'infrastructure_data': {}
        }
        
        # Phase 1: Advanced Network Discovery
        self._update_progress(f"🔍 Phase 1: Advanced Network Discovery on {host['name']}")
        scan_results['network_topology'] = self._advanced_network_discovery(host)
        
        # Phase 2: Deep Traffic Analysis
        self._update_progress(f"📊 Phase 2: Traffic Analysis on {host['name']}")
        scan_results['traffic_analysis'] = self._deep_traffic_analysis(host)
        
        # Phase 3: Performance Monitoring
        self._update_progress(f"⚡ Phase 3: Performance Analysis on {host['name']}")
        scan_results['performance_metrics'] = self._performance_analysis(host)
        
        # Phase 4: Security Analysis
        self._update_progress(f"🔒 Phase 4: Security Analysis on {host['name']}")
        scan_results['security_info'] = self._security_analysis(host)
        
        # Phase 5: Infrastructure Discovery
        self._update_progress(f"🏗️ Phase 5: Infrastructure Discovery on {host['name']}")
        scan_results['infrastructure_data'] = self._infrastructure_discovery(host)
        
        # Phase 6: Internet Connectivity Analysis
        self._update_progress(f"🌐 Phase 6: Internet Connectivity Analysis from {host['name']}")
        scan_results['internet_connectivity'] = self._internet_connectivity_analysis(host)
        
        # Store comprehensive results
        self._store_enhanced_scan_results(host, scan_results)
        
        self._update_progress(f"✅ Comprehensive scan completed for {host['name']}")
        return scan_results
    
    def _advanced_network_discovery(self, host):
        """Phase 1: Use nmap, arp-scan, fping, masscan for network discovery"""
        discovery_data = {
            'local_network': {},
            'port_scan': {},
            'arp_table': {},
            'network_routes': {},
            'ping_sweep': {}
        }
        
        # 1.1: Comprehensive nmap scan
        self._update_progress(f"  🗺️ Running comprehensive nmap scan from {host['name']}")
        discovery_data['port_scan'] = self._comprehensive_nmap_scan(host)
        
        # 1.2: ARP table discovery
        self._update_progress(f"  🔍 Discovering ARP table on {host['name']}")
        discovery_data['arp_table'] = self._arp_table_discovery(host)
        
        # 1.3: Network route analysis
        self._update_progress(f"  🛣️ Analyzing network routes from {host['name']}")
        discovery_data['network_routes'] = self._network_route_analysis(host)
        
        # 1.4: Fast ping sweep with fping
        self._update_progress(f"  🏃 Fast ping sweep from {host['name']}")
        discovery_data['ping_sweep'] = self._fast_ping_sweep(host)
        
        # 1.5: Masscan for rapid port discovery
        self._update_progress(f"  💨 Rapid port discovery with masscan from {host['name']}")
        discovery_data['masscan_results'] = self._masscan_discovery(host)
        
        return discovery_data
    
    def _deep_traffic_analysis(self, host):
        """Phase 2: Use tcpdump, tshark, iftop, nethogs for traffic analysis"""
        traffic_data = {
            'interface_stats': {},
            'connection_analysis': {},
            'protocol_breakdown': {},
            'bandwidth_usage': {},
            'network_flows': {}
        }
        
        # 2.1: Interface statistics and bandwidth
        self._update_progress(f"  📡 Analyzing network interfaces on {host['name']}")
        traffic_data['interface_stats'] = self._interface_analysis(host)
        
        # 2.2: Active connection analysis with detailed info
        self._update_progress(f"  🔗 Analyzing active connections on {host['name']}")
        traffic_data['connection_analysis'] = self._detailed_connection_analysis(host)
        
        # 2.3: Protocol analysis with tshark (short capture)
        self._update_progress(f"  🔬 Protocol analysis with tshark on {host['name']}")
        traffic_data['protocol_breakdown'] = self._protocol_analysis(host)
        
        # 2.4: Bandwidth monitoring with iftop/nethogs
        self._update_progress(f"  📈 Bandwidth usage analysis on {host['name']}")
        traffic_data['bandwidth_usage'] = self._bandwidth_analysis(host)
        
        # 2.5: vnstat historical data
        self._update_progress(f"  📊 Historical traffic data from {host['name']}")
        traffic_data['historical_stats'] = self._vnstat_analysis(host)
        
        return traffic_data
    
    def _performance_analysis(self, host):
        """Phase 3: Use iperf3, netperf, speedtest for performance testing"""
        performance_data = {
            'system_performance': {},
            'network_latency': {},
            'bandwidth_tests': {},
            'internet_speed': {},
            'network_diagnostics': {}
        }
        
        # 3.1: System performance with htop/iotop
        self._update_progress(f"  💻 System performance analysis on {host['name']}")
        performance_data['system_performance'] = self._system_performance_check(host)
        
        # 3.2: Network latency with mtr
        self._update_progress(f"  ⏱️ Network latency analysis from {host['name']}")
        performance_data['network_latency'] = self._network_latency_analysis(host)
        
        # 3.3: Internet speed test
        self._update_progress(f"  🌐 Internet speed test from {host['name']}")
        performance_data['internet_speed'] = self._internet_speed_test(host)
        
        # 3.4: Network path diagnostics
        self._update_progress(f"  🛤️ Network path diagnostics from {host['name']}")
        performance_data['network_diagnostics'] = self._network_path_diagnostics(host)
        
        return performance_data
    
    def _security_analysis(self, host):
        """Phase 4: Use ngrep, p0f for security analysis"""
        security_data = {
            'passive_fingerprinting': {},
            'network_monitoring': {},
            'open_ports_analysis': {},
            'service_fingerprinting': {},
            'vulnerability_indicators': {}
        }
        
        # 4.1: Passive OS fingerprinting with p0f
        self._update_progress(f"  🕵️ Passive OS fingerprinting on {host['name']}")
        security_data['passive_fingerprinting'] = self._passive_fingerprinting(host)
        
        # 4.2: Network security monitoring
        self._update_progress(f"  🔐 Network security analysis on {host['name']}")
        security_data['network_monitoring'] = self._security_monitoring(host)
        
        # 4.3: Service fingerprinting
        self._update_progress(f"  🎯 Service fingerprinting on {host['name']}")
        security_data['service_fingerprinting'] = self._service_fingerprinting(host)
        
        return security_data
    
    def _infrastructure_discovery(self, host):
        """Phase 5: Use SNMP tools for infrastructure discovery"""
        infrastructure_data = {
            'snmp_discovery': {},
            'device_inventory': {},
            'network_topology': {},
            'management_interfaces': {},
            'infrastructure_health': {}
        }
        
        # 5.1: SNMP-based discovery
        self._update_progress(f"  🏢 SNMP infrastructure discovery from {host['name']}")
        infrastructure_data['snmp_discovery'] = self._snmp_discovery(host)
        
        # 5.2: Network device inventory
        self._update_progress(f"  📋 Network device inventory from {host['name']}")
        infrastructure_data['device_inventory'] = self._device_inventory(host)
        
        return infrastructure_data
    
    def _internet_connectivity_analysis(self, host):
        """Phase 6: Analyze internet connectivity and external routes"""
        connectivity_data = {
            'external_routes': {},
            'dns_analysis': {},
            'cdn_discovery': {},
            'public_services': {},
            'geographic_routing': {}
        }
        
        # 6.1: External route analysis
        self._update_progress(f"  🌍 External route analysis from {host['name']}")
        connectivity_data['external_routes'] = self._external_route_analysis(host)
        
        # 6.2: DNS infrastructure analysis
        self._update_progress(f"  🔍 DNS infrastructure analysis from {host['name']}")
        connectivity_data['dns_analysis'] = self._dns_analysis(host)
        
        # 6.3: CDN and public service discovery
        self._update_progress(f"  ☁️ CDN and service discovery from {host['name']}")
        connectivity_data['public_services'] = self._public_service_discovery(host)
        
        return connectivity_data
    
    # Implementation of individual scan methods
    def _comprehensive_nmap_scan(self, host):
        """Comprehensive nmap scanning"""
        nmap_results = {}
        
        # Get local networks first
        result, _ = self.host_manager.execute_command(
            host, "ip route show | grep -E '^[0-9]+\\.' | head -3"
        )
        
        if not (result and result['success']):
            return nmap_results
        
        networks = []
        for line in result['stdout'].strip().split('\n'):
            if '/' in line and line.strip():
                parts = line.split()
                if parts and '/' in parts[0]:
                    try:
                        network = ipaddress.IPv4Network(parts[0], strict=False)
                        if network.is_private and network.num_addresses <= 256:
                            networks.append(str(network))
                    except:
                        continue
        
        # Comprehensive nmap scan of local networks
        for network in networks[:2]:  # Limit to 2 networks
            self._update_progress(f"    📡 Scanning network {network}")
            
            cmd = [
                f"nmap -sS -sU -O -sV --version-intensity 3 -T4 --max-parallelism 10",
                f"-p 1-1000,3306,5432,6379,8080,8443,9200 --top-ports 100",
                f"--script=default,discovery,safe --max-hostgroup 5",
                f"--max-rtt-timeout 2s {network}"
            ]
            
            result, _ = self.host_manager.execute_command(host, ' '.join(cmd), timeout=300)
            
            if result and result['success']:
                nmap_results[network] = self._parse_nmap_xml_output(result['stdout'])
        
        return nmap_results
    
    def _arp_table_discovery(self, host):
        """Discover network hosts via ARP table and arp-scan"""
        arp_data = {}
        
        # Get ARP table
        result, _ = self.host_manager.execute_command(host, "arp -a")
        if result and result['success']:
            arp_data['arp_table'] = self._parse_arp_table(result['stdout'])
        
        # Use arp-scan for discovery
        networks_cmd = "ip route show | grep -E '^[0-9]+\\.' | awk '{print $1}' | head -2"
        result, _ = self.host_manager.execute_command(host, networks_cmd)
        
        if result and result['success']:
            for network in result['stdout'].strip().split('\n'):
                if network.strip() and '/' in network:
                    self._update_progress(f"    🔍 ARP scanning {network}")
                    cmd = f"arp-scan -l -I $(ip route get {network.split('/')[0]} | head -1 | awk '{{print $5}}')"
                    result, _ = self.host_manager.execute_command(host, cmd, timeout=60)
                    
                    if result and result['success']:
                        arp_data[f'arp_scan_{network}'] = self._parse_arp_scan(result['stdout'])
        
        return arp_data
    
    def _network_route_analysis(self, host):
        """Analyze network routes and topology"""
        route_data = {}
        
        # Get routing table
        result, _ = self.host_manager.execute_command(host, "ip route show")
        if result and result['success']:
            route_data['routing_table'] = self._parse_routing_table(result['stdout'])
        
        # Get network interfaces
        result, _ = self.host_manager.execute_command(host, "ip addr show")
        if result and result['success']:
            route_data['interfaces'] = self._parse_network_interfaces(result['stdout'])
        
        # Traceroute to key destinations
        key_destinations = ['8.8.8.8', '1.1.1.1', 'google.com']
        route_data['traceroutes'] = {}
        
        for dest in key_destinations:
            self._update_progress(f"    🛤️ Tracing route to {dest}")
            result, _ = self.host_manager.execute_command(host, f"traceroute -m 15 -w 3 {dest}", timeout=45)
            if result and result['success']:
                route_data['traceroutes'][dest] = self._parse_traceroute(result['stdout'])
        
        return route_data
    
    def _fast_ping_sweep(self, host):
        """Fast ping sweep using fping"""
        ping_data = {}
        
        # Get local networks
        route_cmd = "ip route show | grep -E '^[0-9]+\\.' | awk '{print $1}' | head -2"
        self._update_progress(f"    🔍 DEBUG: Getting networks with: {route_cmd}")
        result, _ = self.host_manager.execute_command(host, route_cmd)
        
        if not (result and result['success']):
            self._update_progress(f"    ❌ DEBUG: Failed to get networks. Result: {result}")
            return ping_data
        
        self._update_progress(f"    📋 DEBUG: Found networks: {result['stdout'].strip()}")
        
        for network_line in result['stdout'].strip().split('\n'):
            if network_line.strip() and '/' in network_line:
                try:
                    # Extract just the network CIDR from the route line
                    # Format: "100.64.0.0/10 dev eth0 proto kernel scope link src 100.64.1.50 metric 100"
                    network_cidr = network_line.strip().split()[0]  # Get first part (CIDR)
                    
                    # Validate it's a proper CIDR
                    if '/' not in network_cidr or not network_cidr.split('/')[0].replace('.', '').isdigit():
                        self._update_progress(f"    ⚠️ Skipping invalid network format: {network_line[:50]}")
                        continue
                    
                    # Check network size before attempting ping sweep
                    net = ipaddress.IPv4Network(network_cidr, strict=False)
                    self._update_progress(f"    📊 DEBUG: Network {network_cidr} has {net.num_addresses} addresses")
                    
                    # Skip very large networks (more than /16 or 65536 addresses)
                    if net.num_addresses > 65536:
                        self._update_progress(f"    ⚠️ Skipping large network {network_cidr} ({net.num_addresses} addresses)")
                        continue
                    
                    # Skip networks that are not private
                    if not net.is_private:
                        self._update_progress(f"    ⚠️ Skipping non-private network {network_cidr}")
                        continue
                    
                    self._update_progress(f"    🏃 Fast ping sweep of {network_cidr} ({net.num_addresses} addresses)")
                    
                    # Use fping for fast sweep with timeout
                    cmd = f"timeout 30 fping -a -q -r 1 -g {network_cidr} 2>/dev/null | head -50"
                    self._update_progress(f"    🔧 DEBUG: Executing: {cmd}")
                    
                    result, _ = self.host_manager.execute_command(host, cmd, timeout=45)
                    
                    if result and result['success']:
                        alive_hosts = [ip.strip() for ip in result['stdout'].split('\n') if ip.strip()]
                        self._update_progress(f"    ✅ Found {len(alive_hosts)} alive hosts in {network_cidr}")
                        ping_data[network_cidr] = {
                            'alive_hosts': alive_hosts,
                            'count': len(alive_hosts)
                        }
                        
                        # Show first few discovered hosts for debugging
                        if alive_hosts:
                            sample_hosts = alive_hosts[:5]
                            self._update_progress(f"    📍 Sample hosts: {', '.join(sample_hosts)}")
                    else:
                        self._update_progress(f"    ⚠️ No result from fping for {network_cidr}")
                        
                except Exception as e:
                    self._update_progress(f"    ❌ Error processing network {network}: {e}")
                    continue
        
        return ping_data
    
    def _masscan_discovery(self, host):
        """Rapid port discovery with masscan"""
        masscan_data = {}
        
        # Get local networks for scanning
        result, _ = self.host_manager.execute_command(
            host, "ip route show | grep -E '^[0-9]+\\.' | awk '{print $1}' | head -2"
        )
        
        if not (result and result['success']):
            return masscan_data
        
        for network in result['stdout'].strip().split('\n'):
            if network.strip() and '/' in network:
                try:
                    net = ipaddress.IPv4Network(network.strip(), strict=False)
                    if net.is_private and net.num_addresses <= 256:
                        self._update_progress(f"    💨 Masscan rapid discovery on {network}")
                        
                        # Fast scan of common ports
                        cmd = f"masscan {network} -p 22,80,443,3306,5432,6379,8080 --rate=1000 --wait=0"
                        result, _ = self.host_manager.execute_command(host, cmd, timeout=60)
                        
                        if result and result['success']:
                            masscan_data[network] = self._parse_masscan_output(result['stdout'])
                except:
                    continue
        
        return masscan_data
    
    def _interface_analysis(self, host):
        """Analyze network interfaces and statistics"""
        interface_data = {}
        
        # Get interface statistics
        result, _ = self.host_manager.execute_command(host, "cat /proc/net/dev")
        if result and result['success']:
            interface_data['statistics'] = self._parse_interface_stats(result['stdout'])
        
        # Get interface details
        result, _ = self.host_manager.execute_command(host, "ip -s link show")
        if result and result['success']:
            interface_data['details'] = self._parse_interface_details(result['stdout'])
        
        return interface_data
    
    def _detailed_connection_analysis(self, host):
        """Detailed analysis of network connections"""
        connection_data = {}
        
        # Get detailed socket information
        result, _ = self.host_manager.execute_command(host, "ss -tuln")
        if result and result['success']:
            connection_data['listening_sockets'] = self._parse_socket_stats(result['stdout'])
        
        # Get established connections with process info
        result, _ = self.host_manager.execute_command(host, "ss -tulpn")
        if result and result['success']:
            connection_data['active_connections'] = self._parse_active_connections(result['stdout'])
        
        return connection_data
    
    def _protocol_analysis(self, host):
        """Protocol analysis using tshark (short capture)"""
        protocol_data = {}
        
        # Short packet capture for protocol analysis
        self._update_progress(f"    🔬 Capturing packets for protocol analysis")
        
        # 10-second capture
        cmd = "timeout 10 tshark -i any -q -z io,phs 2>/dev/null || echo 'tshark unavailable'"
        result, _ = self.host_manager.execute_command(host, cmd, timeout=15)
        
        if result and result['success'] and 'tshark unavailable' not in result['stdout']:
            protocol_data['protocol_hierarchy'] = self._parse_protocol_hierarchy(result['stdout'])
        
        return protocol_data
    
    def _bandwidth_analysis(self, host):
        """Bandwidth usage analysis"""
        bandwidth_data = {}
        
        # Use iftop for bandwidth analysis (5 seconds)
        cmd = "timeout 5 iftop -t -s 5 2>/dev/null | tail -20 || echo 'iftop unavailable'"
        result, _ = self.host_manager.execute_command(host, cmd, timeout=10)
        
        if result and result['success'] and 'iftop unavailable' not in result['stdout']:
            bandwidth_data['current_usage'] = self._parse_iftop_output(result['stdout'])
        
        return bandwidth_data
    
    def _vnstat_analysis(self, host):
        """Historical traffic analysis with vnstat"""
        vnstat_data = {}
        
        # Get vnstat data
        result, _ = self.host_manager.execute_command(host, "vnstat -i any --json d 7 2>/dev/null || echo 'vnstat unavailable'")
        
        if result and result['success'] and 'vnstat unavailable' not in result['stdout']:
            try:
                vnstat_data = json.loads(result['stdout'])
            except:
                vnstat_data = {'error': 'Failed to parse vnstat JSON'}
        
        return vnstat_data
    
    def _system_performance_check(self, host):
        """System performance analysis"""
        perf_data = {}
        
        # CPU and memory usage
        result, _ = self.host_manager.execute_command(host, "top -bn1 | head -20")
        if result and result['success']:
            perf_data['system_load'] = self._parse_top_output(result['stdout'])
        
        # I/O statistics
        result, _ = self.host_manager.execute_command(host, "iostat -x 1 1 2>/dev/null | tail -10 || echo 'iostat unavailable'")
        if result and result['success'] and 'iostat unavailable' not in result['stdout']:
            perf_data['io_stats'] = self._parse_iostat_output(result['stdout'])
        
        return perf_data
    
    def _network_latency_analysis(self, host):
        """Network latency analysis using mtr"""
        latency_data = {}
        
        # MTR to key destinations
        destinations = ['8.8.8.8', '1.1.1.1']
        
        for dest in destinations:
            self._update_progress(f"    ⏱️ MTR analysis to {dest}")
            cmd = f"mtr --report --report-cycles 10 --json {dest}"
            result, _ = self.host_manager.execute_command(host, cmd, timeout=60)
            
            if result and result['success']:
                try:
                    latency_data[dest] = json.loads(result['stdout'])
                except:
                    latency_data[dest] = {'error': 'Failed to parse MTR JSON'}
        
        return latency_data
    
    def _internet_speed_test(self, host):
        """Internet speed test"""
        speed_data = {}
        
        self._update_progress(f"    🌐 Running internet speed test")
        cmd = "speedtest-cli --json --timeout 30 2>/dev/null || echo 'speedtest unavailable'"
        result, _ = self.host_manager.execute_command(host, cmd, timeout=45)
        
        if result and result['success'] and 'speedtest unavailable' not in result['stdout']:
            try:
                speed_data = json.loads(result['stdout'])
            except:
                speed_data = {'error': 'Failed to parse speedtest results'}
        
        return speed_data
    
    def _network_path_diagnostics(self, host):
        """Network path diagnostics"""
        path_data = {}
        
        # Path MTU discovery
        destinations = ['google.com', 'cloudflare.com']
        
        for dest in destinations:
            cmd = f"ping -M do -s 1472 -c 3 {dest} 2>&1 | head -10"
            result, _ = self.host_manager.execute_command(host, cmd, timeout=15)
            
            if result and result['success']:
                path_data[f'mtu_{dest}'] = result['stdout']
        
        return path_data
    
    def _passive_fingerprinting(self, host):
        """Passive OS fingerprinting"""
        fingerprint_data = {}
        
        # Use p0f for passive fingerprinting (if available)
        # This is a placeholder - p0f requires specific setup
        fingerprint_data['note'] = 'Passive fingerprinting would require p0f daemon setup'
        
        return fingerprint_data
    
    def _security_monitoring(self, host):
        """Network security monitoring"""
        security_data = {}
        
        # Check for suspicious network activity
        result, _ = self.host_manager.execute_command(host, "netstat -tuln | grep LISTEN")
        if result and result['success']:
            security_data['listening_services'] = self._analyze_listening_services(result['stdout'])
        
        return security_data
    
    def _service_fingerprinting(self, host):
        """Service fingerprinting"""
        service_data = {}
        
        # Detailed service fingerprinting with nmap
        cmd = f"nmap -sV --version-intensity 5 -p 22,80,443,3306,5432 {host['ip_address']}"
        result, _ = self.host_manager.execute_command(host, cmd, timeout=60)
        
        if result and result['success']:
            service_data = self._parse_service_fingerprint(result['stdout'])
        
        return service_data
    
    def _snmp_discovery(self, host):
        """SNMP-based infrastructure discovery"""
        snmp_data = {}
        
        # SNMP walk of common MIBs (if SNMP is available)
        communities = ['public', 'private']
        
        for community in communities:
            self._update_progress(f"    🏢 SNMP discovery with community {community}")
            cmd = f"snmpwalk -v2c -c {community} {host['ip_address']} 1.3.6.1.2.1.1 2>/dev/null | head -10"
            result, _ = self.host_manager.execute_command(host, cmd, timeout=30)
            
            if result and result['success'] and result['stdout'].strip():
                snmp_data[community] = result['stdout']
                break  # Stop after first successful community
        
        return snmp_data
    
    def _device_inventory(self, host):
        """Network device inventory"""
        inventory_data = {}
        
        # Get system information
        result, _ = self.host_manager.execute_command(host, "uname -a")
        if result and result['success']:
            inventory_data['system_info'] = result['stdout'].strip()
        
        # Get hardware information
        result, _ = self.host_manager.execute_command(host, "lscpu | head -10")
        if result and result['success']:
            inventory_data['cpu_info'] = result['stdout'].strip()
        
        return inventory_data
    
    def _external_route_analysis(self, host):
        """External route analysis"""
        route_data = {}
        
        # Traceroute to major internet destinations
        destinations = ['8.8.8.8', '1.1.1.1', 'google.com', 'amazonaws.com']
        
        for dest in destinations:
            self._update_progress(f"    🌍 Tracing route to {dest}")
            result, _ = self.host_manager.execute_command(host, f"traceroute -m 10 {dest}", timeout=30)
            
            if result and result['success']:
                route_data[dest] = self._parse_external_traceroute(result['stdout'])
        
        return route_data
    
    def _dns_analysis(self, host):
        """DNS infrastructure analysis"""
        dns_data = {}
        
        # DNS server discovery
        result, _ = self.host_manager.execute_command(host, "cat /etc/resolv.conf")
        if result and result['success']:
            dns_data['dns_servers'] = self._parse_resolv_conf(result['stdout'])
        
        # DNS lookup tests
        test_domains = ['google.com', 'cloudflare.com', 'amazonaws.com']
        dns_data['lookup_tests'] = {}
        
        for domain in test_domains:
            result, _ = self.host_manager.execute_command(host, f"dig {domain} +short")
            if result and result['success']:
                dns_data['lookup_tests'][domain] = result['stdout'].strip().split('\n')
        
        return dns_data
    
    def _public_service_discovery(self, host):
        """CDN and public service discovery"""
        service_data = {}
        
        # Test connectivity to major CDNs and services
        services = {
            'cloudflare': '1.1.1.1',
            'google_dns': '8.8.8.8',
            'aws_dns': '8.8.4.4',
            'quad9': '9.9.9.9'
        }
        
        service_data['connectivity_tests'] = {}
        
        for service, ip in services.items():
            result, _ = self.host_manager.execute_command(host, f"ping -c 3 {ip}")
            if result and result['success']:
                service_data['connectivity_tests'][service] = self._parse_ping_results(result['stdout'])
        
        return service_data
    
    # Parsing helper methods
    def _parse_nmap_xml_output(self, output):
        """Parse nmap XML output"""
        # This would parse nmap XML output - simplified for now
        return {'raw_output': output[:1000]}
    
    def _parse_arp_table(self, output):
        """Parse ARP table output"""
        arp_entries = []
        for line in output.split('\n'):
            if '(' in line and ')' in line and 'at' in line:
                parts = line.split()
                if len(parts) >= 4:
                    hostname = parts[0] if parts[0] != '?' else 'unknown'
                    ip = parts[1][1:-1] if parts[1].startswith('(') else parts[1]
                    mac = parts[3]
                    arp_entries.append({'hostname': hostname, 'ip': ip, 'mac': mac})
        
        return arp_entries
    
    def _parse_arp_scan(self, output):
        """Parse arp-scan output"""
        hosts = []
        for line in output.split('\n'):
            if '\t' in line and '.' in line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    hosts.append({
                        'ip': parts[0].strip(),
                        'mac': parts[1].strip(),
                        'vendor': parts[2].strip() if len(parts) > 2 else 'unknown'
                    })
        
        return hosts
    
    def _parse_routing_table(self, output):
        """Parse routing table"""
        routes = []
        for line in output.split('\n'):
            if line.strip():
                routes.append(line.strip())
        
        return routes
    
    def _parse_network_interfaces(self, output):
        """Parse network interfaces"""
        interfaces = {}
        current_interface = None
        
        for line in output.split('\n'):
            if line and not line.startswith(' '):
                if ':' in line:
                    current_interface = line.split(':')[1].strip()
                    interfaces[current_interface] = []
            elif current_interface and line.strip():
                interfaces[current_interface].append(line.strip())
        
        return interfaces
    
    def _parse_traceroute(self, output):
        """Parse traceroute output"""
        hops = []
        for line in output.split('\n'):
            if line.strip() and line[0].isdigit():
                hops.append(line.strip())
        
        return hops
    
    def _parse_masscan_output(self, output):
        """Parse masscan output"""
        discoveries = []
        for line in output.split('\n'):
            if 'open' in line and 'tcp' in line:
                discoveries.append(line.strip())
        
        return discoveries
    
    def _parse_interface_stats(self, output):
        """Parse interface statistics"""
        stats = {}
        for line in output.split('\n'):
            if ':' in line and '|' not in line:
                parts = line.split()
                if len(parts) > 10:
                    interface = parts[0].replace(':', '')
                    stats[interface] = {
                        'rx_bytes': parts[1],
                        'tx_bytes': parts[9]
                    }
        
        return stats
    
    def _parse_interface_details(self, output):
        """Parse interface details"""
        return {'raw_output': output[:500]}
    
    def _parse_socket_stats(self, output):
        """Parse socket statistics"""
        sockets = []
        for line in output.split('\n'):
            if line.strip() and ('LISTEN' in line or ':' in line):
                sockets.append(line.strip())
        
        return sockets
    
    def _parse_active_connections(self, output):
        """Parse active connections"""
        connections = []
        for line in output.split('\n'):
            if line.strip() and ':' in line:
                connections.append(line.strip())
        
        return connections
    
    def _parse_protocol_hierarchy(self, output):
        """Parse protocol hierarchy from tshark"""
        return {'raw_output': output}
    
    def _parse_iftop_output(self, output):
        """Parse iftop output"""
        return {'raw_output': output[:500]}
    
    def _parse_top_output(self, output):
        """Parse top command output"""
        lines = output.split('\n')
        load_line = [line for line in lines if 'load average' in line]
        mem_line = [line for line in lines if 'KiB Mem' in line or 'MiB Mem' in line]
        
        return {
            'load_average': load_line[0] if load_line else '',
            'memory': mem_line[0] if mem_line else ''
        }
    
    def _parse_iostat_output(self, output):
        """Parse iostat output"""
        return {'raw_output': output}
    
    def _analyze_listening_services(self, output):
        """Analyze listening services for security"""
        services = []
        for line in output.split('\n'):
            if 'LISTEN' in line:
                services.append(line.strip())
        
        return services
    
    def _parse_service_fingerprint(self, output):
        """Parse service fingerprinting results"""
        return {'raw_output': output}
    
    def _parse_external_traceroute(self, output):
        """Parse external traceroute"""
        hops = []
        for line in output.split('\n'):
            if line.strip() and line[0].isdigit():
                hops.append(line.strip())
        
        return hops
    
    def _parse_resolv_conf(self, output):
        """Parse resolv.conf"""
        dns_servers = []
        for line in output.split('\n'):
            if line.startswith('nameserver'):
                parts = line.split()
                if len(parts) > 1:
                    dns_servers.append(parts[1])
        
        return dns_servers
    
    def _parse_ping_results(self, output):
        """Parse ping results"""
        lines = output.split('\n')
        summary = [line for line in lines if 'packet loss' in line]
        
        return {
            'summary': summary[0] if summary else '',
            'raw_output': output[:200]
        }
    
    def _store_enhanced_scan_results(self, host, results):
        """Store comprehensive scan results in database"""
        try:
            # Store in a dedicated table for enhanced scan results
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS enhanced_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    scan_timestamp TEXT,
                    scan_data TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            self.db.execute('''
                INSERT INTO enhanced_scan_results (host_id, scan_timestamp, scan_data)
                VALUES (?, ?, ?)
            ''', (host['id'], datetime.now().isoformat(), json.dumps(results, default=str)))
            
            self._update_progress(f"✅ Stored enhanced scan results for {host['name']}")
            
        except Exception as e:
            self._update_progress(f"❌ Error storing scan results: {e}")
    
    def get_enhanced_topology_data(self):
        """Generate enhanced topology data from scan results"""
        self._update_progress("🗺️ Generating enhanced topology from scan data")
        
        try:
            # Get recent enhanced scan results
            results = self.db.execute('''
                SELECT host_id, scan_data FROM enhanced_scan_results 
                WHERE scan_timestamp > datetime('now', '-24 hours')
                ORDER BY scan_timestamp DESC
            ''').fetchall()
            
            topology_data = {
                'nodes': [],
                'edges': [],
                'metadata': {
                    'scan_count': len(results),
                    'generated_at': datetime.now().isoformat()
                }
            }
            
            host_data = {}
            all_discovered_ips = set()
            
            # Process scan results
            for row in results:
                try:
                    scan_data = json.loads(row['scan_data'])
                    host_info = scan_data['host_info']
                    host_data[host_info['id']] = scan_data
                    
                    # Collect discovered IPs
                    if 'network_topology' in scan_data:
                        topology = scan_data['network_topology']
                        for network_scan in topology.values():
                            if isinstance(network_scan, dict) and 'alive_hosts' in network_scan:
                                all_discovered_ips.update(network_scan['alive_hosts'])
                    
                except Exception as e:
                    self._update_progress(f"❌ Error processing scan data: {e}")
                    continue
            
            # Create enhanced nodes
            for host_id, scan_data in host_data.items():
                host_info = scan_data['host_info']
                
                # Calculate node properties based on scan data
                node = {
                    'id': f"host_{host_id}",
                    'label': host_info['name'],
                    'ip': host_info['ip_address'],
                    'type': 'managed_host',
                    'size': 30,
                    'color': {'background': '#4CAF50', 'border': '#2E7D32'},
                    'shape': 'dot',
                    'metadata': {
                        'scan_timestamp': scan_data['timestamp'],
                        'tools_used': scan_data.get('tools_used', []),
                        'performance': scan_data.get('performance_metrics', {}),
                        'security': scan_data.get('security_info', {}),
                        'infrastructure': scan_data.get('infrastructure_data', {})
                    }
                }
                
                topology_data['nodes'].append(node)
            
            # Add discovered hosts as nodes
            managed_ips = {scan_data['host_info']['ip_address'] for scan_data in host_data.values()}
            discovered_count = 0
            
            for ip in all_discovered_ips:
                if ip not in managed_ips and discovered_count < 50:  # Limit discovered nodes
                    topology_data['nodes'].append({
                        'id': f"discovered_{ip.replace('.', '_')}",
                        'label': ip,
                        'ip': ip,
                        'type': 'discovered_host',
                        'size': 15,
                        'color': {'background': '#FF9800', 'border': '#F57C00'},
                        'shape': 'triangle'
                    })
                    discovered_count += 1
            
            # Create edges based on network relationships
            for host_id, scan_data in host_data.items():
                host_ip = scan_data['host_info']['ip_address']
                host_node_id = f"host_{host_id}"
                
                # Add edges to discovered hosts in same network
                if 'network_topology' in scan_data:
                    for network, network_data in scan_data['network_topology'].items():
                        if isinstance(network_data, dict) and 'alive_hosts' in network_data:
                            for discovered_ip in network_data['alive_hosts']:
                                if discovered_ip != host_ip:
                                    discovered_node_id = f"discovered_{discovered_ip.replace('.', '_')}"
                                    
                                    topology_data['edges'].append({
                                        'from': host_node_id,
                                        'to': discovered_node_id,
                                        'label': 'local network',
                                        'color': {'color': '#4CAF50'},
                                        'width': 2,
                                        'dashes': False
                                    })
            
            # Add internet connectivity edges
            for host_id, scan_data in host_data.items():
                if 'internet_connectivity' in scan_data:
                    host_node_id = f"host_{host_id}"
                    
                    # Add internet node if not exists
                    internet_node_exists = any(node['id'] == 'internet' for node in topology_data['nodes'])
                    if not internet_node_exists:
                        topology_data['nodes'].append({
                            'id': 'internet',
                            'label': 'Internet',
                            'type': 'internet',
                            'size': 40,
                            'color': {'background': '#2196F3', 'border': '#1565C0'},
                            'shape': 'star'
                        })
                    
                    # Add edge to internet
                    topology_data['edges'].append({
                        'from': host_node_id,
                        'to': 'internet',
                        'label': 'internet',
                        'color': {'color': '#2196F3'},
                        'width': 3,
                        'dashes': True
                    })
            
            self._update_progress(f"✅ Generated enhanced topology with {len(topology_data['nodes'])} nodes and {len(topology_data['edges'])} edges")
            return topology_data
            
        except Exception as e:
            self._update_progress(f"❌ Error generating enhanced topology: {e}")
            return {'nodes': [], 'edges': [], 'error': str(e)}
