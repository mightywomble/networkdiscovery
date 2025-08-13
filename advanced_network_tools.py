#!/usr/bin/env python3
"""
Advanced Network Tools Integration
Leverages Ubuntu network analysis tools for comprehensive network discovery
"""

import subprocess
import json
import re
import socket
import time
from datetime import datetime
from collections import defaultdict
import xml.etree.ElementTree as ET


class AdvancedNetworkTools:
    def __init__(self, host_manager, database):
        self.host_manager = host_manager
        self.db = database
        self.tools_available = {}
        self._check_tool_availability()
    
    def _check_tool_availability(self):
        """Check which network tools are available on each host"""
        tools_to_check = [
            'nmap', 'traceroute', 'mtr', 'arp-scan', 'fping',
            'tcpdump', 'tshark', 'iftop', 'nethogs', 'vnstat',
            'iperf3', 'netperf', 'speedtest', 'snmpwalk',
            'ngrep', 'p0f', 'masscan', 'bmon'
        ]
        
        hosts = self.host_manager.get_all_hosts()
        for host in hosts:
            if host.get('status') != 'online':
                continue
                
            host_tools = {}
            for tool in tools_to_check:
                result, _ = self.host_manager.execute_command(host, f"which {tool}")
                host_tools[tool] = result and result['success']
            
            self.tools_available[host['id']] = host_tools
            print(f"Available tools on {host['name']}: {sum(host_tools.values())}/{len(tools_to_check)}")
    
    def advanced_network_discovery(self, host):
        """Perform advanced network discovery using available tools"""
        discovery_data = {
            'host_id': host['id'],
            'timestamp': datetime.now().isoformat(),
            'advanced_topology': {},
            'traffic_analysis': {},
            'performance_metrics': {},
            'security_scan': {},
            'bandwidth_analysis': {},
            'network_flows': {}
        }
        
        # Get available tools for this host
        available_tools = self.tools_available.get(host['id'], {})
        
        print(f"Running advanced discovery on {host['name']}")
        
        # 1. Advanced Network Topology Discovery
        if available_tools.get('nmap'):
            discovery_data['advanced_topology'].update(self._nmap_topology_scan(host))
        
        if available_tools.get('arp-scan'):
            discovery_data['advanced_topology'].update(self._arp_scan_discovery(host))
        
        if available_tools.get('fping'):
            discovery_data['advanced_topology'].update(self._fping_subnet_discovery(host))
        
        # 2. Traffic Analysis
        if available_tools.get('tshark'):
            discovery_data['traffic_analysis'].update(self._tshark_traffic_analysis(host))
        
        if available_tools.get('vnstat'):
            discovery_data['traffic_analysis'].update(self._vnstat_bandwidth_history(host))
        
        if available_tools.get('iftop'):
            discovery_data['traffic_analysis'].update(self._iftop_realtime_connections(host))
        
        # 3. Performance Metrics
        if available_tools.get('mtr'):
            discovery_data['performance_metrics'].update(self._mtr_network_performance(host))
        
        if available_tools.get('iperf3'):
            discovery_data['performance_metrics'].update(self._iperf3_bandwidth_test(host))
        
        # 4. Security Analysis
        if available_tools.get('ngrep'):
            discovery_data['security_scan'].update(self._ngrep_protocol_analysis(host))
        
        if available_tools.get('p0f'):
            discovery_data['security_scan'].update(self._p0f_passive_fingerprinting(host))
        
        # 5. SNMP Discovery (if available)
        if available_tools.get('snmpwalk'):
            discovery_data['advanced_topology'].update(self._snmp_infrastructure_discovery(host))
        
        # Store the advanced discovery data
        self.db.save_network_discovery(host['id'], 'advanced_tools', discovery_data)
        
        return discovery_data
    
    def _nmap_topology_scan(self, host):
        """Advanced nmap scanning for network topology"""
        topology_data = {}
        
        # Get local networks from host
        result, _ = self.host_manager.execute_command(host, "ip route show | grep -E '^[0-9]+\\.[0-9]+\\.' | head -5")
        if not (result and result['success']):
            return topology_data
        
        networks = []
        for line in result['stdout'].strip().split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if match:
                networks.append(match.group(1))
        
        for network in networks[:3]:  # Limit to first 3 networks
            print(f"  Scanning network {network} with nmap...")
            
            # Comprehensive nmap scan
            nmap_cmd = f"nmap -sS -O -sV --version-intensity 5 -T4 --top-ports 1000 {network}"
            result, _ = self.host_manager.execute_command(host, nmap_cmd, timeout=300)
            
            if result and result['success']:
                topology_data[f'nmap_scan_{network}'] = {
                    'network': network,
                    'scan_results': self._parse_nmap_xml_alternative(result['stdout']),
                    'discovered_hosts': self._extract_nmap_hosts(result['stdout']),
                    'os_detection': self._extract_nmap_os_info(result['stdout']),
                    'service_detection': self._extract_nmap_services(result['stdout'])
                }
        
        return topology_data
    
    def _arp_scan_discovery(self, host):
        """Use arp-scan for local network discovery"""
        arp_data = {}
        
        # Get network interfaces
        result, _ = self.host_manager.execute_command(host, "ip route show | grep -E '^[0-9]+\\.[0-9]+\\.' | head -3")
        if not (result and result['success']):
            return arp_data
        
        networks = []
        for line in result['stdout'].strip().split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if match:
                networks.append(match.group(1))
        
        for network in networks:
            print(f"  ARP scanning {network}...")
            result, _ = self.host_manager.execute_command(host, f"arp-scan -l {network}")
            
            if result and result['success']:
                arp_data[f'arp_scan_{network}'] = {
                    'network': network,
                    'discovered_devices': self._parse_arp_scan(result['stdout']),
                    'vendor_info': self._extract_mac_vendors(result['stdout'])
                }
        
        return arp_data
    
    def _tshark_traffic_analysis(self, host):
        """Use tshark for traffic analysis"""
        traffic_data = {}
        
        print(f"  Analyzing traffic with tshark...")
        
        # Capture traffic for 30 seconds and analyze
        tshark_cmd = "timeout 30s tshark -i any -T fields -e ip.src -e ip.dst -e tcp.dstport -e udp.dstport -e frame.protocols"
        result, _ = self.host_manager.execute_command(host, tshark_cmd)
        
        if result and result['success']:
            traffic_data['packet_analysis'] = self._parse_tshark_output(result['stdout'])
            traffic_data['protocol_distribution'] = self._analyze_protocol_distribution(result['stdout'])
            traffic_data['connection_patterns'] = self._analyze_connection_patterns(result['stdout'])
        
        return traffic_data
    
    def _mtr_network_performance(self, host):
        """Use mtr for network performance analysis"""
        performance_data = {}
        
        # Test connectivity to common destinations
        destinations = ['8.8.8.8', '1.1.1.1', 'google.com', 'github.com']
        
        for dest in destinations:
            print(f"  MTR analysis to {dest}...")
            result, _ = self.host_manager.execute_command(host, f"mtr -r -c 10 {dest}")
            
            if result and result['success']:
                performance_data[f'mtr_{dest}'] = {
                    'destination': dest,
                    'route_analysis': self._parse_mtr_output(result['stdout']),
                    'latency_stats': self._extract_mtr_latency(result['stdout']),
                    'packet_loss': self._extract_mtr_loss(result['stdout'])
                }
        
        return performance_data
    
    def _vnstat_bandwidth_history(self, host):
        """Get bandwidth usage history with vnstat"""
        bandwidth_data = {}
        
        # Get interface list
        result, _ = self.host_manager.execute_command(host, "vnstat --iflist")
        if not (result and result['success']):
            return bandwidth_data
        
        # Get bandwidth stats for each interface
        result, _ = self.host_manager.execute_command(host, "vnstat -i eth0 --json")  # Assuming eth0
        if result and result['success']:
            try:
                vnstat_json = json.loads(result['stdout'])
                bandwidth_data['historical_usage'] = vnstat_json
            except json.JSONDecodeError:
                pass
        
        return bandwidth_data
    
    def _snmp_infrastructure_discovery(self, host):
        """Discover network infrastructure using SNMP"""
        snmp_data = {}
        
        # Common SNMP-enabled devices to check
        networks = self._get_local_networks(host)
        
        for network in networks[:2]:  # Limit scanning
            print(f"  SNMP discovery on {network}...")
            
            # Scan for SNMP-enabled devices
            result, _ = self.host_manager.execute_command(
                host, 
                f"nmap -sU -p 161 --open {network} | grep -B4 'open'"
            )
            
            if result and result['success']:
                snmp_hosts = self._extract_snmp_hosts(result['stdout'])
                
                for snmp_host in snmp_hosts[:5]:  # Limit to 5 hosts
                    # Query SNMP information
                    snmp_result, _ = self.host_manager.execute_command(
                        host,
                        f"snmpwalk -v2c -c public {snmp_host} 1.3.6.1.2.1.1"
                    )
                    
                    if snmp_result and snmp_result['success']:
                        snmp_data[snmp_host] = self._parse_snmp_system_info(snmp_result['stdout'])
        
        return snmp_data
    
    def _parse_nmap_xml_alternative(self, nmap_output):
        """Parse nmap output (text format)"""
        hosts_data = []
        current_host = None
        
        for line in nmap_output.split('\n'):
            line = line.strip()
            
            # Host detection
            if 'Nmap scan report for' in line:
                if current_host:
                    hosts_data.append(current_host)
                
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                current_host = {
                    'ip': ip_match.group(1) if ip_match else 'unknown',
                    'ports': [],
                    'os': '',
                    'services': []
                }
            
            # Port detection
            elif '/tcp' in line and 'open' in line:
                port_match = re.search(r'(\d+)/tcp\s+(\w+)\s+(\w+)', line)
                if port_match and current_host:
                    current_host['ports'].append({
                        'port': int(port_match.group(1)),
                        'state': port_match.group(2),
                        'service': port_match.group(3)
                    })
        
        if current_host:
            hosts_data.append(current_host)
        
        return hosts_data
    
    def _parse_arp_scan(self, arp_output):
        """Parse arp-scan output"""
        devices = []
        
        for line in arp_output.split('\n'):
            if re.match(r'\d+\.\d+\.\d+\.\d+', line.strip()):
                parts = line.strip().split('\t')
                if len(parts) >= 2:
                    devices.append({
                        'ip': parts[0],
                        'mac': parts[1],
                        'vendor': parts[2] if len(parts) > 2 else 'Unknown'
                    })
        
        return devices
    
    def _parse_tshark_output(self, tshark_output):
        """Parse tshark traffic capture"""
        connections = defaultdict(int)
        protocols = defaultdict(int)
        
        for line in tshark_output.split('\n'):
            if line.strip():
                fields = line.strip().split('\t')
                if len(fields) >= 3:
                    src_ip = fields[0]
                    dst_ip = fields[1]
                    
                    if src_ip and dst_ip:
                        conn_key = f"{src_ip} -> {dst_ip}"
                        connections[conn_key] += 1
                        
                        if len(fields) > 4:
                            protocol = fields[4].split(':')[0] if ':' in fields[4] else fields[4]
                            protocols[protocol] += 1
        
        return {
            'top_connections': dict(sorted(connections.items(), key=lambda x: x[1], reverse=True)[:20]),
            'protocol_stats': dict(protocols)
        }
    
    def _parse_mtr_output(self, mtr_output):
        """Parse MTR network route analysis"""
        hops = []
        
        for line in mtr_output.split('\n'):
            if re.match(r'^\s*\d+\.', line):
                parts = line.strip().split()
                if len(parts) >= 7:
                    hops.append({
                        'hop': int(float(parts[0])),
                        'hostname': parts[1],
                        'loss_pct': float(parts[2].rstrip('%')),
                        'avg_latency': float(parts[5])
                    })
        
        return hops
    
    def _get_local_networks(self, host):
        """Get local networks from host routing table"""
        result, _ = self.host_manager.execute_command(host, "ip route show | grep -E '^[0-9]+\\.[0-9]+\\.'")
        if not (result and result['success']):
            return []
        
        networks = []
        for line in result['stdout'].strip().split('\n'):
            match = re.search(r'(\d+\.\d+\.\d+\.\d+/\d+)', line)
            if match:
                networks.append(match.group(1))
        
        return networks
    
    def generate_advanced_topology_report(self):
        """Generate comprehensive network topology report from advanced tools"""
        hosts = self.host_manager.get_all_hosts()
        
        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'infrastructure_map': {},
            'performance_analysis': {},
            'security_overview': {},
            'traffic_patterns': {},
            'recommendations': []
        }
        
        for host in hosts:
            if host.get('status') != 'online':
                continue
            
            # Get advanced discovery data
            discovery_data = self.db.get_network_discovery(host['id'], 'advanced_tools', hours=24)
            
            if discovery_data:
                latest_data = discovery_data[0].get('discovery_data', {})
                
                report['infrastructure_map'][host['name']] = latest_data.get('advanced_topology', {})
                report['performance_analysis'][host['name']] = latest_data.get('performance_metrics', {})
                report['security_overview'][host['name']] = latest_data.get('security_scan', {})
                report['traffic_patterns'][host['name']] = latest_data.get('traffic_analysis', {})
        
        # Generate recommendations
        report['recommendations'] = self._generate_network_recommendations(report)
        
        return report
    
    def _generate_network_recommendations(self, report):
        """Generate network optimization recommendations"""
        recommendations = []
        
        # Analyze infrastructure
        total_hosts = len(report['infrastructure_map'])
        if total_hosts > 0:
            recommendations.append(f"✓ Network scan completed for {total_hosts} hosts")
        
        # Check for security issues
        for host_name, security_data in report['security_overview'].items():
            if security_data:
                recommendations.append(f"🔍 Security analysis available for {host_name}")
        
        # Performance recommendations
        for host_name, perf_data in report['performance_analysis'].items():
            mtr_data = perf_data.get('mtr_8.8.8.8', {})
            if mtr_data.get('route_analysis'):
                avg_latency = sum(hop.get('avg_latency', 0) for hop in mtr_data['route_analysis'])
                if avg_latency > 100:
                    recommendations.append(f"⚠️ High latency detected for {host_name} ({avg_latency:.1f}ms)")
        
        return recommendations
    
    # Missing helper methods
    def _extract_nmap_hosts(self, nmap_output):
        """Extract discovered hosts from nmap output"""
        hosts = []
        for line in nmap_output.split('\n'):
            if 'Nmap scan report for' in line:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                if ip_match:
                    hosts.append(ip_match.group(1))
        return hosts
    
    def _extract_nmap_os_info(self, nmap_output):
        """Extract OS detection info from nmap output"""
        os_info = []
        in_os_section = False
        
        for line in nmap_output.split('\n'):
            if 'OS detection performed' in line:
                in_os_section = True
            elif in_os_section and line.strip():
                if 'OS:' in line or 'Running:' in line:
                    os_info.append(line.strip())
            elif in_os_section and not line.strip():
                in_os_section = False
        
        return os_info
    
    def _extract_nmap_services(self, nmap_output):
        """Extract service detection info from nmap output"""
        services = []
        for line in nmap_output.split('\n'):
            if '/tcp' in line and 'open' in line:
                services.append(line.strip())
        return services
    
    def _extract_mac_vendors(self, arp_output):
        """Extract MAC address vendor information"""
        vendors = {}
        for line in arp_output.split('\n'):
            if re.match(r'\d+\.\d+\.\d+\.\d+', line.strip()):
                parts = line.strip().split('\t')
                if len(parts) >= 3:
                    vendors[parts[1]] = parts[2]
        return vendors
    
    def _fping_subnet_discovery(self, host):
        """Use fping for fast subnet discovery"""
        fping_data = {}
        
        networks = self._get_local_networks(host)
        for network in networks[:2]:  # Limit to 2 networks
            print(f"  FPing sweep of {network}...")
            result, _ = self.host_manager.execute_command(host, f"fping -g {network} -c 1 -t 1000")
            
            if result and result['success']:
                alive_hosts = []
                for line in result['stdout'].split('\n'):
                    if 'alive' in line or 'bytes' in line:
                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if ip_match:
                            alive_hosts.append(ip_match.group(1))
                
                fping_data[f'fping_{network}'] = {
                    'network': network,
                    'alive_hosts': alive_hosts,
                    'total_found': len(alive_hosts)
                }
        
        return fping_data
    
    def _iftop_realtime_connections(self, host):
        """Capture real-time connection data with iftop"""
        # This would require iftop to run in text mode
        # For now, return a placeholder
        return {'note': 'iftop integration would require additional setup'}
    
    def _iperf3_bandwidth_test(self, host):
        """Perform bandwidth testing with iperf3"""
        # This would require iperf3 server setup
        # For now, return a placeholder
        return {'note': 'iperf3 testing requires server setup'}
    
    def _ngrep_protocol_analysis(self, host):
        """Analyze network protocols with ngrep"""
        # This would require running ngrep for a period
        # For now, return a placeholder
        return {'note': 'ngrep analysis requires live capture'}
    
    def _p0f_passive_fingerprinting(self, host):
        """Perform passive OS fingerprinting with p0f"""
        # This would require running p0f in background
        # For now, return a placeholder
        return {'note': 'p0f requires passive monitoring setup'}
    
    def _analyze_protocol_distribution(self, tshark_output):
        """Analyze protocol distribution from tshark output"""
        protocols = defaultdict(int)
        
        for line in tshark_output.split('\n'):
            if line.strip():
                fields = line.strip().split('\t')
                if len(fields) > 4:
                    protocol = fields[4].split(':')[0] if ':' in fields[4] else fields[4]
                    protocols[protocol] += 1
        
        return dict(protocols)
    
    def _analyze_connection_patterns(self, tshark_output):
        """Analyze connection patterns from tshark output"""
        patterns = {
            'top_talkers': defaultdict(int),
            'top_destinations': defaultdict(int),
            'port_usage': defaultdict(int)
        }
        
        for line in tshark_output.split('\n'):
            if line.strip():
                fields = line.strip().split('\t')
                if len(fields) >= 3:
                    src_ip = fields[0]
                    dst_ip = fields[1]
                    
                    if src_ip:
                        patterns['top_talkers'][src_ip] += 1
                    if dst_ip:
                        patterns['top_destinations'][dst_ip] += 1
                    
                    if len(fields) > 2 and fields[2]:
                        patterns['port_usage'][fields[2]] += 1
        
        return dict(patterns)
    
    def _extract_mtr_latency(self, mtr_output):
        """Extract latency statistics from MTR output"""
        latencies = []
        
        for line in mtr_output.split('\n'):
            if re.match(r'^\s*\d+\.', line):
                parts = line.strip().split()
                if len(parts) >= 6:
                    try:
                        avg_latency = float(parts[5])
                        latencies.append(avg_latency)
                    except ValueError:
                        pass
        
        if latencies:
            return {
                'min': min(latencies),
                'max': max(latencies),
                'avg': sum(latencies) / len(latencies),
                'total_hops': len(latencies)
            }
        return {}
    
    def _extract_mtr_loss(self, mtr_output):
        """Extract packet loss statistics from MTR output"""
        losses = []
        
        for line in mtr_output.split('\n'):
            if re.match(r'^\s*\d+\.', line):
                parts = line.strip().split()
                if len(parts) >= 3:
                    try:
                        loss_pct = float(parts[2].rstrip('%'))
                        losses.append(loss_pct)
                    except ValueError:
                        pass
        
        if losses:
            return {
                'max_loss': max(losses),
                'avg_loss': sum(losses) / len(losses),
                'total_loss_points': sum(1 for loss in losses if loss > 0)
            }
        return {}
    
    def _extract_snmp_hosts(self, nmap_output):
        """Extract SNMP-enabled hosts from nmap UDP scan"""
        hosts = []
        for line in nmap_output.split('\n'):
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match and 'open' in line:
                hosts.append(ip_match.group(1))
        return hosts
    
    def _parse_snmp_system_info(self, snmp_output):
        """Parse SNMP system information"""
        info = {}
        
        for line in snmp_output.split('\n'):
            if 'sysDescr' in line:
                info['description'] = line.split('STRING:')[-1].strip() if 'STRING:' in line else ''
            elif 'sysName' in line:
                info['name'] = line.split('STRING:')[-1].strip() if 'STRING:' in line else ''
            elif 'sysLocation' in line:
                info['location'] = line.split('STRING:')[-1].strip() if 'STRING:' in line else ''
            elif 'sysContact' in line:
                info['contact'] = line.split('STRING:')[-1].strip() if 'STRING:' in line else ''
        
        return info


def install_tools_on_hosts(host_manager):
    """Install network analysis tools on all Ubuntu hosts"""
    
    install_script = """
# Update package list
sudo apt update

# Essential network analysis tools
sudo apt install -y nmap traceroute mtr-tiny arp-scan fping masscan
sudo apt install -y tcpdump wireshark-common tshark
sudo apt install -y iftop nethogs iotop htop bmon vnstat
sudo apt install -y iperf3 netperf speedtest-cli
sudo apt install -y snmp snmp-mibs-downloader
sudo apt install -y ngrep p0f

# Configure tools
sudo download-mibs 2>/dev/null || true
sudo vnstat -u -i eth0 2>/dev/null || true

echo "Network analysis tools installation completed"
"""
    
    hosts = host_manager.get_all_hosts()
    results = {}
    
    for host in hosts:
        if host.get('status') != 'online':
            continue
        
        print(f"Installing tools on {host['name']}...")
        
        # Create temporary script file
        result, _ = host_manager.execute_command(host, 'mktemp')
        if not (result and result['success']):
            continue
        
        script_path = result['stdout'].strip()
        
        # Write install script
        write_result, _ = host_manager.execute_command(
            host, 
            f'cat > {script_path} << "EOF"\n{install_script}\nEOF'
        )
        
        if write_result and write_result['success']:
            # Execute install script
            install_result, _ = host_manager.execute_command(host, f'bash {script_path}', timeout=600)
            results[host['name']] = install_result['success'] if install_result else False
        
        # Cleanup
        host_manager.execute_command(host, f'rm -f {script_path}')
    
    return results
