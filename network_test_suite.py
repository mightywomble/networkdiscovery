#!/usr/bin/env python3
"""
Network Test Suite Definition
Defines all available network tests that can be run by agents
Based on the comprehensive network scanning functionality
"""

import subprocess
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import ipaddress
import socket

class NetworkTestSuite:
    """Defines all network tests available for agent execution"""
    
    # Define all available test categories and their individual tests
    TEST_DEFINITIONS = {
        'network_discovery': {
            'name': 'Network Discovery',
            'description': 'Discover network topology, hosts, and services',
            'required_tools': ['nmap', 'arp-scan', 'fping'],
            'tests': {
                'port_scan': {
                    'name': 'Port Scanning',
                    'description': 'Scan for open ports on local network',
                    'tool': 'nmap',
                    'enabled': True
                },
                'arp_discovery': {
                    'name': 'ARP Table Discovery',
                    'description': 'Discover hosts via ARP table and scanning',
                    'tool': 'arp-scan',
                    'enabled': True
                },
                'ping_sweep': {
                    'name': 'Ping Sweep',
                    'description': 'Fast ping sweep to find alive hosts',
                    'tool': 'fping',
                    'enabled': True
                },
                'route_analysis': {
                    'name': 'Route Analysis',
                    'description': 'Analyze network routes and topology',
                    'tool': 'ip',
                    'enabled': True
                },
                'masscan_discovery': {
                    'name': 'Fast Port Discovery',
                    'description': 'Rapid port scanning with masscan',
                    'tool': 'masscan',
                    'enabled': False  # Optional high-speed tool
                }
            }
        },
        'traffic_analysis': {
            'name': 'Traffic Analysis',
            'description': 'Analyze network traffic and connections',
            'required_tools': ['netstat', 'ss'],
            'optional_tools': ['tcpdump', 'tshark', 'iftop', 'nethogs'],
            'tests': {
                'interface_stats': {
                    'name': 'Interface Statistics',
                    'description': 'Analyze network interface statistics',
                    'tool': 'ip',
                    'enabled': True
                },
                'connection_analysis': {
                    'name': 'Connection Analysis',
                    'description': 'Analyze active network connections',
                    'tool': 'ss',
                    'enabled': True
                },
                'protocol_analysis': {
                    'name': 'Protocol Analysis',
                    'description': 'Short traffic capture and protocol analysis',
                    'tool': 'tshark',
                    'enabled': False  # Requires elevated privileges
                },
                'bandwidth_monitoring': {
                    'name': 'Bandwidth Monitoring',
                    'description': 'Monitor bandwidth usage by process',
                    'tool': 'nethogs',
                    'enabled': False  # Resource intensive
                },
                'vnstat_history': {
                    'name': 'Historical Traffic',
                    'description': 'Get historical network traffic data',
                    'tool': 'vnstat',
                    'enabled': True
                }
            }
        },
        'performance_testing': {
            'name': 'Performance Testing',
            'description': 'Test network and system performance',
            'required_tools': [],
            'optional_tools': ['iperf3', 'speedtest', 'mtr'],
            'tests': {
                'system_performance': {
                    'name': 'System Performance',
                    'description': 'Check CPU, memory, and I/O performance',
                    'tool': 'built-in',
                    'enabled': True
                },
                'network_latency': {
                    'name': 'Network Latency',
                    'description': 'Test latency to key destinations with MTR',
                    'tool': 'mtr',
                    'enabled': True
                },
                'internet_speed': {
                    'name': 'Internet Speed Test',
                    'description': 'Test internet download/upload speed',
                    'tool': 'speedtest',
                    'enabled': False  # Can consume bandwidth
                },
                'iperf_throughput': {
                    'name': 'Network Throughput',
                    'description': 'Test network throughput with iperf3',
                    'tool': 'iperf3',
                    'enabled': False  # Requires server setup
                }
            }
        },
        'security_analysis': {
            'name': 'Security Analysis',
            'description': 'Perform security-focused network analysis',
            'required_tools': [],
            'optional_tools': ['ngrep', 'p0f'],
            'tests': {
                'open_ports_analysis': {
                    'name': 'Open Ports Analysis',
                    'description': 'Analyze open ports for security risks',
                    'tool': 'nmap',
                    'enabled': True
                },
                'service_fingerprinting': {
                    'name': 'Service Fingerprinting',
                    'description': 'Identify services and versions',
                    'tool': 'nmap',
                    'enabled': True
                },
                'passive_fingerprinting': {
                    'name': 'Passive OS Fingerprinting',
                    'description': 'Passively identify operating systems',
                    'tool': 'p0f',
                    'enabled': False  # Requires packet capture
                },
                'vulnerability_scan': {
                    'name': 'Basic Vulnerability Scan',
                    'description': 'Basic vulnerability detection with nmap scripts',
                    'tool': 'nmap',
                    'enabled': False  # Can be intrusive
                }
            }
        },
        'infrastructure_discovery': {
            'name': 'Infrastructure Discovery',
            'description': 'Discover network infrastructure and devices',
            'required_tools': [],
            'optional_tools': ['snmpwalk', 'snmpget'],
            'tests': {
                'snmp_discovery': {
                    'name': 'SNMP Discovery',
                    'description': 'Discover SNMP-enabled devices',
                    'tool': 'snmpwalk',
                    'enabled': False  # May not be available
                },
                'device_inventory': {
                    'name': 'Device Inventory',
                    'description': 'Inventory network devices and services',
                    'tool': 'nmap',
                    'enabled': True
                },
                'dns_analysis': {
                    'name': 'DNS Analysis',
                    'description': 'Analyze DNS configuration and resolution',
                    'tool': 'dig',
                    'enabled': True
                }
            }
        },
        'connectivity_analysis': {
            'name': 'Connectivity Analysis',
            'description': 'Analyze internet and external connectivity',
            'required_tools': ['ping', 'traceroute'],
            'tests': {
                'external_connectivity': {
                    'name': 'External Connectivity',
                    'description': 'Test connectivity to external services',
                    'tool': 'ping',
                    'enabled': True
                },
                'dns_resolution': {
                    'name': 'DNS Resolution',
                    'description': 'Test DNS resolution to various servers',
                    'tool': 'nslookup',
                    'enabled': True
                },
                'traceroute_analysis': {
                    'name': 'Route Tracing',
                    'description': 'Trace routes to external destinations',
                    'tool': 'traceroute',
                    'enabled': True
                },
                'cdn_detection': {
                    'name': 'CDN Detection',
                    'description': 'Detect CDN usage and geographic routing',
                    'tool': 'dig',
                    'enabled': True
                }
            }
        }
    }
    
    # Default enabled tests for new agent installations
    DEFAULT_ENABLED_TESTS = {
        'network_discovery': ['port_scan', 'arp_discovery', 'ping_sweep', 'route_analysis'],
        'traffic_analysis': ['interface_stats', 'connection_analysis', 'vnstat_history'],
        'performance_testing': ['system_performance', 'network_latency'],
        'security_analysis': ['open_ports_analysis', 'service_fingerprinting'],
        'infrastructure_discovery': ['device_inventory', 'dns_analysis'],
        'connectivity_analysis': ['external_connectivity', 'dns_resolution', 'traceroute_analysis', 'cdn_detection']
    }
    
    # Tool installation commands for Debian/Ubuntu systems
    TOOL_INSTALL_COMMANDS = {
        'nmap': 'apt-get install -y nmap',
        'arp-scan': 'apt-get install -y arp-scan',
        'fping': 'apt-get install -y fping',
        'masscan': 'apt-get install -y masscan',
        'tcpdump': 'apt-get install -y tcpdump',
        'tshark': 'apt-get install -y tshark',
        'wireshark-common': 'apt-get install -y wireshark-common',
        'iftop': 'apt-get install -y iftop',
        'nethogs': 'apt-get install -y nethogs',
        'bmon': 'apt-get install -y bmon',
        'vnstat': 'apt-get install -y vnstat',
        'htop': 'apt-get install -y htop',
        'iotop': 'apt-get install -y iotop',
        'iperf3': 'apt-get install -y iperf3',
        'speedtest': 'apt-get install -y speedtest-cli',
        'mtr': 'apt-get install -y mtr-tiny',
        'snmpwalk': 'apt-get install -y snmp',
        'snmpget': 'apt-get install -y snmp',
        'snmp-mibs-downloader': 'apt-get install -y snmp-mibs-downloader',
        'ngrep': 'apt-get install -y ngrep',
        'p0f': 'apt-get install -y p0f',
        'dig': 'apt-get install -y dnsutils',
        'nslookup': 'apt-get install -y dnsutils',
        'traceroute': 'apt-get install -y traceroute'
    }
    
    @classmethod
    def get_all_test_categories(cls) -> Dict[str, Any]:
        """Get all test categories and their definitions"""
        return cls.TEST_DEFINITIONS
    
    @classmethod
    def get_test_category(cls, category: str) -> Optional[Dict[str, Any]]:
        """Get a specific test category"""
        return cls.TEST_DEFINITIONS.get(category)
    
    @classmethod
    def get_all_required_tools(cls) -> List[str]:
        """Get all tools that are required across all test categories"""
        required = set()
        for category in cls.TEST_DEFINITIONS.values():
            required.update(category.get('required_tools', []))
        return sorted(list(required))
    
    @classmethod
    def get_all_optional_tools(cls) -> List[str]:
        """Get all optional tools across all test categories"""
        optional = set()
        for category in cls.TEST_DEFINITIONS.values():
            optional.update(category.get('optional_tools', []))
        return sorted(list(optional))
    
    @classmethod
    def get_all_tools(cls) -> List[str]:
        """Get all tools (required + optional)"""
        all_tools = set(cls.get_all_required_tools())
        all_tools.update(cls.get_all_optional_tools())
        # Add tools mentioned in test definitions
        for category in cls.TEST_DEFINITIONS.values():
            for test in category.get('tests', {}).values():
                if test.get('tool') and test['tool'] not in ['built-in', 'ip']:
                    all_tools.add(test['tool'])
        return sorted(list(all_tools))
    
    @classmethod
    def get_default_configuration(cls) -> Dict[str, Dict[str, bool]]:
        """Get default test configuration for new agents"""
        config = {}
        for category_name, enabled_tests in cls.DEFAULT_ENABLED_TESTS.items():
            config[category_name] = {}
            category = cls.TEST_DEFINITIONS.get(category_name, {})
            for test_name, test_def in category.get('tests', {}).items():
                config[category_name][test_name] = test_name in enabled_tests
        return config
    
    @classmethod
    def validate_configuration(cls, config: Dict[str, Dict[str, bool]]) -> List[str]:
        """Validate a test configuration and return any errors"""
        errors = []
        
        for category_name, tests in config.items():
            if category_name not in cls.TEST_DEFINITIONS:
                errors.append(f"Unknown test category: {category_name}")
                continue
            
            category_def = cls.TEST_DEFINITIONS[category_name]
            for test_name, enabled in tests.items():
                if test_name not in category_def.get('tests', {}):
                    errors.append(f"Unknown test '{test_name}' in category '{category_name}'")
                
                if not isinstance(enabled, bool):
                    errors.append(f"Test '{test_name}' in category '{category_name}' must be true/false")
        
        return errors
    
    @classmethod
    def get_tools_for_configuration(cls, config: Dict[str, Dict[str, bool]]) -> List[str]:
        """Get list of tools needed for a specific test configuration"""
        needed_tools = set()
        
        for category_name, tests in config.items():
            if category_name not in cls.TEST_DEFINITIONS:
                continue
            
            category_def = cls.TEST_DEFINITIONS[category_name]
            
            # Check if any tests in this category are enabled
            category_enabled = any(tests.values())
            if not category_enabled:
                continue
            
            # Add required tools for this category
            needed_tools.update(category_def.get('required_tools', []))
            
            # Add tools for enabled individual tests
            for test_name, enabled in tests.items():
                if enabled and test_name in category_def.get('tests', {}):
                    test_def = category_def['tests'][test_name]
                    tool = test_def.get('tool')
                    if tool and tool not in ['built-in', 'ip']:
                        needed_tools.add(tool)
        
        return sorted(list(needed_tools))
    
    @classmethod
    def check_tool_availability(cls, tools: List[str]) -> Dict[str, bool]:
        """Check which tools are available on the system"""
        availability = {}
        
        for tool in tools:
            try:
                # Try to run the tool with a version or help flag
                result = subprocess.run([tool, '--version'], 
                                      capture_output=True, 
                                      timeout=5)
                availability[tool] = result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError):
                # Try alternative check methods
                try:
                    result = subprocess.run(['which', tool], 
                                          capture_output=True, 
                                          timeout=5)
                    availability[tool] = result.returncode == 0
                except:
                    availability[tool] = False
        
        return availability
    
    @classmethod
    def generate_installation_script(cls, missing_tools: List[str]) -> str:
        """Generate installation script for missing tools"""
        if not missing_tools:
            return "# All required tools are already installed"
        
        install_commands = []
        install_commands.append("#!/bin/bash")
        install_commands.append("# Network testing tools installation script")
        install_commands.append("set -e")
        install_commands.append("")
        install_commands.append("echo 'Installing network testing tools...'")
        install_commands.append("apt-get update -qq")
        install_commands.append("")
        
        for tool in missing_tools:
            if tool in cls.TOOL_INSTALL_COMMANDS:
                install_commands.append(f"echo 'Installing {tool}...'")
                install_commands.append(cls.TOOL_INSTALL_COMMANDS[tool])
                install_commands.append("")
        
        # Special post-installation configuration
        install_commands.append("# Post-installation configuration")
        
        if 'vnstat' in missing_tools:
            install_commands.extend([
                "echo 'Configuring vnstat...'",
                "INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)",
                "if [ ! -z \"$INTERFACE\" ]; then",
                "    vnstat -u -i $INTERFACE 2>/dev/null || true",
                "    systemctl enable vnstat 2>/dev/null || true",
                "    systemctl start vnstat 2>/dev/null || true",
                "fi",
                ""
            ])
        
        if 'snmp-mibs-downloader' in missing_tools:
            install_commands.extend([
                "echo 'Downloading SNMP MIBs...'",
                "download-mibs 2>/dev/null || true",
                ""
            ])
        
        install_commands.append("echo 'Network testing tools installation completed!'")
        
        return "\n".join(install_commands)
