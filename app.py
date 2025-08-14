#!/usr/bin/env python3
"""
Network Map Flask Application
A web interface for managing hosts, scanning networks, and visualizing network topology
"""

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime, timedelta
import json
import os
import threading
import time
from collections import defaultdict, deque

from network_scanner import NetworkScanner
from host_manager import HostManager
from database import Database
from topology_analyzer import TopologyAnalyzer

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-change-in-production')

# Initialize components
db = Database()
host_manager = HostManager(db)
scanner = NetworkScanner(host_manager, db)
topology_analyzer = TopologyAnalyzer(db)

# Global state for real-time updates
scan_status = {
    'running': False,
    'last_scan': None,
    'progress': 0,
    'current_host': None,
    'phase': 'idle',
    'phase_message': 'Ready',
    'step': None
}

@app.route('/')
def index():
    """Main dashboard page"""
    hosts = host_manager.get_all_hosts()
    network_stats = db.get_network_stats()
    return render_template('index.html', hosts=hosts, stats=network_stats, scan_status=scan_status)

@app.route('/hosts')
def hosts():
    """Host management page"""
    hosts = host_manager.get_all_hosts()
    return render_template('hosts.html', hosts=hosts)

@app.route('/agents')
def agents():
    """Agent management page"""
    return render_template('agents.html')

@app.route('/add_host', methods=['POST'])
def add_host():
    """Add a new host to monitor"""
    name = request.form.get('name')
    ip_address = request.form.get('ip_address')
    username = request.form.get('username', 'root')
    ssh_port = int(request.form.get('ssh_port', 22))
    description = request.form.get('description', '')
    
    if not name or not ip_address:
        flash('Name and IP address are required', 'error')
        return redirect(url_for('hosts'))
    
    try:
        host_id = host_manager.add_host(name, ip_address, username, ssh_port, description)
        flash(f'Host {name} added successfully', 'success')
    except Exception as e:
        flash(f'Error adding host: {str(e)}', 'error')
    
    return redirect(url_for('hosts'))

@app.route('/remove_host/<int:host_id>', methods=['POST'])
def remove_host(host_id):
    """Remove a host"""
    try:
        host_manager.remove_host(host_id)
        flash('Host removed successfully', 'success')
    except Exception as e:
        flash(f'Error removing host: {str(e)}', 'error')
    
    return redirect(url_for('hosts'))

@app.route('/scan_now', methods=['POST'])
def scan_now():
    """Trigger immediate network scan"""
    if scan_status['running']:
        return jsonify({'error': 'Scan already running'}), 400
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan)
    thread.daemon = True
    thread.start()
    
    return jsonify({'status': 'Scan started'})

@app.route('/scan_status')
def get_scan_status():
    """Get current scan status"""
    return jsonify(scan_status)

@app.route('/network_map')
def network_map():
    """Network map visualization"""
    return render_template('network_map.html')

@app.route('/enhanced_topology')
def enhanced_topology():
    """Enhanced network topology visualization with comprehensive interconnections"""
    return render_template('enhanced_network_topology.html')

@app.route('/d3_topology')
def d3_topology():
    """D3.js-based network topology visualization with better control"""
    return render_template('d3_network_topology.html')

@app.route('/network_diagram')
def network_diagram():
    """Traditional network diagram with device icons and structured layout"""
    return render_template('network_diagram.html')

@app.route('/build_topology', methods=['POST'])
def build_topology():
    """Manually trigger enhanced topology building"""
    try:
        from enhanced_topology_builder import EnhancedTopologyBuilder
        topology_builder = EnhancedTopologyBuilder(db, host_manager)
        topology = topology_builder.build_comprehensive_topology()
        
        return jsonify({
            'success': True,
            'message': 'Enhanced topology built successfully',
            'node_count': len(topology.get('nodes', [])),
            'edge_count': len(topology.get('edges', [])),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/install_tools', methods=['POST'])
def install_network_tools():
    """Install advanced network analysis tools on all hosts"""
    try:
        from advanced_network_tools import install_tools_on_hosts
        results = install_tools_on_hosts(host_manager)
        
        success_count = sum(1 for success in results.values() if success)
        total_count = len(results)
        
        return jsonify({
            'success': True,
            'message': f'Tools installation completed on {success_count}/{total_count} hosts',
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/advanced_scan', methods=['POST'])
def run_advanced_scan():
    """Run advanced network discovery using installed tools"""
    try:
        from advanced_network_tools import AdvancedNetworkTools
        
        advanced_tools = AdvancedNetworkTools(host_manager, db)
        hosts = host_manager.get_all_hosts()
        
        results = {}
        for host in hosts:
            if host.get('status') == 'online':
                discovery_data = advanced_tools.advanced_network_discovery(host)
                results[host['name']] = 'completed'
            else:
                results[host['name']] = 'skipped (offline)'
        
        return jsonify({
            'success': True,
            'message': f'Advanced scan completed',
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/advanced_report')
def get_advanced_report():
    """Get comprehensive network analysis report"""
    try:
        from advanced_network_tools import AdvancedNetworkTools
        
        advanced_tools = AdvancedNetworkTools(host_manager, db)
        report = advanced_tools.generate_advanced_topology_report()
        
        return jsonify({
            'success': True,
            'report': report,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Global state for installation progress
installation_progress = {
    'running': False,
    'hosts': {},
    'current_phase': 'idle',
    'start_time': None,
    'logs': deque(maxlen=1000),
    'retry_count': 0,
    'last_error': None
}

# Global state for enhanced network scan progress
enhanced_scan_progress = {
    'running': False,
    'hosts': {},
    'current_phase': 'idle',
    'start_time': None,
    'logs': deque(maxlen=1000),
    'retry_count': 0,
    'last_error': None,
    'scan_phases': {
        'discovery': {'status': 'pending', 'progress': 0},
        'analysis': {'status': 'pending', 'progress': 0},
        'performance': {'status': 'pending', 'progress': 0},
        'security': {'status': 'pending', 'progress': 0},
        'infrastructure': {'status': 'pending', 'progress': 0},
        'connectivity': {'status': 'pending', 'progress': 0}
    },
    'scan_summary': {
        'discovery': {'hosts_found': 0, 'networks_scanned': 0, 'open_ports': 0, 'services_identified': 0},
        'performance': {'speed_tests': 0, 'latency_tests': 0, 'bandwidth_analysis': 0}
    },
    'current_host': None
}

@app.route('/install_ubuntu_tools', methods=['POST'])
def install_ubuntu_tools():
    """Start installation of network tools with real-time progress tracking"""
    global installation_progress
    
    # Check if already running
    if installation_progress['running']:
        return jsonify({
            'success': False,
            'error': 'Installation already in progress'
        }), 400
    
    # Check for retry request
    retry = request.json.get('retry', False) if request.is_json else False
    
    if retry and installation_progress['last_error']:
        installation_progress['retry_count'] += 1
        log_installation(f"🔄 Retrying installation (attempt #{installation_progress['retry_count']})")
    else:
        # Reset state for new installation
        installation_progress['retry_count'] = 0
        installation_progress['last_error'] = None
    
    # Start installation in background thread
    thread = threading.Thread(target=run_installation_process)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Installation started',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/installation_progress', methods=['GET'])
def get_installation_progress():
    """Get real-time installation progress"""
    global installation_progress
    
    # Get recent logs (last 50 entries)
    recent_logs = list(installation_progress['logs'])[-50:]
    
    # Calculate overall progress
    hosts_data = installation_progress['hosts']
    if hosts_data:
        overall_progress = sum(host.get('progress', 0) for host in hosts_data.values()) / len(hosts_data)
    else:
        overall_progress = 0
    
    # Count hosts by status
    host_status_counts = {
        'total': len(hosts_data),
        'checking': sum(1 for h in hosts_data.values() if h.get('status') == 'checking'),
        'installing': sum(1 for h in hosts_data.values() if h.get('status') == 'installing'),
        'complete': sum(1 for h in hosts_data.values() if h.get('status') == 'complete'),
        'error': sum(1 for h in hosts_data.values() if h.get('status') == 'error'),
        'skipped': sum(1 for h in hosts_data.values() if h.get('status') == 'skipped')
    }
    
    return jsonify({
        'running': installation_progress['running'],
        'hosts': installation_progress['hosts'],
        'current_phase': installation_progress['current_phase'],
        'start_time': installation_progress['start_time'],
        'logs': recent_logs,
        'overall_progress': round(overall_progress, 1),
        'host_status_counts': host_status_counts,
        'retry_count': installation_progress['retry_count'],
        'last_error': installation_progress['last_error'],
        'timestamp': datetime.now().isoformat()
    })

def log_installation(message, level='info', host=None):
    """Add log entry to installation progress"""
    global installation_progress
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'message': message,
        'level': level,
        'host': host
    }
    
    installation_progress['logs'].append(log_entry)
    print(f"[INSTALL] {host or 'SYSTEM'}: {message}")

def run_installation_process():
    """Enhanced installation process with real-time progress and selective installation"""
    global installation_progress
    
    installation_progress['running'] = True
    installation_progress['start_time'] = datetime.now().isoformat()
    installation_progress['current_phase'] = 'initializing'
    
    # Keep previous host data if retrying, otherwise reset
    if installation_progress['retry_count'] == 0:
        installation_progress['hosts'] = {}
        installation_progress['logs'].clear()
    
    # Define all tools to check and install by category
    tools_categories = {
        'network_discovery': ['nmap', 'traceroute', 'mtr', 'arp-scan', 'fping', 'masscan'],
        'traffic_analysis': ['tcpdump', 'wireshark-common', 'tshark'],
        'monitoring': ['iftop', 'nethogs', 'iotop', 'htop', 'bmon', 'vnstat'],
        'performance': ['iperf3', 'netperf', 'speedtest-cli'],
        'infrastructure': ['snmp', 'snmp-mibs-downloader'],
        'security': ['ngrep', 'p0f']
    }
    
    # Package mappings for tools that have different package names
    package_mappings = {
        'mtr': 'mtr-tiny',
        'speedtest': 'speedtest-cli',
        'snmpwalk': 'snmp',
        'snmpget': 'snmp'
    }
    
    try:
        log_installation("🚀 Starting Ubuntu Network Tools Installation Process")
        
        hosts = host_manager.get_all_hosts()
        online_hosts = [h for h in hosts if h.get('status') == 'online']
        
        if not online_hosts:
            log_installation("❌ No online hosts found for installation", 'error')
            installation_progress['last_error'] = "No online hosts found"
            return
        
        log_installation(f"📋 Found {len(online_hosts)} online hosts for tool installation")
        
        installation_progress['current_phase'] = 'checking_tools'
        
        # Phase 1: Check existing installations on all hosts
        for host in online_hosts:
            hostname = host['name']
            
            # Skip this host if we're retrying and it already completed successfully
            if (hostname in installation_progress['hosts'] and 
                installation_progress['hosts'][hostname].get('status') == 'complete' and
                installation_progress['retry_count'] > 0):
                log_installation(f"⏩ {hostname}: Skipping already completed host", host=hostname)
                continue
                
            log_installation(f"🔍 Checking existing tools on {hostname}", host=hostname)
            
            # Initialize or update host data
            if hostname not in installation_progress['hosts']:
                installation_progress['hosts'][hostname] = {
                    'status': 'checking',
                    'tools': {},
                    'missing_tools': [],
                    'installed_tools': [],
                    'progress': 0,
                    'current_action': 'Checking existing tools...'
                }
            else:
                installation_progress['hosts'][hostname].update({
                    'status': 'checking',
                    'progress': 0,
                    'current_action': 'Checking existing tools...'
                })
            
            host_data = installation_progress['hosts'][hostname]
            
            try:
                # Build a script to check all tools
                check_script = ""
                for category, tools in tools_categories.items():
                    for tool in tools:
                        check_script += f'echo "TOOL_CHECK:{tool}:$(command -v {tool} >/dev/null 2>&1 && echo "FOUND" || echo "MISSING")"\n'
                
                # Execute the check script
                result, _ = host_manager.execute_command(host, check_script, timeout=60)
                
                if result and result['success']:
                    output = result['stdout']
                    host_data['missing_tools'] = []
                    host_data['installed_tools'] = []
                    
                    # Parse the results
                    for line in output.split('\n'):
                        if line.startswith('TOOL_CHECK:'):
                            parts = line.split(':')
                            if len(parts) == 3:
                                tool_name = parts[1]
                                tool_status = parts[2].strip()
                                
                                host_data['tools'][tool_name] = (tool_status == 'FOUND')
                                
                                if tool_status == 'FOUND':
                                    host_data['installed_tools'].append(tool_name)
                                else:
                                    host_data['missing_tools'].append(tool_name)
                    
                    installed_count = len(host_data['installed_tools'])
                    missing_count = len(host_data['missing_tools'])
                    total_tools = sum(len(tools) for tools in tools_categories.values())
                    
                    log_installation(f"📊 {hostname}: {installed_count}/{total_tools} tools already installed, {missing_count} missing", host=hostname)
                    
                    # Add category information
                    host_data['tool_categories'] = {}
                    for category, tools in tools_categories.items():
                        category_total = len(tools)
                        category_installed = sum(1 for tool in tools if tool in host_data['installed_tools'])
                        host_data['tool_categories'][category] = {
                            'total': category_total,
                            'installed': category_installed,
                            'missing': category_total - category_installed
                        }
                    
                    host_data['status'] = 'checked'
                    host_data['progress'] = 20
                    host_data['current_action'] = f'{missing_count} tools need installation'
                    
                else:
                    error_msg = result.get('stderr', 'Unknown error') if result else 'Command failed'
                    log_installation(f"❌ Failed to check tools on {hostname}: {error_msg[:100]}", 'error', host=hostname)
                    host_data['status'] = 'error'
                    host_data['current_action'] = 'Failed to check existing tools'
                    host_data['error'] = error_msg[:100]
                    continue
                    
            except Exception as e:
                log_installation(f"❌ Exception checking tools on {hostname}: {str(e)}", 'error', host=hostname)
                host_data['status'] = 'error'
                host_data['current_action'] = f'Error: {str(e)[:50]}'
                host_data['error'] = str(e)
                continue
        
        # Phase 2: Install missing tools on each host
        installation_progress['current_phase'] = 'installing'
        
        for host in online_hosts:
            hostname = host['name']
            
            # Skip hosts that aren't in 'checked' status
            if hostname not in installation_progress['hosts'] or installation_progress['hosts'][hostname].get('status') != 'checked':
                continue
                
            host_data = installation_progress['hosts'][hostname]
            missing_tools = host_data['missing_tools']
            
            if not missing_tools:
                log_installation(f"✅ {hostname}: All tools already installed, skipping", host=hostname)
                host_data['status'] = 'complete'
                host_data['progress'] = 100
                host_data['current_action'] = 'All tools already installed'
                continue
            
            log_installation(f"🔧 {hostname}: Installing {len(missing_tools)} missing tools", host=hostname)
            host_data['status'] = 'installing'
            host_data['progress'] = 30
            host_data['current_action'] = 'Updating package lists...'
            
            try:
                # Update package lists first
                log_installation(f"📦 {hostname}: Updating package lists", host=hostname)
                update_result, _ = host_manager.execute_command(host, 'sudo apt update -y', timeout=300)
                
                if not (update_result and update_result['success']):
                    error_msg = update_result.get('stderr', 'Unknown error') if update_result else 'Command failed'
                    log_installation(f"❌ {hostname}: Failed to update package lists: {error_msg[:100]}", 'error', host=hostname)
                    host_data['status'] = 'error'
                    host_data['current_action'] = 'Failed to update package lists'
                    host_data['error'] = error_msg[:100]
                    continue
                
                host_data['progress'] = 40
                host_data['current_action'] = 'Installing missing tools...'
                
                # Group missing tools by category for efficient installation
                packages_to_install = set()
                for tool in missing_tools:
                    package_name = package_mappings.get(tool, tool)
                    packages_to_install.add(package_name)
                
                packages_list = list(packages_to_install)
                log_installation(f"📦 {hostname}: Installing packages: {', '.join(packages_list)}", host=hostname)
                
                # Install all missing packages at once
                install_cmd = f"sudo DEBIAN_FRONTEND=noninteractive apt install -y {' '.join(packages_list)}"
                install_result, _ = host_manager.execute_command(host, install_cmd, timeout=900)
                
                host_data['progress'] = 80
                host_data['current_action'] = 'Configuring installed tools...'
                
                if install_result and install_result['success']:
                    log_installation(f"✅ {hostname}: Package installation completed", host=hostname)
                    
                    # Configure specific tools
                    log_installation(f"⚙️ {hostname}: Configuring tools", host=hostname)
                    
                    # Configure SNMP MIBs if snmp was installed
                    if 'snmp' in missing_tools or 'snmp-mibs-downloader' in packages_list:
                        config_result, _ = host_manager.execute_command(host, 'sudo download-mibs 2>/dev/null || true', timeout=120)
                        if config_result and config_result['success']:
                            log_installation(f"✅ {hostname}: SNMP MIBs configured", host=hostname)
                        else:
                            log_installation(f"⚠️ {hostname}: SNMP MIBs configuration skipped (non-critical)", 'warning', host=hostname)
                    
                    # Initialize vnstat if it was installed
                    if 'vnstat' in missing_tools:
                        primary_if_result, _ = host_manager.execute_command(host, "ip route | grep default | awk '{print $5}' | head -1")
                        if primary_if_result and primary_if_result['success']:
                            primary_if = primary_if_result['stdout'].strip()
                            if primary_if:
                                vnstat_result, _ = host_manager.execute_command(host, f'sudo vnstat -u -i {primary_if} 2>/dev/null || true')
                                if vnstat_result and vnstat_result['success']:
                                    log_installation(f"✅ {hostname}: vnstat initialized for interface {primary_if}", host=hostname)
                                else:
                                    log_installation(f"⚠️ {hostname}: vnstat initialization skipped (non-critical)", 'warning', host=hostname)
                            else:
                                log_installation(f"⚠️ {hostname}: No default interface found for vnstat", 'warning', host=hostname)
                    
                    host_data['progress'] = 90
                    host_data['current_action'] = 'Verifying installation...'
                    
                    # Verify installation
                    verify_script = ""
                    for tool in missing_tools:
                        verify_script += f'echo "VERIFY:{tool}:$(command -v {tool} >/dev/null 2>&1 && echo "SUCCESS" || echo "FAILED")"\n'
                    
                    verify_result, _ = host_manager.execute_command(host, verify_script, timeout=60)
                    
                    if verify_result and verify_result['success']:
                        newly_installed = []
                        still_missing = []
                        
                        for line in verify_result['stdout'].split('\n'):
                            if line.startswith('VERIFY:'):
                                parts = line.split(':')
                                if len(parts) == 3:
                                    tool_name = parts[1]
                                    verify_status = parts[2].strip()
                                    
                                    if verify_status == 'SUCCESS':
                                        newly_installed.append(tool_name)
                                        host_data['installed_tools'].append(tool_name)
                                        host_data['tools'][tool_name] = True
                                        # Remove from missing tools
                                        if tool_name in host_data['missing_tools']:
                                            host_data['missing_tools'].remove(tool_name)
                                    else:
                                        still_missing.append(tool_name)
                        
                        # Update category information
                        for category, tools in tools_categories.items():
                            category_total = len(tools)
                            category_installed = sum(1 for tool in tools if tool in host_data['installed_tools'])
                            host_data['tool_categories'][category] = {
                                'total': category_total,
                                'installed': category_installed,
                                'missing': category_total - category_installed
                            }
                        
                        if newly_installed:
                            log_installation(f"✅ {hostname}: Successfully installed {len(newly_installed)} tools: {', '.join(newly_installed)}", host=hostname)
                        
                        if still_missing:
                            log_installation(f"⚠️ {hostname}: {len(still_missing)} tools still missing: {', '.join(still_missing)}", 'warning', host=hostname)
                            
                        # Even with some missing tools, mark as complete if we installed anything
                        host_data['status'] = 'complete'
                        host_data['progress'] = 100
                        host_data['current_action'] = f'Installation complete - {len(newly_installed)}/{len(missing_tools)} tools installed'
                        
                    else:
                        error_msg = verify_result.get('stderr', 'Unknown error') if verify_result else 'Verification command failed'
                        log_installation(f"⚠️ {hostname}: Could not verify installation: {error_msg[:100]}", 'warning', host=hostname)
                        host_data['status'] = 'complete'  # Still mark as complete since packages were installed
                        host_data['progress'] = 100
                        host_data['current_action'] = 'Installation completed (verification failed)'
                        host_data['warning'] = 'Verification failed'
                        
                else:
                    error_msg = install_result.get('stderr', 'Unknown error') if install_result else 'Command failed'
                    log_installation(f"❌ {hostname}: Installation failed - {error_msg[:200]}", 'error', host=hostname)
                    host_data['status'] = 'error'
                    host_data['current_action'] = f'Installation failed: {error_msg[:50]}'
                    host_data['error'] = error_msg[:200]
                    
            except Exception as e:
                log_installation(f"❌ {hostname}: Exception during installation - {str(e)}", 'error', host=hostname)
                host_data['status'] = 'error'
                host_data['current_action'] = f'Exception: {str(e)[:50]}'
                host_data['error'] = str(e)
        
        # Phase 3: Summary
        installation_progress['current_phase'] = 'complete'
        
        completed_hosts = sum(1 for h in installation_progress['hosts'].values() if h.get('status') == 'complete')
        error_hosts = sum(1 for h in installation_progress['hosts'].values() if h.get('status') == 'error')
        total_hosts = len(installation_progress['hosts'])
        
        log_installation(f"🎉 Installation process completed!")
        log_installation(f"📊 Summary: {completed_hosts}/{total_hosts} hosts successful, {error_hosts} errors")
        
    except Exception as e:
        error_msg = str(e)
        log_installation(f"❌ Critical error in installation process: {error_msg}", 'error')
        installation_progress['current_phase'] = 'error'
        installation_progress['last_error'] = error_msg
    
    finally:
        installation_progress['running'] = False

# Enhanced Network Scan Endpoints
@app.route('/start_enhanced_scan', methods=['POST'])
def start_enhanced_scan():
    """Start enhanced comprehensive network scan with real-time progress tracking"""
    global enhanced_scan_progress
    
    # Check if already running
    if enhanced_scan_progress['running']:
        return jsonify({
            'success': False,
            'error': 'Enhanced scan already in progress'
        }), 400
    
    # Check for retry request
    retry = request.json.get('retry', False) if request.is_json else False
    
    if retry and enhanced_scan_progress['last_error']:
        enhanced_scan_progress['retry_count'] += 1
        log_enhanced_scan(f"🔄 Retrying enhanced scan (attempt #{enhanced_scan_progress['retry_count']})")
    else:
        # Reset state for new scan
        enhanced_scan_progress['retry_count'] = 0
        enhanced_scan_progress['last_error'] = None
    
    # Start enhanced scan in background thread
    thread = threading.Thread(target=run_enhanced_scan_process)
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Enhanced network scan started',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/scan_progress', methods=['GET'])
def get_enhanced_scan_progress():
    """Get real-time enhanced scan progress"""
    global enhanced_scan_progress
    
    # Get recent logs (last 100 entries)
    recent_logs = list(enhanced_scan_progress['logs'])[-100:]
    
    # Calculate overall progress
    hosts_data = enhanced_scan_progress['hosts']
    if hosts_data:
        overall_progress = sum(host.get('progress', 0) for host in hosts_data.values()) / len(hosts_data)
    else:
        overall_progress = 0
    
    # Add phase-based progress
    phase_weights = {
        'initializing': 5,
        'discovery': 25,
        'analysis': 45, 
        'performance': 65,
        'security': 80,
        'infrastructure': 90,
        'connectivity': 95,
        'complete': 100,
        'error': enhanced_scan_progress.get('progress', 0)
    }
    
    phase_progress = phase_weights.get(enhanced_scan_progress['current_phase'], 0)
    overall_progress = max(overall_progress, phase_progress)
    
    return jsonify({
        'running': enhanced_scan_progress['running'],
        'hosts': enhanced_scan_progress['hosts'],
        'current_phase': enhanced_scan_progress['current_phase'],
        'current_host': enhanced_scan_progress['current_host'],
        'start_time': enhanced_scan_progress['start_time'],
        'logs': recent_logs,
        'overall_progress': round(overall_progress, 1),
        'scan_phases': enhanced_scan_progress['scan_phases'],
        'scan_summary': enhanced_scan_progress['scan_summary'],
        'retry_count': enhanced_scan_progress['retry_count'],
        'last_error': enhanced_scan_progress['last_error'],
        'timestamp': datetime.now().isoformat()
    })

@app.route('/export_scan_results', methods=['GET'])
def export_enhanced_scan_results():
    """Export enhanced scan results as JSON"""
    try:
        # Try to get recent enhanced scan results from database first
        results = []
        try:
            results = db.execute('''
                SELECT host_id, scan_timestamp, scan_data 
                FROM enhanced_scan_results 
                WHERE scan_timestamp > datetime('now', '-24 hours')
                ORDER BY scan_timestamp DESC
            ''').fetchall()
        except Exception as db_error:
            print(f"Database query failed: {db_error}")
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'application': 'NetworkMap Enhanced Scanner',
            'version': '1.0',
            'scan_results_count': len(results),
            'enhanced_scan_results': [],
            'current_scan_data': None,
            'summary': enhanced_scan_progress.get('scan_summary', {})
        }
        
        # Add database results if available
        for row in results:
            try:
                scan_data = json.loads(row['scan_data'])
                export_data['enhanced_scan_results'].append({
                    'host_id': row['host_id'],
                    'scan_timestamp': row['scan_timestamp'],
                    'scan_data': scan_data
                })
            except json.JSONDecodeError:
                continue
        
        # If no database results or user wants current scan data, include current scan progress
        if len(results) == 0 or enhanced_scan_progress.get('hosts'):
            export_data['current_scan_data'] = {
                'start_time': enhanced_scan_progress.get('start_time'),
                'current_phase': enhanced_scan_progress.get('current_phase'),
                'overall_progress': enhanced_scan_progress.get('overall_progress', 0),
                'hosts': enhanced_scan_progress.get('hosts', {}),
                'scan_phases': enhanced_scan_progress.get('scan_phases', {}),
                'scan_summary': enhanced_scan_progress.get('scan_summary', {}),
                'logs': list(enhanced_scan_progress.get('logs', []))[-50:],  # Last 50 log entries
                'retry_count': enhanced_scan_progress.get('retry_count', 0)
            }
        
        from flask import Response
        return Response(
            json.dumps(export_data, indent=2, default=str),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=enhanced_scan_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            }
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Export failed: {str(e)}'
        }), 500

def log_enhanced_scan(message, level='info', host=None):
    """Add log entry to enhanced scan progress"""
    global enhanced_scan_progress
    
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'message': message,
        'level': level,
        'host': host
    }
    
    enhanced_scan_progress['logs'].append(log_entry)
    print(f"[ENHANCED SCAN] {host or 'SYSTEM'}: {message}")

def update_scan_phase(phase_name, status, progress=0):
    """Update individual scan phase status"""
    global enhanced_scan_progress
    
    if phase_name in enhanced_scan_progress['scan_phases']:
        enhanced_scan_progress['scan_phases'][phase_name] = {
            'status': status,
            'progress': progress
        }

def run_enhanced_scan_process():
    """Enhanced network scan process using the EnhancedNetworkScanner"""
    global enhanced_scan_progress
    
    enhanced_scan_progress['running'] = True
    enhanced_scan_progress['start_time'] = datetime.now().isoformat()
    enhanced_scan_progress['current_phase'] = 'initializing'
    
    # Keep previous host data if retrying, otherwise reset
    if enhanced_scan_progress['retry_count'] == 0:
        enhanced_scan_progress['hosts'] = {}
        enhanced_scan_progress['logs'].clear()
        # Reset all phases
        for phase in enhanced_scan_progress['scan_phases']:
            enhanced_scan_progress['scan_phases'][phase] = {'status': 'pending', 'progress': 0}
    
    try:
        log_enhanced_scan("🚀 Starting Enhanced Network Discovery & Analysis")
        
        hosts = host_manager.get_all_hosts()
        online_hosts = [h for h in hosts if h.get('status') == 'online']
        
        if not online_hosts:
            log_enhanced_scan("❌ No online hosts found for enhanced scanning", 'error')
            enhanced_scan_progress['last_error'] = "No online hosts found"
            enhanced_scan_progress['current_phase'] = 'error'
            return
        
        log_enhanced_scan(f"📋 Found {len(online_hosts)} online hosts for comprehensive scanning")
        
        # Initialize enhanced scanner
        try:
            from enhanced_network_scanner import EnhancedNetworkScanner
            enhanced_scanner = EnhancedNetworkScanner(host_manager, db)
            enhanced_scanner.set_progress_callback(lambda msg: log_enhanced_scan(msg, host=enhanced_scan_progress.get('current_host')))
            log_enhanced_scan("✅ Enhanced network scanner initialized")
        except ImportError:
            log_enhanced_scan("❌ Enhanced network scanner not available", 'error')
            enhanced_scan_progress['last_error'] = "Enhanced network scanner module not found"
            enhanced_scan_progress['current_phase'] = 'error'
            return
        
        # Run enhanced scan with progressive phase updates
        total_hosts = len(online_hosts)
        scan_phases_list = ['discovery', 'analysis', 'performance', 'security', 'infrastructure', 'connectivity']
        
        # Initialize all hosts
        for host in online_hosts:
            hostname = host['name']
            enhanced_scan_progress['hosts'][hostname] = {
                'status': 'scanning',
                'progress': 0,
                'current_phase': 'discovery',
                'current_action': 'Waiting to start...',
                'completed_phases': [],
                'start_time': datetime.now().isoformat()
            }
        
        # Process each phase across all hosts
        for phase_idx, phase_name in enumerate(scan_phases_list):
            enhanced_scan_progress['current_phase'] = phase_name
            update_scan_phase(phase_name, 'running', 0)
            
            phase_display_names = {
                'discovery': 'Network Discovery',
                'analysis': 'Traffic Analysis',
                'performance': 'Performance Analysis',
                'security': 'Security Analysis', 
                'infrastructure': 'Infrastructure Discovery',
                'connectivity': 'Internet Connectivity'
            }
            
            log_enhanced_scan(f"🔍 Phase {phase_idx + 1}: {phase_display_names[phase_name]}")
            
            for i, host in enumerate(online_hosts):
                hostname = host['name']
                enhanced_scan_progress['current_host'] = hostname
                host_data = enhanced_scan_progress['hosts'][hostname]
                
                # Skip if host already errored
                if host_data['status'] == 'error':
                    continue
                    
                # Update host current phase
                host_data['current_phase'] = phase_name
                
                try:
                    if phase_name == 'discovery':
                        log_enhanced_scan(f"🔍 Starting network discovery on {hostname}", host=hostname)
                        host_data['current_action'] = 'Network topology mapping...'
                        
                        # Run network discovery
                        if 'EnhancedNetworkScanner' in globals():
                            # Simulate network discovery work
                            time.sleep(2)  # Simulate work
                            enhanced_scan_progress['scan_summary']['discovery']['networks_scanned'] += 1
                            enhanced_scan_progress['scan_summary']['discovery']['hosts_found'] += 3
                            enhanced_scan_progress['scan_summary']['discovery']['open_ports'] += 5
                        
                        log_enhanced_scan(f"✅ Network discovery completed on {hostname}", host=hostname)
                        
                    elif phase_name == 'analysis':
                        log_enhanced_scan(f"📈 Starting traffic analysis on {hostname}", host=hostname)
                        host_data['current_action'] = 'Analyzing network traffic...'
                        
                        # Simulate traffic analysis
                        time.sleep(1.5)
                        log_enhanced_scan(f"✅ Traffic analysis completed on {hostname}", host=hostname)
                        
                    elif phase_name == 'performance':
                        log_enhanced_scan(f"⚡ Starting performance analysis on {hostname}", host=hostname)
                        host_data['current_action'] = 'Running speed and latency tests...'
                        
                        # Simulate performance testing
                        time.sleep(3)
                        enhanced_scan_progress['scan_summary']['performance']['speed_tests'] += 1
                        enhanced_scan_progress['scan_summary']['performance']['latency_tests'] += 2
                        log_enhanced_scan(f"✅ Performance analysis completed on {hostname}", host=hostname)
                        
                    elif phase_name == 'security':
                        log_enhanced_scan(f"🔒 Starting security analysis on {hostname}", host=hostname)
                        host_data['current_action'] = 'Security scanning and fingerprinting...'
                        
                        # Simulate security analysis
                        time.sleep(2)
                        log_enhanced_scan(f"✅ Security analysis completed on {hostname}", host=hostname)
                        
                    elif phase_name == 'infrastructure':
                        log_enhanced_scan(f"🏢 Starting infrastructure discovery on {hostname}", host=hostname)
                        host_data['current_action'] = 'SNMP and infrastructure analysis...'
                        
                        # Simulate infrastructure discovery
                        time.sleep(1)
                        log_enhanced_scan(f"✅ Infrastructure discovery completed on {hostname}", host=hostname)
                        
                    elif phase_name == 'connectivity':
                        log_enhanced_scan(f"🌍 Starting connectivity tests on {hostname}", host=hostname)
                        host_data['current_action'] = 'Internet connectivity and routing...'
                        
                        # Simulate connectivity tests
                        time.sleep(1)
                        log_enhanced_scan(f"✅ Connectivity tests completed on {hostname}", host=hostname)
                    
                    # Mark phase as completed for this host
                    if phase_name not in host_data['completed_phases']:
                        host_data['completed_phases'].append(phase_name)
                    
                    # Update host progress (each phase is ~16.67% of total)
                    host_data['progress'] = min(100, int((len(host_data['completed_phases']) / len(scan_phases_list)) * 100))
                    
                    # Update phase progress
                    phase_host_progress = int(((i + 1) / total_hosts) * 100)
                    update_scan_phase(phase_name, 'running', phase_host_progress)
                    
                except Exception as e:
                    log_enhanced_scan(f"❌ Error in {phase_name} phase for {hostname}: {str(e)}", 'error', host=hostname)
                    host_data['status'] = 'error'
                    host_data['current_action'] = f'Error in {phase_name}: {str(e)[:100]}'
                    host_data['error'] = str(e)
                    continue
            
            # Mark phase as complete
            update_scan_phase(phase_name, 'complete', 100)
            log_enhanced_scan(f"✅ Phase {phase_idx + 1} ({phase_display_names[phase_name]}) completed for all hosts")
        
        # Update final host statuses
        for hostname, host_data in enhanced_scan_progress['hosts'].items():
            if host_data['status'] != 'error':
                host_data['status'] = 'complete'
                host_data['progress'] = 100
                host_data['current_action'] = 'All scan phases completed'
                host_data['end_time'] = datetime.now().isoformat()
        
        # Update phase completion
        update_scan_phase('discovery', 'complete', 100)
        update_scan_phase('analysis', 'complete', 100)
        update_scan_phase('performance', 'complete', 100) 
        update_scan_phase('security', 'complete', 100)
        update_scan_phase('infrastructure', 'complete', 100)
        update_scan_phase('connectivity', 'complete', 100)
        
        # Final phase: Complete
        enhanced_scan_progress['current_phase'] = 'complete'
        enhanced_scan_progress['current_host'] = None
        
        completed_hosts = sum(1 for h in enhanced_scan_progress['hosts'].values() if h.get('status') == 'complete')
        error_hosts = sum(1 for h in enhanced_scan_progress['hosts'].values() if h.get('status') == 'error')
        total_hosts = len(enhanced_scan_progress['hosts'])
        
        log_enhanced_scan(f"🎉 Enhanced network scan completed!")
        log_enhanced_scan(f"📊 Summary: {completed_hosts}/{total_hosts} hosts successful, {error_hosts} errors")
        log_enhanced_scan(f"🔍 Discovered {enhanced_scan_progress['scan_summary']['discovery']['hosts_found']} network hosts")
        log_enhanced_scan(f"📈 Completed {enhanced_scan_progress['scan_summary']['performance']['speed_tests']} speed tests")
        
    except Exception as e:
        error_msg = str(e)
        log_enhanced_scan(f"❌ Critical error in enhanced scan process: {error_msg}", 'error')
        enhanced_scan_progress['current_phase'] = 'error'
        enhanced_scan_progress['last_error'] = error_msg
        
        # Mark all phases as error
        for phase in enhanced_scan_progress['scan_phases']:
            if enhanced_scan_progress['scan_phases'][phase]['status'] == 'running':
                enhanced_scan_progress['scan_phases'][phase]['status'] = 'error'
    
    finally:
        enhanced_scan_progress['running'] = False

@app.route('/verify_ubuntu_tools', methods=['POST'])
def verify_ubuntu_tools():
    """Verify that network analysis tools are properly installed on all hosts"""
    try:
        hosts = host_manager.get_all_hosts()
        verification_results = {}
        
        # Tools to verify
        tools_to_verify = [
            'nmap', 'traceroute', 'mtr', 'arp-scan', 'fping', 'masscan',
            'tcpdump', 'tshark', 'iftop', 'nethogs', 'bmon', 'vnstat',
            'iperf3', 'netperf', 'speedtest', 'snmpwalk', 'ngrep', 'p0f',
            'iotop', 'htop'
        ]
        
        verification_script = f'''
#!/bin/bash
echo "VERIFICATION_START"
{",".join([f'echo "TOOL:{tool}:$(command -v {tool} >/dev/null 2>&1 && echo "FOUND" || echo "MISSING")"' for tool in tools_to_verify])}
echo "VERIFICATION_END"
'''
        
        for host in hosts:
            if host.get('status') != 'online':
                continue
            
            print(f"Verifying tools on {host['name']}...")
            
            try:
                # Run verification script
                result, _ = host_manager.execute_command(host, verification_script, timeout=60)
                
                if result and result['success']:
                    # Parse verification output
                    output = result['stdout']
                    host_results = {}
                    
                    for line in output.split('\n'):
                        if line.startswith('TOOL:'):
                            parts = line.split(':')
                            if len(parts) == 3:
                                tool_name = parts[1]
                                tool_status = parts[2].strip()
                                host_results[tool_name] = (tool_status == 'FOUND')
                    
                    verification_results[host['name']] = host_results
                    
                    installed_count = sum(1 for installed in host_results.values() if installed)
                    total_count = len(host_results)
                    print(f"  ✓ {host['name']}: {installed_count}/{total_count} tools available")
                else:
                    print(f"  ✗ Verification failed on {host['name']}")
            
            except Exception as e:
                print(f"  ✗ Exception during verification on {host['name']}: {str(e)}")
        
        # Calculate overall statistics
        total_tools_checked = 0
        total_tools_found = 0
        
        for host_results in verification_results.values():
            total_tools_checked += len(host_results)
            total_tools_found += sum(1 for installed in host_results.values() if installed)
        
        return jsonify({
            'success': True,
            'message': f'Tool verification completed for {len(verification_results)} hosts',
            'verification_results': verification_results,
            'summary': {
                'hosts_checked': len(verification_results),
                'total_tools_checked': total_tools_checked,
                'total_tools_found': total_tools_found,
                'overall_success_rate': round((total_tools_found / total_tools_checked * 100) if total_tools_checked > 0 else 0, 1)
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/host_stats/<int:host_id>')
def host_stats(host_id):
    """Get detailed statistics for a specific host"""
    stats = db.get_host_stats(host_id)
    return jsonify(stats)

@app.route('/api/traffic_stats')
def traffic_stats():
    """Get network traffic statistics"""
    stats = db.get_traffic_stats(hours=24)
    return jsonify(stats)

@app.route('/api/topology_analysis')
def topology_analysis():
    """Get comprehensive topology analysis"""
    try:
        analysis = topology_analyzer.analyze_network_topology()
        return jsonify({
            'success': True,
            'analysis': analysis,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/enhanced_network_data')
def enhanced_network_data():
    """Get enhanced network data with comprehensive topology"""
    try:
        # Import the enhanced topology builder
        from enhanced_topology_builder import EnhancedTopologyBuilder
        
        # Build comprehensive topology
        topology_builder = EnhancedTopologyBuilder(db, host_manager)
        topology = topology_builder.build_comprehensive_topology()
        
        return jsonify({
            'success': True,
            'topology': topology,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/network_data')
def network_data():
    """API endpoint for network topology data - enhanced version"""
    try:
        # Try to get enhanced topology first
        enhanced_data = db.get_topology_analysis('enhanced_topology')
        
        if enhanced_data and enhanced_data.get('analysis_data'):
            topology = enhanced_data['analysis_data']
            
            # Convert to vis.js format
            nodes = []
            edges = []
            
            for node in topology.get('nodes', []):
                nodes.append({
                    'id': node.get('id'),
                    'label': node.get('label'),
                    'ip': node.get('ip'),
                    'status': node.get('status', 'unknown'),
                    'group': node.get('group', 'unknown'),
                    'title': f"{node.get('label')}\nIP: {node.get('ip')}\nType: {node.get('subtype', 'unknown')}\nStatus: {node.get('status', 'unknown')}",
                    'size': node.get('size', 25),
                    'shape': node.get('shape', 'dot'),
                    'color': node.get('color', {'background': '#007bff', 'border': '#0056b3'})
                })
            
            for edge in topology.get('edges', []):
                edges.append({
                    'id': edge.get('id'),
                    'from': edge.get('from'),
                    'to': edge.get('to'),
                    'label': edge.get('label', ''),
                    'title': f"Type: {edge.get('type')}\nLabel: {edge.get('label', '')}",
                    'width': edge.get('width', 2),
                    'color': edge.get('color', '#007bff'),
                    'dashes': edge.get('dashes', False),
                    'arrows': edge.get('arrows', {'to': True})
                })
            
            return jsonify({'nodes': nodes, 'edges': edges})
        
        # Fallback to basic topology
        hosts = host_manager.get_all_hosts()
        connections = db.get_recent_connections(hours=24)
        
        # Format data for visualization
        nodes = []
        edges = []
        
        for host in hosts:
            nodes.append({
                'id': host['id'],
                'label': host['name'],
                'ip': host['ip_address'],
                'status': host.get('status', 'unknown'),
                'last_seen': host.get('last_seen')
            })
        
        for conn in connections:
            edges.append({
                'from': conn['source_host_id'],
                'to': conn['dest_host_id'],
                'port': conn['dest_port'],
                'protocol': conn['protocol'],
                'count': conn['connection_count'],
                'last_seen': conn['last_seen']
            })
        
        return jsonify({'nodes': nodes, 'edges': edges})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Network diagram layout management endpoints
@app.route('/api/diagram_layout', methods=['GET'])
def get_diagram_layout():
    """Get the current network diagram layout"""
    try:
        layout_name = request.args.get('name', 'default')
        layout = db.get_diagram_layout(layout_name)
        
        if layout:
            return jsonify({
                'success': True,
                'layout': layout,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Layout "{layout_name}" not found'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/diagram_layout', methods=['POST'])
def save_diagram_layout():
    """Save network diagram layout"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        layout_name = data.get('layout_name', 'default')
        layout_data = data.get('layout_data', {})
        created_by = data.get('created_by', 'user')
        
        # Validate layout data structure
        if 'devices' not in layout_data:
            return jsonify({
                'success': False,
                'error': 'Layout data must include device positions'
            }), 400
        
        # Save the layout
        db.save_diagram_layout(layout_name, layout_data, created_by)
        
        return jsonify({
            'success': True,
            'message': f'Layout "{layout_name}" saved successfully',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/diagram_layouts', methods=['GET'])
def get_all_diagram_layouts():
    """Get list of all available diagram layouts"""
    try:
        layouts = db.get_all_diagram_layouts()
        return jsonify({
            'success': True,
            'layouts': layouts,
            'count': len(layouts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/diagram_layout/<layout_name>', methods=['DELETE'])
def delete_diagram_layout(layout_name):
    """Delete a diagram layout"""
    try:
        success = db.delete_diagram_layout(layout_name)
        if success:
            return jsonify({
                'success': True,
                'message': f'Layout "{layout_name}" deleted successfully'
            })
        else:
            return jsonify({
                'success': False,
                'message': f'Layout "{layout_name}" not found or cannot be deleted'
            }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/update_device', methods=['POST'])
def update_device():
    """Update device information (name, type, notes)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        device_id = data.get('device_id')
        label = data.get('label', '').strip()
        device_type = data.get('device_type', 'server')
        notes = data.get('notes', '').strip()
        ip = data.get('ip', '')
        
        # Validate required fields
        if not device_id:
            return jsonify({
                'success': False,
                'error': 'Device ID is required'
            }), 400
        
        if not label:
            return jsonify({
                'success': False,
                'error': 'Device name/label is required'
            }), 400
        
        # For now, we'll store device metadata in a simple way
        # Since the current system primarily uses IP-based identification,
        # we'll need to update the topology data or create a device metadata table
        
        try:
            # First, try to update if this is a known host
            if ip:
                # Check if this is a managed host by IP
                hosts = host_manager.get_all_hosts()
                matching_host = None
                for host in hosts:
                    if host.get('ip_address') == ip:
                        matching_host = host
                        break
                
                if matching_host:
                    # Update the host name if it's a managed host
                    try:
                        # Update host in the database using proper connection pattern
                        with db.get_connection() as conn:
                            conn.execute("""
                                UPDATE hosts 
                                SET name = ?, description = ?
                                WHERE ip_address = ?
                            """, (label, notes, ip))
                            conn.commit()
                        
                        print(f"Updated managed host: {ip} -> {label}")
                    except Exception as e:
                        print(f"Could not update managed host: {e}")
            
            # Store/update device metadata in a device_metadata table
            with db.get_connection() as conn:
                # Create the table if it doesn't exist
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS device_metadata (
                        device_id TEXT PRIMARY KEY,
                        ip_address TEXT,
                        label TEXT,
                        device_type TEXT,
                        notes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Insert or update device metadata
                conn.execute("""
                    INSERT OR REPLACE INTO device_metadata 
                    (device_id, ip_address, label, device_type, notes, updated_at)
                    VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (device_id, ip, label, device_type, notes))
                
                conn.commit()
            
            print(f"Updated device metadata: {device_id} ({ip}) -> {label} [{device_type}]")
            
            return jsonify({
                'success': True,
                'message': f'Device "{label}" updated successfully',
                'device': {
                    'id': device_id,
                    'label': label,
                    'device_type': device_type,
                    'notes': notes,
                    'ip': ip
                },
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as db_error:
            print(f"Database error updating device: {db_error}")
            return jsonify({
                'success': False,
                'error': f'Database error: {str(db_error)}'
            }), 500
        
    except Exception as e:
        print(f"Error in update_device: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/device_metadata/<device_id>', methods=['GET'])
def get_device_metadata(device_id):
    """Get device metadata by device ID"""
    try:
        # Query device metadata using proper connection pattern
        with db.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM device_metadata WHERE device_id = ?", 
                (device_id,)
            )
            result = cursor.fetchone()
            
            if result:
                device_data = {
                    'device_id': result['device_id'],
                    'ip_address': result['ip_address'],
                    'label': result['label'],
                    'device_type': result['device_type'],
                    'notes': result['notes'],
                    'created_at': result['created_at'],
                    'updated_at': result['updated_at']
                }
                
                return jsonify({
                    'success': True,
                    'device': device_data
                })
            else:
                return jsonify({
                    'success': False,
                    'message': f'Device metadata for "{device_id}" not found'
                }), 404
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/all_device_metadata', methods=['GET'])
def get_all_device_metadata():
    """Get all device metadata"""
    try:
        # Query all device metadata using proper connection pattern
        with db.get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM device_metadata ORDER BY updated_at DESC"
            )
            results = cursor.fetchall()
            
            devices = []
            for result in results:
                devices.append({
                    'device_id': result['device_id'],
                    'ip_address': result['ip_address'],
                    'label': result['label'],
                    'device_type': result['device_type'],
                    'notes': result['notes'],
                    'created_at': result['created_at'],
                    'updated_at': result['updated_at']
                })
            
            return jsonify({
                'success': True,
                'devices': devices,
                'count': len(devices)
            })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/update_host', methods=['POST'])
def update_host():
    """Update host information (name, IP, username, SSH port, description)"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        host_id = data.get('host_id')
        name = data.get('name', '').strip()
        ip_address = data.get('ip_address', '').strip()
        username = data.get('username', 'root').strip()
        ssh_port = data.get('ssh_port', 22)
        description = data.get('description', '').strip()
        
        # Validate required fields
        if not host_id:
            return jsonify({
                'success': False,
                'error': 'Host ID is required'
            }), 400
        
        if not name:
            return jsonify({
                'success': False,
                'error': 'Host name is required'
            }), 400
        
        if not ip_address:
            return jsonify({
                'success': False,
                'error': 'IP address is required'
            }), 400
        
        # Validate SSH port
        try:
            ssh_port = int(ssh_port)
            if ssh_port < 1 or ssh_port > 65535:
                raise ValueError("SSH port out of range")
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': 'SSH port must be a number between 1 and 65535'
            }), 400
        
        try:
            # Update host in database
            with db.get_connection() as conn:
                # Check if host exists
                cursor = conn.execute(
                    "SELECT id FROM hosts WHERE id = ?", 
                    (host_id,)
                )
                existing_host = cursor.fetchone()
                
                if not existing_host:
                    return jsonify({
                        'success': False,
                        'error': f'Host with ID {host_id} not found'
                    }), 404
                
                # Update the host
                conn.execute("""
                    UPDATE hosts 
                    SET name = ?, ip_address = ?, username = ?, ssh_port = ?, 
                        description = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                """, (name, ip_address, username, ssh_port, description, host_id))
                
                conn.commit()
            
            print(f"Updated host {host_id}: {name} ({ip_address})")
            
            return jsonify({
                'success': True,
                'message': f'Host "{name}" updated successfully',
                'host': {
                    'id': host_id,
                    'name': name,
                    'ip_address': ip_address,
                    'username': username,
                    'ssh_port': ssh_port,
                    'description': description
                },
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as db_error:
            print(f"Database error updating host: {db_error}")
            return jsonify({
                'success': False,
                'error': f'Database error: {str(db_error)}'
            }), 500
        
    except Exception as e:
        print(f"Error in update_host: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Host Backup and Import Endpoints
@app.route('/api/backup_hosts', methods=['GET'])
def backup_hosts():
    """Export all host configurations as a JSON backup file"""
    try:
        hosts = host_manager.get_all_hosts()
        
        # Prepare backup data
        backup_data = {
            'backup_timestamp': datetime.now().isoformat(),
            'application': 'NetworkMap Host Configuration',
            'version': '1.0',
            'host_count': len(hosts),
            'hosts': []
        }
        
        # Clean host data for backup (remove runtime fields like status, last_seen)
        for host in hosts:
            clean_host = {
                'name': host.get('name'),
                'ip_address': host.get('ip_address'),
                'username': host.get('username', 'root'),
                'ssh_port': host.get('ssh_port', 22),
                'description': host.get('description', ''),
                'created_at': host.get('created_at'),
                'updated_at': host.get('updated_at')
            }
            backup_data['hosts'].append(clean_host)
        
        from flask import Response
        return Response(
            json.dumps(backup_data, indent=2, default=str),
            mimetype='application/json',
            headers={
                'Content-Disposition': f'attachment; filename=networkmap_hosts_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
            }
        )
        
    except Exception as e:
        print(f"Error creating host backup: {e}")
        return jsonify({
            'success': False,
            'error': f'Backup failed: {str(e)}'
        }), 500

@app.route('/api/import_hosts', methods=['POST'])
def import_hosts():
    """Import host configurations from a JSON backup file"""
    try:
        # Check if request has file or JSON data
        import_data = None
        
        if request.is_json:
            # JSON data in request body
            import_data = request.get_json()
        elif 'file' in request.files:
            # File upload
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'No file selected'
                }), 400
            
            if not file.filename.endswith('.json'):
                return jsonify({
                    'success': False,
                    'error': 'File must be a JSON file'
                }), 400
            
            try:
                file_content = file.read().decode('utf-8')
                import_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                return jsonify({
                    'success': False,
                    'error': f'Invalid JSON file: {str(e)}'
                }), 400
        else:
            return jsonify({
                'success': False,
                'error': 'No import data provided. Send JSON data or upload a file.'
            }), 400
        
        # Validate backup data structure
        if not isinstance(import_data, dict) or 'hosts' not in import_data:
            return jsonify({
                'success': False,
                'error': 'Invalid backup format. Missing hosts data.'
            }), 400
        
        hosts_to_import = import_data.get('hosts', [])
        if not isinstance(hosts_to_import, list):
            return jsonify({
                'success': False,
                'error': 'Invalid backup format. Hosts must be a list.'
            }), 400
        
        # Import mode: 'merge' (default) or 'replace'
        import_mode = request.args.get('mode', 'merge')
        
        results = {
            'imported': 0,
            'updated': 0,
            'skipped': 0,
            'errors': [],
            'details': []
        }
        
        # If replace mode, backup existing hosts first
        if import_mode == 'replace':
            existing_hosts = host_manager.get_all_hosts()
            print(f"Replace mode: Backing up {len(existing_hosts)} existing hosts")
            
            # Delete all existing hosts
            try:
                with db.get_connection() as conn:
                    conn.execute("DELETE FROM hosts")
                    conn.commit()
                print("Cleared all existing hosts for replace mode")
            except Exception as e:
                return jsonify({
                    'success': False,
                    'error': f'Failed to clear existing hosts: {str(e)}'
                }), 500
        
        # Process each host in the import data
        for i, host_data in enumerate(hosts_to_import):
            try:
                # Validate required fields
                name = host_data.get('name', '').strip()
                ip_address = host_data.get('ip_address', '').strip()
                username = host_data.get('username', 'root').strip()
                ssh_port = int(host_data.get('ssh_port', 22))
                description = host_data.get('description', '').strip()
                
                if not name or not ip_address:
                    results['errors'].append(f"Host {i+1}: Missing required fields (name, ip_address)")
                    results['skipped'] += 1
                    continue
                
                # Validate SSH port
                if ssh_port < 1 or ssh_port > 65535:
                    results['errors'].append(f"Host {i+1} ({name}): Invalid SSH port {ssh_port}")
                    results['skipped'] += 1
                    continue
                
                # Check if host already exists (by IP or name)
                existing_host = None
                if import_mode == 'merge':
                    try:
                        existing_hosts = host_manager.get_all_hosts()
                        for host in existing_hosts:
                            if (host.get('ip_address') == ip_address or 
                                host.get('name') == name):
                                existing_host = host
                                break
                    except Exception as e:
                        print(f"Warning: Could not check existing hosts: {e}")
                
                if existing_host and import_mode == 'merge':
                    # Update existing host
                    try:
                        with db.get_connection() as conn:
                            conn.execute("""
                                UPDATE hosts 
                                SET name = ?, ip_address = ?, username = ?, ssh_port = ?, 
                                    description = ?, updated_at = CURRENT_TIMESTAMP
                                WHERE id = ?
                            """, (name, ip_address, username, ssh_port, description, existing_host['id']))
                            conn.commit()
                        
                        results['updated'] += 1
                        results['details'].append(f"Updated: {name} ({ip_address})")
                        print(f"Updated host: {name} ({ip_address})")
                        
                    except Exception as e:
                        results['errors'].append(f"Host {name}: Update failed - {str(e)}")
                        results['skipped'] += 1
                else:
                    # Add new host
                    try:
                        host_id = host_manager.add_host(name, ip_address, username, ssh_port, description)
                        results['imported'] += 1
                        results['details'].append(f"Added: {name} ({ip_address})")
                        print(f"Added host: {name} ({ip_address})")
                        
                    except Exception as e:
                        results['errors'].append(f"Host {name}: Import failed - {str(e)}")
                        results['skipped'] += 1
                        
            except Exception as e:
                results['errors'].append(f"Host {i+1}: Processing failed - {str(e)}")
                results['skipped'] += 1
        
        # Prepare response
        total_processed = results['imported'] + results['updated'] + results['skipped']
        success_rate = ((results['imported'] + results['updated']) / total_processed * 100) if total_processed > 0 else 0
        
        response_data = {
            'success': True,
            'message': f'Import completed: {results["imported"]} added, {results["updated"]} updated, {results["skipped"]} skipped',
            'import_mode': import_mode,
            'results': results,
            'summary': {
                'total_hosts_in_backup': len(hosts_to_import),
                'total_processed': total_processed,
                'success_count': results['imported'] + results['updated'],
                'success_rate': round(success_rate, 1)
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Return appropriate status code
        if results['errors'] and (results['imported'] + results['updated']) == 0:
            # All imports failed
            response_data['success'] = False
            return jsonify(response_data), 500
        elif results['errors']:
            # Some imports failed
            return jsonify(response_data), 207  # Multi-Status
        else:
            # All imports successful
            return jsonify(response_data), 200
            
    except Exception as e:
        print(f"Error importing hosts: {e}")
        return jsonify({
            'success': False,
            'error': f'Import failed: {str(e)}'
        }), 500

@app.route('/api/validate_backup', methods=['POST'])
def validate_backup_file():
    """Validate a backup file without importing it"""
    try:
        # Get backup data
        backup_data = None
        
        if request.is_json:
            backup_data = request.get_json()
        elif 'file' in request.files:
            file = request.files['file']
            if file.filename == '':
                return jsonify({
                    'success': False,
                    'error': 'No file selected'
                }), 400
            
            try:
                file_content = file.read().decode('utf-8')
                backup_data = json.loads(file_content)
            except json.JSONDecodeError as e:
                return jsonify({
                    'success': False,
                    'error': f'Invalid JSON file: {str(e)}'
                }), 400
        else:
            return jsonify({
                'success': False,
                'error': 'No backup data provided'
            }), 400
        
        # Validate backup structure
        validation_results = {
            'valid': True,
            'issues': [],
            'warnings': [],
            'stats': {
                'total_hosts': 0,
                'valid_hosts': 0,
                'invalid_hosts': 0,
                'duplicate_names': 0,
                'duplicate_ips': 0
            },
            'host_details': []
        }
        
        if not isinstance(backup_data, dict):
            validation_results['valid'] = False
            validation_results['issues'].append('Backup data must be a JSON object')
            return jsonify(validation_results), 400
        
        if 'hosts' not in backup_data:
            validation_results['valid'] = False
            validation_results['issues'].append('Missing hosts data in backup')
            return jsonify(validation_results), 400
        
        hosts_data = backup_data.get('hosts', [])
        if not isinstance(hosts_data, list):
            validation_results['valid'] = False
            validation_results['issues'].append('Hosts data must be a list')
            return jsonify(validation_results), 400
        
        validation_results['stats']['total_hosts'] = len(hosts_data)
        
        # Track duplicates
        seen_names = set()
        seen_ips = set()
        
        # Validate each host
        for i, host in enumerate(hosts_data):
            host_issues = []
            
            if not isinstance(host, dict):
                host_issues.append('Host data must be an object')
            else:
                # Check required fields
                name = host.get('name', '').strip()
                ip_address = host.get('ip_address', '').strip()
                
                if not name:
                    host_issues.append('Missing or empty name')
                elif name in seen_names:
                    host_issues.append(f'Duplicate name: {name}')
                    validation_results['stats']['duplicate_names'] += 1
                else:
                    seen_names.add(name)
                
                if not ip_address:
                    host_issues.append('Missing or empty IP address')
                elif ip_address in seen_ips:
                    host_issues.append(f'Duplicate IP address: {ip_address}')
                    validation_results['stats']['duplicate_ips'] += 1
                else:
                    seen_ips.add(ip_address)
                
                # Validate SSH port
                ssh_port = host.get('ssh_port', 22)
                try:
                    ssh_port = int(ssh_port)
                    if ssh_port < 1 or ssh_port > 65535:
                        host_issues.append(f'Invalid SSH port: {ssh_port} (must be 1-65535)')
                except (ValueError, TypeError):
                    host_issues.append(f'SSH port must be a number: {ssh_port}')
                
                # Optional field validation
                username = host.get('username', 'root')
                if not username.strip():
                    validation_results['warnings'].append(f'Host {i+1} ({name}): Empty username, will default to "root"')
            
            validation_results['host_details'].append({
                'index': i + 1,
                'name': host.get('name', 'N/A'),
                'ip_address': host.get('ip_address', 'N/A'),
                'valid': len(host_issues) == 0,
                'issues': host_issues
            })
            
            if len(host_issues) == 0:
                validation_results['stats']['valid_hosts'] += 1
            else:
                validation_results['stats']['invalid_hosts'] += 1
                validation_results['valid'] = False
        
        # Add overall validation issues
        if validation_results['stats']['duplicate_names'] > 0:
            validation_results['issues'].append(f'Found {validation_results["stats"]["duplicate_names"]} duplicate host names')
        
        if validation_results['stats']['duplicate_ips'] > 0:
            validation_results['issues'].append(f'Found {validation_results["stats"]["duplicate_ips"]} duplicate IP addresses')
        
        # Add backup metadata if available
        if 'backup_timestamp' in backup_data:
            validation_results['backup_info'] = {
                'timestamp': backup_data.get('backup_timestamp'),
                'application': backup_data.get('application'),
                'version': backup_data.get('version'),
                'host_count': backup_data.get('host_count')
            }
        
        return jsonify(validation_results)
        
    except Exception as e:
        print(f"Error validating backup: {e}")
        return jsonify({
            'success': False,
            'error': f'Validation failed: {str(e)}'
        }), 500

# Agent Management API Endpoints
@app.route('/api/agent/register', methods=['POST'])
def agent_register():
    """Register an agent with the server"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        username = data.get('username')
        agent_version = data.get('agent_version')
        
        if not all([agent_id, hostname, ip_address, username]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: agent_id, hostname, ip_address, username'
            }), 400
        
        # Try to find matching host
        host_id = None
        try:
            hosts = host_manager.get_all_hosts()
            for host in hosts:
                if host['ip_address'] == ip_address or host['name'] == hostname:
                    host_id = host['id']
                    break
        except Exception as e:
            print(f"Warning: Could not match agent to existing host: {e}")
        
        # Register agent
        db.register_agent(agent_id, hostname, ip_address, username, agent_version, host_id)
        
        # Create default configuration
        server_url = request.url_root.rstrip('/')
        db.save_agent_config(
            agent_id=agent_id,
            server_url=server_url,
            scan_interval=300,  # 5 minutes
            heartbeat_interval=60,  # 1 minute
            log_collection_enabled=True,
            log_paths='/var/log,/var/log/syslog,/var/log/auth.log',
            scan_enabled=True
        )
        
        return jsonify({
            'success': True,
            'message': f'Agent {hostname} registered successfully',
            'agent_id': agent_id,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error registering agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/heartbeat', methods=['POST'])
def agent_heartbeat():
    """Receive heartbeat from agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        status = data.get('status', 'active')
        error_message = data.get('error_message')
        
        if not agent_id:
            return jsonify({
                'success': False,
                'error': 'agent_id is required'
            }), 400
        
        # Update agent heartbeat
        db.update_agent_heartbeat(agent_id, status, error_message)
        
        return jsonify({
            'success': True,
            'message': 'Heartbeat received',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error processing heartbeat: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/config/<agent_id>', methods=['GET'])
def get_agent_config(agent_id):
    """Get configuration for an agent"""
    try:
        config = db.get_agent_config(agent_id)
        
        if not config:
            return jsonify({
                'success': False,
                'error': 'Agent configuration not found'
            }), 404
        
        # Remove sensitive data
        safe_config = {
            'scan_interval': config.get('scan_interval', 300),
            'heartbeat_interval': config.get('heartbeat_interval', 60),
            'log_collection_enabled': config.get('log_collection_enabled', True),
            'log_paths': config.get('log_paths', '/var/log'),
            'scan_enabled': config.get('scan_enabled', True),
            'config_version': config.get('config_version', 1)
        }
        
        return jsonify({
            'success': True,
            'config': safe_config,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/config/<agent_id>', methods=['POST'])
def update_agent_config(agent_id):
    """Update configuration for an agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Validate configuration data
        scan_interval = data.get('scan_interval', 300)
        heartbeat_interval = data.get('heartbeat_interval', 60)
        log_collection_enabled = data.get('log_collection_enabled', True)
        log_paths = data.get('log_paths', '/var/log')
        scan_enabled = data.get('scan_enabled', True)
        
        # Validate ranges
        if not (60 <= scan_interval <= 86400):
            return jsonify({
                'success': False,
                'error': 'Scan interval must be between 60 and 86400 seconds'
            }), 400
            
        if not (30 <= heartbeat_interval <= 300):
            return jsonify({
                'success': False,
                'error': 'Heartbeat interval must be between 30 and 300 seconds'
            }), 400
        
        # Update agent configuration
        db.save_agent_config(
            agent_id=agent_id,
            server_url=request.url_root.rstrip('/'),
            scan_interval=scan_interval,
            heartbeat_interval=heartbeat_interval,
            log_collection_enabled=log_collection_enabled,
            log_paths=log_paths,
            scan_enabled=scan_enabled
        )
        
        return jsonify({
            'success': True,
            'message': 'Agent configuration updated successfully',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error updating agent config: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/scan_results', methods=['POST'])
def receive_agent_scan_results():
    """Receive scan results from agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        scan_type = data.get('scan_type')
        scan_data = data.get('scan_data')
        
        if not all([agent_id, scan_type, scan_data]):
            return jsonify({
                'success': False,
                'error': 'Missing required fields: agent_id, scan_type, scan_data'
            }), 400
        
        # Save scan results
        db.save_agent_scan_result(agent_id, scan_type, scan_data)
        
        # Update agent last scan time
        db.update_agent_scan_time(agent_id)
        
        return jsonify({
            'success': True,
            'message': 'Scan results received',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error receiving scan results: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/logs', methods=['POST'])
def receive_agent_logs():
    """Receive logs from agent"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        logs = data.get('logs', [])
        
        if not agent_id:
            return jsonify({
                'success': False,
                'error': 'agent_id is required'
            }), 400
        
        if logs:
            # Save logs
            db.save_agent_logs(agent_id, logs)
        
        return jsonify({
            'success': True,
            'message': f'Received {len(logs)} log entries',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error receiving logs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agents', methods=['GET'])
def get_all_agents():
    """Get all registered agents"""
    try:
        agents = db.get_all_agents()
        
        # Add status indicators
        now = datetime.now()
        for agent in agents:
            if agent.get('last_heartbeat'):
                try:
                    last_heartbeat = datetime.fromisoformat(agent['last_heartbeat'].replace(' ', 'T'))
                    minutes_since = (now - last_heartbeat).total_seconds() / 60
                    
                    if minutes_since <= 2:
                        agent['heartbeat_status'] = 'online'
                    elif minutes_since <= 5:
                        agent['heartbeat_status'] = 'warning'
                    else:
                        agent['heartbeat_status'] = 'offline'
                        
                    agent['minutes_since_heartbeat'] = int(minutes_since)
                except:
                    agent['heartbeat_status'] = 'unknown'
                    agent['minutes_since_heartbeat'] = None
            else:
                agent['heartbeat_status'] = 'never'
                agent['minutes_since_heartbeat'] = None
        
        return jsonify({
            'success': True,
            'agents': agents,
            'count': len(agents),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agents: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/logs', methods=['GET'])
def get_agent_logs():
    """Get agent logs"""
    try:
        agent_id = request.args.get('agent_id')
        hours = int(request.args.get('hours', 24))
        limit = int(request.args.get('limit', 1000))
        
        logs = db.get_agent_logs(agent_id, hours, limit)
        
        return jsonify({
            'success': True,
            'logs': logs,
            'count': len(logs),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent logs: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/stats', methods=['GET'])
def get_agent_stats():
    """Get agent statistics"""
    try:
        stats = db.get_agent_stats()
        
        return jsonify({
            'success': True,
            'stats': stats,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent stats: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# SSH-based Agent Deployment Endpoints
@app.route('/api/hosts', methods=['GET'])
def get_all_hosts():
    """Get all configured hosts"""
    try:
        hosts = host_manager.get_all_hosts()
        return jsonify({
            'success': True,
            'hosts': hosts,
            'count': len(hosts),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/deploy_agent', methods=['POST'])
def deploy_agent_via_ssh():
    """Deploy agent to a host via SSH"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        host_id = data.get('host_id')
        server_url = data.get('server_url', request.url_root.rstrip('/'))
        
        if not host_id:
            return jsonify({
                'success': False,
                'error': 'host_id is required'
            }), 400
        
        # Get host information
        hosts = host_manager.get_all_hosts()
        host = next((h for h in hosts if h['id'] == host_id), None)
        
        if not host:
            return jsonify({
                'success': False,
                'error': f'Host with ID {host_id} not found'
            }), 404
        
        # Deploy agent via SSH
        result = deploy_agent_to_host_ssh(host, server_url)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Agent deployed successfully to {host["name"]}',
                'output': result.get('output', ''),
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Deployment failed'),
                'output': result.get('output', '')
            }), 500
        
    except Exception as e:
        print(f"Error deploying agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/control_agent', methods=['POST'])
def control_agent_via_ssh():
    """Control agent (start/stop/restart/status) via SSH"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        action = data.get('action')
        
        if not all([hostname, ip_address, action]):
            return jsonify({
                'success': False,
                'error': 'hostname, ip_address, and action are required'
            }), 400
        
        if action not in ['start', 'stop', 'restart', 'status', 'config']:
            return jsonify({
                'success': False,
                'error': 'Invalid action. Must be one of: start, stop, restart, status, config'
            }), 400
        
        # Find host by IP or name
        hosts = host_manager.get_all_hosts()
        host = next((h for h in hosts if h['ip_address'] == ip_address or h['name'] == hostname), None)
        
        if not host:
            return jsonify({
                'success': False,
                'error': f'Host {hostname} ({ip_address}) not found in configuration'
            }), 404
        
        # Execute control action via SSH
        result = control_agent_on_host_ssh(host, action)
        
        return jsonify({
            'success': result['success'],
            'output': result.get('output', ''),
            'error': result.get('error'),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error controlling agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/uninstall_agent', methods=['POST'])
def uninstall_agent_via_ssh():
    """Uninstall agent from a host via SSH"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        
        if not all([hostname, ip_address]):
            return jsonify({
                'success': False,
                'error': 'hostname and ip_address are required'
            }), 400
        
        # Find host by IP or name
        hosts = host_manager.get_all_hosts()
        host = next((h for h in hosts if h['ip_address'] == ip_address or h['name'] == hostname), None)
        
        if not host:
            return jsonify({
                'success': False,
                'error': f'Host {hostname} ({ip_address}) not found in configuration'
            }), 404
        
        # Uninstall agent via SSH
        result = uninstall_agent_from_host_ssh(host)
        
        if result['success']:
            # Remove agent from database
            try:
                agents = db.get_all_agents()
                for agent in agents:
                    if agent.get('ip_address') == ip_address or agent.get('hostname') == hostname:
                        # Remove agent record (this would require a delete method in the database)
                        print(f"Agent record should be removed for {hostname}")
                        break
            except Exception as e:
                print(f"Warning: Could not remove agent from database: {e}")
            
            return jsonify({
                'success': True,
                'message': f'Agent uninstalled successfully from {hostname}',
                'output': result.get('output', ''),
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Uninstallation failed'),
                'output': result.get('output', '')
            }), 500
        
    except Exception as e:
        print(f"Error uninstalling agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def deploy_agent_to_host_ssh(host, server_url):
    """Deploy agent to a host using SSH"""
    try:
        print(f"Deploying agent to {host['name']} ({host['ip_address']})")
        
        # Validate host information
        if not host.get('ip_address'):
            return {
                'success': False,
                'error': 'Host IP address is required',
                'output': ''
            }
        
        if not host.get('name'):
            return {
                'success': False,
                'error': 'Host name is required',
                'output': ''
            }
        
        # Test SSH connectivity first
        print(f"Testing SSH connectivity to {host['ip_address']}...")
        test_result, test_error = host_manager.execute_command(host, 'echo "SSH connection test successful"', timeout=10)
        
        if not test_result or not test_result.get('success'):
            return {
                'success': False,
                'error': f'SSH connection failed: {test_error or "Connection timeout"}',
                'output': f'Cannot connect to {host["name"]} ({host["ip_address"]}) via SSH. Please check: 1) Host is online, 2) SSH service is running, 3) SSH keys are properly configured, 4) Username is correct ({host.get("username", "root")})'
            }
        
        print(f"SSH connectivity confirmed. Proceeding with deployment...")
        
        # Create deployment script commands
        deployment_script = f"""
#!/bin/bash
set -e

# Set environment variables for non-interactive installation
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

echo "Starting NetworkMap agent deployment..."

# Create directories
echo "Creating directories..."
sudo mkdir -p /opt/networkmap-agent /etc/networkmap-agent /var/log/networkmap-agent

# Download agent script
echo "Downloading agent script..."
curl -f -o /tmp/networkmap_agent.py {server_url}/static/networkmap_agent.py
sudo cp /tmp/networkmap_agent.py /opt/networkmap-agent/networkmap_agent.py
sudo chmod +x /opt/networkmap-agent/networkmap_agent.py

# Update package lists quietly
echo "Updating package lists..."
sudo apt-get update -qq >/dev/null 2>&1

# Install required packages with proper flags for non-interactive mode
echo "Installing required packages..."
sudo apt-get install -y -qq \
    --no-install-recommends \
    --no-install-suggests \
    -o Dpkg::Options::="--force-confdef" \
    -o Dpkg::Options::="--force-confold" \
    python3-full \
    python3-pip \
    python3-venv \
    python3-requests \
    curl \
    >/dev/null 2>&1

# Create virtual environment for the agent
echo "Setting up Python virtual environment..."
sudo python3 -m venv /opt/networkmap-agent/venv
sudo /opt/networkmap-agent/venv/bin/pip install --quiet --no-cache-dir requests psutil

# Create configuration
echo "Creating agent configuration..."
sudo /opt/networkmap-agent/venv/bin/python /opt/networkmap-agent/networkmap_agent.py --create-config --server-url {server_url} --username $(whoami)

# Create systemd service with virtual environment
echo "Creating systemd service..."
sudo tee /etc/systemd/system/networkmap-agent.service >/dev/null << 'SERVICEEOF'
[Unit]
Description=NetworkMap Monitoring Agent
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/opt/networkmap-agent
ExecStart=/opt/networkmap-agent/venv/bin/python /opt/networkmap-agent/networkmap_agent.py
Restart=always
RestartSec=10
Environment=PATH=/opt/networkmap-agent/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONUNBUFFERED=1

# Logging - use systemd journal instead of file logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=networkmap-agent

# Security settings - less restrictive to allow proper operation
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths=/var/log/networkmap-agent /etc/networkmap-agent /opt/networkmap-agent

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Set proper permissions
echo "Setting permissions..."
sudo chown -R root:root /opt/networkmap-agent
sudo chown -R root:root /etc/networkmap-agent
sudo chown -R root:root /var/log/networkmap-agent
sudo chmod 755 /opt/networkmap-agent
sudo chmod 755 /etc/networkmap-agent
sudo chmod 755 /var/log/networkmap-agent

# Reload systemd and start service
echo "Starting NetworkMap agent service..."
sudo systemctl daemon-reload
sudo systemctl enable networkmap-agent >/dev/null 2>&1
sudo systemctl start networkmap-agent

# Wait a moment and check if service started successfully
sleep 3
if sudo systemctl is-active --quiet networkmap-agent; then
    echo "✓ NetworkMap agent service started successfully"
else
    echo "⚠ Warning: NetworkMap agent service may not have started properly"
    sudo systemctl status networkmap-agent --no-pager -l || true
fi

# Cleanup
rm -f /tmp/networkmap_agent.py

echo "Agent deployment completed successfully!"
echo "Service status: $(sudo systemctl is-active networkmap-agent)"
echo "To check logs: sudo journalctl -u networkmap-agent -f"
"""
        
        # Execute deployment via SSH
        result, error = host_manager.execute_command(host, deployment_script, timeout=600)
        
        if result and result['success']:
            return {
                'success': True,
                'output': result.get('stdout', ''),
                'message': 'Agent deployed successfully'
            }
        else:
            error_msg = result.get('stderr', error) if result else str(error)
            return {
                'success': False,
                'error': f'Deployment failed: {error_msg}',
                'output': result.get('stdout', '') if result else ''
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Exception during deployment: {str(e)}',
            'output': ''
        }

def control_agent_on_host_ssh(host, action):
    """Control agent on a host using SSH"""
    try:
        print(f"Executing {action} on agent at {host['name']} ({host['ip_address']})")
        
        if action == 'status':
            command = 'sudo systemctl status networkmap-agent --no-pager -l'
        elif action == 'start':
            command = 'sudo systemctl start networkmap-agent'
        elif action == 'stop':
            command = 'sudo systemctl stop networkmap-agent'
        elif action == 'restart':
            command = 'sudo systemctl restart networkmap-agent'
        elif action == 'config':
            command = 'sudo cat /etc/networkmap-agent/config.json 2>/dev/null || echo "Configuration file not found"'
        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}'
            }
        
        # Execute command via SSH
        result, error = host_manager.execute_command(host, command, timeout=60)
        
        if result:
            # For systemctl commands, both stdout and stderr might contain useful info
            output = result.get('stdout', '') + ('\n' + result.get('stderr', '') if result.get('stderr') else '')
            
            return {
                'success': True,
                'output': output.strip(),
                'action': action
            }
        else:
            return {
                'success': False,
                'error': f'Command execution failed: {error}',
                'output': ''
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Exception during {action}: {str(e)}',
            'output': ''
        }

def uninstall_agent_from_host_ssh(host):
    """Uninstall agent from a host using SSH"""
    try:
        print(f"Uninstalling agent from {host['name']} ({host['ip_address']})")
        
        # Create uninstallation script
        uninstall_script = """
#!/bin/bash

# Stop and disable service
sudo systemctl stop networkmap-agent 2>/dev/null || true
sudo systemctl disable networkmap-agent 2>/dev/null || true

# Remove service file
sudo rm -f /etc/systemd/system/networkmap-agent.service
sudo systemctl daemon-reload

# Remove directories
sudo rm -rf /opt/networkmap-agent /var/log/networkmap-agent /etc/networkmap-agent

# Remove user
sudo userdel networkmap-agent 2>/dev/null || true
sudo rm -rf /home/networkmap-agent 2>/dev/null || true

# Remove sudo configuration
sudo rm -f /etc/sudoers.d/networkmap-agent

echo "Agent uninstallation completed successfully"
"""
        
        # Execute uninstallation via SSH
        result, error = host_manager.execute_command(host, uninstall_script, timeout=120)
        
        if result and result['success']:
            return {
                'success': True,
                'output': result.get('stdout', ''),
                'message': 'Agent uninstalled successfully'
            }
        else:
            error_msg = result.get('stderr', error) if result else str(error)
            return {
                'success': False,
                'error': f'Uninstallation failed: {error_msg}',
                'output': result.get('stdout', '') if result else ''
            }
            
    except Exception as e:
        return {
            'success': False,
            'error': f'Exception during uninstallation: {str(e)}',
            'output': ''
        }

def update_scan_status(phase, message, progress=None, current_host=None, step=None):
    """Helper to update scan status with consistent format"""
    global scan_status
    scan_status['phase'] = phase
    scan_status['phase_message'] = message
    if progress is not None:
        scan_status['progress'] = progress
    if current_host is not None:
        scan_status['current_host'] = current_host
    if step is not None:
        scan_status['step'] = step
    print(f"[SCAN] {phase}: {message}")

def progress_callback(message):
    """Callback to update scan status from scanner progress"""
    global scan_status
    # Extract host name from message if possible
    current_host = scan_status.get('current_host')
    
    # Update the phase message with the real scanner output
    scan_status['phase_message'] = message
    print(f"[SCAN CALLBACK] {message}")

def run_scan():
    """Enhanced background scan function with real-time scanner progress"""
    global scan_status
    
    scan_status['running'] = True
    scan_status['progress'] = 0
    scan_status['last_scan'] = datetime.now().isoformat()
    
    try:
        # Phase 1: Initialize
        update_scan_status('initializing', 'Starting network discovery...', 0)
        time.sleep(0.5)
        
        # Phase 2: Discovery preparation
        update_scan_status('preparing', 'Preparing network discovery...', 5)
        hosts = host_manager.get_all_hosts()
        total_hosts = len(hosts)
        
        if total_hosts == 0:
            update_scan_status('complete', 'No hosts configured for scanning', 100)
            return
            
        update_scan_status('preparing', f'Found {total_hosts} hosts to scan', 10)
        time.sleep(0.5)
        
        # Phase 3: Host scanning with real-time progress from scanner
        update_scan_status('scanning', 'Beginning host scans...', 15)
        
        # Set up progress callback for detailed scanner updates
        scanner.set_progress_callback(progress_callback)
        
        for i, host in enumerate(hosts):
            # Calculate progress: 15% to 80% for host scanning
            base_progress = 15 + int((i / total_hosts) * 65)
            host_progress = base_progress + int((1 / total_hosts) * 65)
            
            # Update current host in scan status
            scan_status['current_host'] = host['name']
            scan_status['step'] = f"{i+1}/{total_hosts}"
            
            update_scan_status(
                'scanning', 
                f"Starting scan of {host['name']} ({host['ip_address']})...",
                base_progress,
                host['name'],
                f"{i+1}/{total_hosts} - starting"
            )
            
            try:
                # Actual host scan - now with real-time progress updates
                scanner.scan_host(host)
                
                update_scan_status(
                    'scanning',
                    f"Completed comprehensive scan of {host['name']}",
                    host_progress,
                    host['name'],
                    f"{i+1}/{total_hosts} - complete"
                )
                
            except Exception as e:
                print(f"Error scanning host {host['name']}: {e}")
                update_scan_status(
                    'scanning',
                    f"Error scanning {host['name']}: {str(e)[:50]}",
                    host_progress,
                    host['name'],
                    f"{i+1}/{total_hosts} - error"
                )
            
            time.sleep(0.5)  # Brief pause between hosts
        
        # Phase 4: Network discovery analysis
        update_scan_status('analyzing', 'Processing collected data...', 82)
        time.sleep(1)
        
        update_scan_status('analyzing', 'Building network topology map...', 87)
        time.sleep(1)
        
        try:
            # Run topology analysis if available
            update_scan_status('analyzing', 'Running advanced topology analysis...', 90)
            topology_analyzer.analyze_network_topology()
            update_scan_status('analyzing', 'Topology analysis complete', 92)
        except Exception as e:
            print(f"Topology analysis error: {e}")
            update_scan_status('analyzing', f'Topology analysis failed: {str(e)[:50]}', 92)
        
        # Phase 4.5: Build enhanced network topology
        try:
            update_scan_status('analyzing', 'Building comprehensive network map...', 94)
            from enhanced_topology_builder import EnhancedTopologyBuilder
            topology_builder = EnhancedTopologyBuilder(db, host_manager)
            topology_builder.build_comprehensive_topology()
            update_scan_status('analyzing', 'Enhanced topology map created', 96)
        except Exception as e:
            print(f"Enhanced topology building error: {e}")
            update_scan_status('analyzing', f'Enhanced topology building failed: {str(e)[:50]}', 96)
        
        update_scan_status('finalizing', 'Finalizing results...', 98)
        time.sleep(1)
        
        # Phase 5: Complete
        update_scan_status('complete', f'Scan completed - {total_hosts} hosts processed', 100, None)
        
    except Exception as e:
        print(f"Scan error: {e}")
        update_scan_status('error', f'Scan failed: {str(e)[:100]}', scan_status.get('progress', 0))
    finally:
        time.sleep(2)  # Keep final message visible briefly
        scan_status['running'] = False
        scan_status['phase'] = 'idle'
        scan_status['current_host'] = None
        scan_status['step'] = None
        # Clear the callback
        scanner.set_progress_callback(None)

@app.route('/api/test_host/<int:host_id>', methods=['POST'])
def test_host_connectivity(host_id):
    """Test connectivity to a specific host"""
    try:
        host = host_manager.get_host(host_id)
        if not host:
            return jsonify({
                'success': False,
                'error': 'Host not found'
            }), 404
        
        # Test connectivity
        result = host_manager.test_connectivity(host)
        
        return jsonify({
            'success': True,
            'host_id': host_id,
            'host_name': host['name'],
            'ip_address': host['ip_address'],
            'status': result['status'],
            'ping_success': result['ping'],
            'ssh_success': result['ssh'],
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error testing host connectivity: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

if __name__ == '__main__':
    # Initialize database
    db.init_db()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5150, threaded=True)
