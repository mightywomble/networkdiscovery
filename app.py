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
    """Network visualization page"""
    return render_template('network_map.html')

@app.route('/enhanced_topology')
def enhanced_topology():
    """Enhanced network topology analysis page"""
    return render_template('enhanced_topology.html')

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
        # Get recent enhanced scan results from database
        results = db.execute('''
            SELECT host_id, scan_timestamp, scan_data 
            FROM enhanced_scan_results 
            WHERE scan_timestamp > datetime('now', '-24 hours')
            ORDER BY scan_timestamp DESC
        ''').fetchall()
        
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'scan_results_count': len(results),
            'enhanced_scan_results': [],
            'summary': enhanced_scan_progress['scan_summary']
        }
        
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
            'error': str(e)
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
        
        # Phase 1: Network Discovery
        enhanced_scan_progress['current_phase'] = 'discovery'
        update_scan_phase('discovery', 'running', 0)
        log_enhanced_scan("🔍 Phase 1: Advanced Network Discovery")
        
        for i, host in enumerate(online_hosts):
            hostname = host['name']
            enhanced_scan_progress['current_host'] = hostname
            
            # Initialize host data
            enhanced_scan_progress['hosts'][hostname] = {
                'status': 'scanning',
                'progress': 0,
                'current_phase': 'discovery',
                'current_action': 'Starting comprehensive scan...',
                'completed_phases': [],
                'start_time': datetime.now().isoformat()
            }
            
            host_data = enhanced_scan_progress['hosts'][hostname]
            
            try:
                log_enhanced_scan(f"🚀 Starting comprehensive scan of {hostname}", host=hostname)
                
                # Run comprehensive enhanced scan
                scan_results = enhanced_scanner.comprehensive_network_scan(host)
                
                # Update host progress
                host_data['status'] = 'complete'
                host_data['progress'] = 100
                host_data['current_action'] = 'Comprehensive scan completed'
                host_data['completed_phases'] = ['discovery', 'analysis', 'performance', 'security', 'infrastructure', 'connectivity']
                host_data['end_time'] = datetime.now().isoformat()
                
                # Update summary statistics
                if 'network_topology' in scan_results:
                    topo = scan_results['network_topology']
                    if 'ping_sweep' in topo:
                        for network, data in topo['ping_sweep'].items():
                            if isinstance(data, dict) and 'count' in data:
                                enhanced_scan_progress['scan_summary']['discovery']['hosts_found'] += data['count']
                                enhanced_scan_progress['scan_summary']['discovery']['networks_scanned'] += 1
                    
                    if 'port_scan' in topo:
                        for network_data in topo['port_scan'].values():
                            if isinstance(network_data, dict):
                                enhanced_scan_progress['scan_summary']['discovery']['open_ports'] += len(str(network_data).split('open'))
                
                if 'performance_metrics' in scan_results:
                    perf = scan_results['performance_metrics']
                    if 'internet_speed' in perf:
                        enhanced_scan_progress['scan_summary']['performance']['speed_tests'] += 1
                    if 'network_latency' in perf:
                        enhanced_scan_progress['scan_summary']['performance']['latency_tests'] += len(perf['network_latency'])
                
                log_enhanced_scan(f"✅ Comprehensive scan completed for {hostname}", host=hostname)
                
            except Exception as e:
                log_enhanced_scan(f"❌ Error scanning {hostname}: {str(e)}", 'error', host=hostname)
                host_data['status'] = 'error'
                host_data['current_action'] = f'Error: {str(e)[:100]}'
                host_data['error'] = str(e)
        
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

if __name__ == '__main__':
    # Initialize database
    db.init_db()
    
    # Run Flask app
    app.run(debug=True, host='0.0.0.0', port=5150, threaded=True)
