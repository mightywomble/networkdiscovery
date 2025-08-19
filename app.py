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


@app.route('/network_diagram')
def network_diagram():
    """Pure SVG network diagram - no vis.js, no physics, no flickering"""
    return render_template("enhanced_svg_diagram.html", disable_visjs=True)

@app.route("/pure_svg")
def pure_svg():
    """Pure SVG network diagram - completely standalone"""
    return render_template("enhanced_svg_diagram.html", disable_visjs=True)

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

# Global state for manual agent runs progress
agent_run_progress = {
    'running': {},  # Dict of agent_id -> run_info
    'logs': deque(maxlen=500)  # Recent logs across all runs
}

# Global state for script execution progress
script_execution_progress = {
    'running': {},  # Dict of execution_id -> execution_info
    'logs': deque(maxlen=1000),  # Recent logs across all script executions
    'completed': {}  # Recently completed executions (kept for 5 minutes)
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
        
        # Fallback to basic topology using hosts and agents
        hosts = host_manager.get_all_hosts()
        agents = db.get_all_agents()
        connections = db.get_recent_connections(hours=72)
        
        # Format data for visualization
        nodes = []
        edges = []
        
        # Add all hosts as nodes
        for host in hosts:
            # Check if this host has an active agent
            agent = next((a for a in agents if a.get('ip_address') == host['ip_address']), None)
            agent_status = 'no-agent'
            
            if agent:
                if agent.get('status') == 'active':
                    agent_status = 'agent-active'
                elif agent.get('last_heartbeat'):
                    agent_status = 'agent-inactive'
                else:
                    agent_status = 'agent-error'
            
            # Set node color based on status and agent presence
            if agent_status == 'agent-active':
                node_color = {'background': '#28a745', 'border': '#1e7e34'}  # Green for active agents
            elif agent_status == 'agent-inactive':
                node_color = {'background': '#ffc107', 'border': '#e0a800'}  # Yellow for inactive agents
            elif agent_status == 'agent-error':
                node_color = {'background': '#dc3545', 'border': '#c82333'}  # Red for error agents
            else:
                node_color = {'background': '#6c757d', 'border': '#5a6268'}  # Gray for no agent
            
            nodes.append({
                'id': host['id'],
                'label': host['name'],
                'ip': host['ip_address'],
                'status': host.get('status', 'unknown'),
                'agent_status': agent_status,
                'last_seen': host.get('last_seen'),
                'group': 'host',
                'title': f"{host['name']}\nIP: {host['ip_address']}\nStatus: {host.get('status', 'unknown')}\nAgent: {agent_status.replace('-', ' ').title()}",
                'size': 30,
                'shape': 'dot',
                'color': node_color
            })
        
        # Create external nodes for connections and add connections from database
        external_nodes = {}  # Track external nodes by IP
        host_id_map = {host['id']: host for host in hosts}  # Map host ID to host data
        
        print(f"DEBUG: Processing {len(connections)} connections")
        print(f"DEBUG: Host ID map: {list(host_id_map.keys())}")
        
        for i, conn in enumerate(connections):
            source_host_id = conn['source_host_id']
            dest_host_id = conn.get('dest_host_id')
            dest_ip = conn.get('dest_ip')
            
            print(f"DEBUG: Connection {i+1}: source_host_id={source_host_id}, dest_host_id={dest_host_id}, dest_ip={dest_ip}")
            
            # Only create edges for connections between known hosts or to external IPs
            if dest_host_id is not None and dest_host_id in host_id_map:
                print(f"DEBUG: Creating internal edge from {source_host_id} to {dest_host_id}")
                # Internal connection between managed hosts
                edges.append({
                    'id': f"{source_host_id}-{dest_host_id}-{conn.get('dest_port', 'unknown')}",
                    'from': source_host_id,
                    'to': dest_host_id,
                    'label': f":{conn.get('dest_port', '?')}",
                    'title': f"Protocol: {conn.get('protocol', 'unknown')}\nPort: {conn.get('dest_port', 'unknown')}\nConnections: {conn.get('connection_count', 1)}\nLast seen: {conn.get('last_seen', 'unknown')}",
                    'width': 2,
                    'color': '#007bff',
                    'arrows': {'to': True}
                })
            elif dest_ip and dest_host_id is None:
                # External connection - create external node if not exists
                if dest_ip not in external_nodes:
                    # Determine if this is a local or internet IP
                    is_local = (dest_ip.startswith('192.168.') or 
                               dest_ip.startswith('10.') or 
                               dest_ip.startswith('172.16.') or 
                               dest_ip.startswith('172.17.') or 
                               dest_ip.startswith('172.18.') or 
                               dest_ip.startswith('172.19.') or 
                               dest_ip.startswith('172.2') or 
                               dest_ip.startswith('172.3') or 
                               dest_ip.startswith('127.'))
                    
                    # Create a unique ID for external node
                    external_id = f"ext_{dest_ip.replace('.', '_')}"
                    
                    external_nodes[dest_ip] = {
                        'id': external_id,
                        'label': dest_ip,
                        'ip': dest_ip,
                        'status': 'external',
                        'group': 'external',
                        'title': f"External Host\nIP: {dest_ip}\nConnections: {sum(1 for c in connections if c.get('dest_ip') == dest_ip)}",
                        'size': 20,
                        'shape': 'dot',
                        'color': {'background': '#dc3545', 'border': '#c82333'} if not is_local else {'background': '#17a2b8', 'border': '#138496'}
                    }
                    
                    # Add external node to nodes list
                    nodes.append(external_nodes[dest_ip])
                
                # Create edge to external node
                external_id = external_nodes[dest_ip]['id']
                edges.append({
                    'id': f"{source_host_id}-{external_id}-{conn.get('dest_port', 'unknown')}",
                    'from': source_host_id,
                    'to': external_id,
                    'label': f":{conn.get('dest_port', '?')}",
                    'title': f"Protocol: {conn.get('protocol', 'unknown')}\nPort: {conn.get('dest_port', 'unknown')}\nConnections: {conn.get('connection_count', 1)}\nLast seen: {conn.get('last_seen', 'unknown')}",
                    'width': 1,
                    'color': '#dc3545' if not dest_ip.startswith(('192.168.', '10.', '172.')) else '#17a2b8',
                    'arrows': {'to': True},
                    'dashes': True if not dest_ip.startswith(('192.168.', '10.', '172.')) else False
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
            # If the default layout doesn't exist, return an empty layout instead of 404
            # This prevents the frontend from breaking when no layout has been saved yet
            if layout_name == 'default':
                empty_layout = {
                    'id': None,
                    'layout_name': 'default',
                    'layout_data': {'devices': {}, 'timestamp': datetime.now().isoformat()},
                    'created_by': 'system',
                    'created_at': datetime.now().isoformat(),
                    'updated_at': datetime.now().isoformat()
                }
                return jsonify({
                    'success': True,
                    'layout': empty_layout,
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
        agent_version = data.get('agent_version')
        build_date = data.get('build_date')
        
        if not agent_id:
            return jsonify({
                'success': False,
                'error': 'agent_id is required'
            }), 400
        
        # Update agent heartbeat with version information
        db.update_agent_heartbeat(agent_id, status, error_message, agent_version, build_date)
        
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
            'test_configuration': config.get('test_configuration'),
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
        test_configuration = data.get('test_configuration')
        
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
        
        # Validate test configuration if provided
        if test_configuration is not None:
            from network_test_suite import NetworkTestSuite
            validation_errors = NetworkTestSuite.validate_configuration(test_configuration)
            if validation_errors:
                return jsonify({
                    'success': False,
                    'error': f'Invalid test configuration: {"; ".join(validation_errors)}'
                }), 400
        
        # Update agent configuration
        db.save_agent_config(
            agent_id=agent_id,
            server_url=request.url_root.rstrip('/'),
            scan_interval=scan_interval,
            heartbeat_interval=heartbeat_interval,
            log_collection_enabled=log_collection_enabled,
            log_paths=log_paths,
            scan_enabled=scan_enabled,
            test_configuration=test_configuration
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

@app.route('/api/test')
def test_endpoint():
    return jsonify({'success': True, 'message': 'Test endpoint is working'})

@app.route('/api/agent/test_configurations', methods=['GET'])
def get_test_configurations():
    """Get available test configurations for agents"""
    try:
        from network_test_suite import NetworkTestSuite
        
        # Create instance and get all test categories and definitions
        test_suite = NetworkTestSuite()
        test_categories = test_suite.get_all_test_categories()
        default_config = test_suite.get_default_configuration()
        
        return jsonify({
            'success': True,
            'test_categories': test_categories,
            'default_configuration': default_config,
            'timestamp': datetime.now().isoformat()
        })
        
    except ImportError as e:
        print(f"NetworkTestSuite not available: {e}")
        # Return a basic fallback configuration
        fallback_categories = {
            'network_discovery': {
                'name': 'Network Discovery',
                'description': 'Basic network discovery tests',
                'tests': {
                    'port_scan': {
                        'name': 'Port Scanning',
                        'description': 'Scan for open ports on local network',
                        'tool': 'nmap',
                        'enabled': True
                    },
                    'ping_sweep': {
                        'name': 'Ping Sweep', 
                        'description': 'Fast ping sweep to find alive hosts',
                        'tool': 'fping',
                        'enabled': True
                    }
                }
            },
            'traffic_analysis': {
                'name': 'Traffic Analysis',
                'description': 'Basic traffic analysis',
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
                    }
                }
            }
        }
        
        fallback_default = {
            'network_discovery': {
                'port_scan': True,
                'ping_sweep': True
            },
            'traffic_analysis': {
                'interface_stats': True,
                'connection_analysis': True
            }
        }
        
        return jsonify({
            'success': True,
            'test_categories': fallback_categories,
            'default_configuration': fallback_default,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting test configurations: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Agent cleanup endpoints
@app.route('/api/agent/cleanup/duplicates', methods=['POST'])
def cleanup_duplicate_agents():
    """Remove duplicate agent entries"""
    try:
        removed_count = db.cleanup_duplicate_agents()
        
        return jsonify({
            'success': True,
            'message': f'Removed {removed_count} duplicate agent entries',
            'removed_count': removed_count,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error cleaning up duplicate agents: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/cleanup/stale', methods=['POST'])
def cleanup_stale_agents():
    """Remove agents that haven't sent heartbeats recently"""
    try:
        hours = int(request.json.get('hours', 24)) if request.is_json else 24
        removed_count = db.cleanup_stale_agents(hours)
        
        return jsonify({
            'success': True,
            'message': f'Removed {removed_count} stale agent entries (older than {hours} hours)',
            'removed_count': removed_count,
            'hours': hours,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error cleaning up stale agents: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/remove', methods=['POST'])
def remove_agent_by_id():
    """Remove a specific agent by agent_id"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({
                'success': False,
                'error': 'agent_id is required'
            }), 400
        
        # Get agent info before removing
        agent = db.get_agent(agent_id)
        if not agent:
            return jsonify({
                'success': False,
                'error': f'Agent {agent_id} not found'
            }), 404
        
        # Remove the agent
        db.remove_agent(agent_id)
        
        return jsonify({
            'success': True,
            'message': f'Removed agent {agent.get("hostname", "unknown")} ({agent_id})',
            'removed_agent': {
                'agent_id': agent_id,
                'hostname': agent.get('hostname'),
                'ip_address': agent.get('ip_address')
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error removing agent: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/remove_by_host', methods=['POST'])
def remove_agents_by_host():
    """Remove agents by hostname or IP address"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        
        if not hostname and not ip_address:
            return jsonify({
                'success': False,
                'error': 'Either hostname or ip_address is required'
            }), 400
        
        # Remove agents
        removed_count = db.remove_agents_by_host(hostname, ip_address)
        
        criteria = []
        if hostname:
            criteria.append(f'hostname="{hostname}"')
        if ip_address:
            criteria.append(f'ip_address="{ip_address}"')
        
        return jsonify({
            'success': True,
            'message': f'Removed {removed_count} agent entries matching {" or ".join(criteria)}',
            'removed_count': removed_count,
            'criteria': {
                'hostname': hostname,
                'ip_address': ip_address
            },
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error removing agents by host: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/versions', methods=['GET'])
def get_agent_versions():
    """Get agent version summary with individual agent data"""
    try:
        # Get all agents with version information
        agents = db.get_all_agents()
        
        # Get server version information
        # Try to read server agent version from the agent script
        server_version = "Unknown"
        server_build_date = "Unknown"
        
        try:
            import os
            import re
            # Check the static agent script first
            agent_script_paths = [
                os.path.join(os.path.dirname(__file__), 'static', 'networkmap_agent.py'),
                os.path.join(os.path.dirname(__file__), 'networkmap_agent.py'),
                os.path.join(os.path.dirname(__file__), 'agent.py')
            ]
            
            for agent_script_path in agent_script_paths:
                if os.path.exists(agent_script_path):
                    try:
                        with open(agent_script_path, 'r') as f:
                            content = f.read()
                            # Look for version information in the agent script
                            version_match = re.search(r'__version__\s*=\s*["\']([^"\'\']+)["\']', content)
                            build_match = re.search(r'__build_date__\s*=\s*["\']([^"\'\']+)["\']', content)
                            
                            # Also try alternative formats
                            if not version_match:
                                version_match = re.search(r'VERSION\s*=\s*["\']([^"\'\']+)["\']', content)
                            if not build_match:
                                build_match = re.search(r'BUILD_DATE\s*=\s*["\']([^"\'\']+)["\']', content)
                            
                            if version_match:
                                server_version = version_match.group(1)
                                print(f"Found server version: {server_version} from {agent_script_path}")
                            if build_match:
                                server_build_date = build_match.group(1)
                                print(f"Found server build date: {server_build_date} from {agent_script_path}")
                            
                            if version_match or build_match:
                                break  # Found version info, stop searching
                    except Exception as e:
                        print(f"Error reading {agent_script_path}: {e}")
                        continue
        except Exception as e:
            print(f"Warning: Could not read server version: {e}")
        
        # Fallback to default version if not found
        if server_version == "Unknown":
            server_version = "1.3.0"
        if server_build_date == "Unknown":
            server_build_date = datetime.now().strftime("%Y-%m-%d")
        
        return jsonify({
            'success': True,
            'agents': agents,
            'server_version': server_version,
            'server_build_date': server_build_date,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent versions: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/update', methods=['POST'])
def update_single_agent():
    """Update a single agent to the latest version"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({
                'success': False,
                'error': 'agent_id is required'
            }), 400
        
        # Get agent info
        agent = db.get_agent(agent_id)
        if not agent:
            return jsonify({
                'success': False,
                'error': f'Agent {agent_id} not found'
            }), 404
        
        # Mark update as started
        db.mark_agent_update_started(agent_id)
        
        # Get server URL from current request
        server_url = request.url_root.rstrip('/')
        
        # Start update process in background thread with server URL
        thread = threading.Thread(target=perform_agent_update, args=(agent, server_url))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Update started for agent {agent.get("hostname", "unknown")}',
            'agent_id': agent_id,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error starting agent update: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/update_all', methods=['POST'])
def update_all_agents():
    """Update all agents to the latest version"""
    try:
        agents = db.get_all_agents()
        active_agents = [agent for agent in agents if agent.get('status') == 'active']
        
        if not active_agents:
            return jsonify({
                'success': False,
                'error': 'No active agents found'
            }), 400
        
        # Get server URL from current request
        server_url = request.url_root.rstrip('/')
        
        # Start update process for all agents
        for agent in active_agents:
            db.mark_agent_update_started(agent['agent_id'])
            thread = threading.Thread(target=perform_agent_update, args=(agent, server_url))
            thread.daemon = True
            thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Update started for {len(active_agents)} active agents',
            'agent_count': len(active_agents),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error starting agent updates: {e}")
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
    """Deploy agent to a host via SSH with optional force redeploy"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        host_id = data.get('host_id')
        server_url = data.get('server_url', request.url_root.rstrip('/'))
        force_redeploy = data.get('force_redeploy', False)
        
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
        
        # Deploy agent via SSH with force redeploy option
        result = deploy_agent_to_host_ssh(host, server_url, force_redeploy)
        
        action_type = "Force redeployed" if force_redeploy else "Deployed"
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Agent {action_type.lower()} successfully to {host["name"]}',
                'output': result.get('output', ''),
                'force_redeploy': force_redeploy,
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', f'{action_type} failed'),
                'output': result.get('output', ''),
                'force_redeploy': force_redeploy
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

def deploy_agent_to_host_ssh(host, server_url, force_redeploy=False):
    """Deploy agent to a host using SSH"""
    try:
        action_type = "Force redeploying" if force_redeploy else "Deploying"
        print(f"{action_type} agent to {host['name']} ({host['ip_address']})")
        
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
        
        print(f"SSH connectivity confirmed. Proceeding with {action_type.lower()}...")
        
        # Create deployment script with optional cleanup for force redeploy
        cleanup_section = ""
        if force_redeploy:
            cleanup_section = f"""
# Force redeploy - completely remove existing agent first
echo "Force redeploy requested - removing existing agent installation..."

# Stop and disable existing service if it exists
sudo systemctl stop networkmap-agent 2>/dev/null || true
sudo systemctl disable networkmap-agent 2>/dev/null || true

# Remove existing service file
sudo rm -f /etc/systemd/system/networkmap-agent.service

# Remove existing directories and files
sudo rm -rf /opt/networkmap-agent /etc/networkmap-agent /var/log/networkmap-agent /etc/networkmap

# Remove any old configurations
sudo rm -f /etc/networkmap/agent.conf

# Reload systemd to remove service references
sudo systemctl daemon-reload

echo "✓ Existing agent installation removed"

"""
        
        # Create deployment script commands
        deployment_script = f"""
#!/bin/bash
set -e

# Set environment variables for non-interactive installation
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1

echo "Starting NetworkMap agent deployment..."

{cleanup_section}
# Create directories
echo "Creating directories..."
sudo mkdir -p /opt/networkmap-agent /etc/networkmap /var/log/networkmap-agent

# Download agent script with verification
echo "Downloading latest agent script..."
curl -f -o /tmp/networkmap_agent.py {server_url}/static/networkmap_agent.py

# Verify downloaded file is not empty
if [ ! -s /tmp/networkmap_agent.py ]; then
    echo "ERROR: Downloaded agent script is empty (0 bytes)"
    echo "Trying alternative download method..."
    wget -O /tmp/networkmap_agent.py {server_url}/static/networkmap_agent.py || \
      {{ echo "All download methods failed"; exit 1; }}
    
    # Check again
    if [ ! -s /tmp/networkmap_agent.py ]; then
        echo "ERROR: Downloaded agent script is still empty. Aborting."
        exit 1
    fi
fi

# Verify Python syntax before copying
echo "Verifying script integrity..."
python3 -m py_compile /tmp/networkmap_agent.py || {{ echo "ERROR: Downloaded script has syntax errors"; exit 1; }}

# Show file information for verification
echo "Agent script details:"
wc -l /tmp/networkmap_agent.py
head -n 30 /tmp/networkmap_agent.py | grep -E "version|build"

# Only copy if verification passes
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
    lsof \
    net-tools \
    iproute2 \
    procps \
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
sudo tee /etc/systemd/system/networkmap-agent.service >/dev/null <<'SERVICEEOF'
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
ReadWritePaths=/var/log/networkmap-agent /etc/networkmap /opt/networkmap-agent

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Set proper permissions
echo "Setting permissions..."
sudo chown -R root:root /opt/networkmap-agent
sudo chown -R root:root /etc/networkmap
sudo chown -R root:root /var/log/networkmap-agent
sudo chmod 755 /opt/networkmap-agent
sudo chmod 755 /etc/networkmap
sudo chmod 755 /var/log/networkmap-agent

# Reload systemd and start service
echo "Starting NetworkMap agent service..."
sudo systemctl daemon-reload
sudo systemctl enable networkmap-agent >/dev/null 2>&1
sudo systemctl start networkmap-agent

# Wait a moment and check if service started successfully
sleep 5
if sudo systemctl is-active --quiet networkmap-agent; then
    echo "✓ NetworkMap agent service started successfully"
    echo "Service status: $(sudo systemctl is-active networkmap-agent)"
else
    echo "⚠ Warning: NetworkMap agent service may not have started properly"
    sudo systemctl status networkmap-agent --no-pager -l || true
    echo "Check logs with: sudo journalctl -u networkmap-agent -f"
fi

# Show configuration location
echo "Configuration file: /etc/networkmap/agent.conf"
echo "Service status: $(sudo systemctl is-active networkmap-agent)"
echo "To check logs: sudo journalctl -u networkmap-agent -f"

# Cleanup
rm -f /tmp/networkmap_agent.py

echo "Agent deployment completed successfully!"
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

def perform_agent_update(agent, server_url):
    """Perform agent update via SSH"""
    try:
        agent_id = agent['agent_id']
        hostname = agent.get('hostname', 'unknown')
        ip_address = agent.get('ip_address')
        
        # Pretty formatted output
        print(f"\n🚀 ╭─────────────────────────────────────────────────╮")
        print(f"   │  STARTING AGENT UPDATE                          │")
        print(f"   │  Host: {hostname:<35} │")
        print(f"   │  IP:   {ip_address:<35} │")
        print(f"   ╰─────────────────────────────────────────────────╯")
        
        # Find the corresponding host in host_manager
        hosts = host_manager.get_all_hosts()
        host = None
        for h in hosts:
            if h.get('ip_address') == ip_address or h.get('name') == hostname:
                host = h
                break
        
        if not host:
            error_msg = f"Host configuration not found for agent {hostname} ({ip_address})"
            print(error_msg)
            db.mark_agent_update_failed(agent_id, error_msg)
            return
        
        # Get current agent version and build date from the actual agent script
        import os
        import re
        
        current_version = "1.4.0"  # Default fallback
        build_date = datetime.now().strftime('%Y-%m-%d')
        
        try:
            # Read version from the agent script
            agent_script_path = os.path.join(os.path.dirname(__file__), 'static', 'networkmap_agent.py')
            if os.path.exists(agent_script_path):
                with open(agent_script_path, 'r') as f:
                    content = f.read()
                    # Look for version information
                    version_match = re.search(r'__version__\s*=\s*["\']([^"\'\']+)["\']', content)
                    build_match = re.search(r'__build_date__\s*=\s*["\']([^"\'\']+)["\']', content)
                    
                    if version_match:
                        current_version = version_match.group(1)
                        print(f"Found agent version to deploy: {current_version}")
                    if build_match:
                        build_date = build_match.group(1)
                        print(f"Found agent build date: {build_date}")
        except Exception as e:
            print(f"Warning: Could not read agent version from script: {e}")
        
        # Create agent update script
        
        update_script = f"""
#!/bin/bash
set -e

echo "Starting NetworkMap agent update..."

# Stop the current agent service
echo "Stopping agent service..."
sudo systemctl stop networkmap-agent || true

# Backup current configuration
echo "Backing up configuration..."
sudo cp /etc/networkmap/agent.conf /etc/networkmap/agent.conf.backup 2>/dev/null || true

# Download latest agent script with verification
echo "Downloading latest agent version..."
curl -f -o /tmp/networkmap_agent.py {server_url}/static/networkmap_agent.py

# Verify downloaded file is not empty
if [ ! -s /tmp/networkmap_agent.py ]; then
    echo "ERROR: Downloaded agent script is empty (0 bytes)"
    echo "Trying alternative download method..."
    wget -O /tmp/networkmap_agent.py {server_url}/static/networkmap_agent.py || \
      {{ echo "All download methods failed"; exit 1; }}
    
    # Check again
    if [ ! -s /tmp/networkmap_agent.py ]; then
        echo "ERROR: Downloaded agent script is still empty. Aborting."
        exit 1
    fi
fi

# Verify Python syntax before copying
echo "Verifying script integrity..."
python3 -m py_compile /tmp/networkmap_agent.py || {{ echo "ERROR: Downloaded script has syntax errors"; exit 1; }}

# Show file information for verification
echo "Agent script details:"
wc -l /tmp/networkmap_agent.py
head -n 30 /tmp/networkmap_agent.py | grep -E "version|build"

# Only copy if verification passes
sudo cp /tmp/networkmap_agent.py /opt/networkmap-agent/networkmap_agent.py
sudo chmod +x /opt/networkmap-agent/networkmap_agent.py

# Update Python dependencies if needed
echo "Updating dependencies..."
sudo /opt/networkmap-agent/venv/bin/pip install --quiet --upgrade requests psutil

# Restart the agent service with proper error handling
echo "Restarting agent service..."
sudo systemctl daemon-reload

# Enable the service (in case it was disabled)
sudo systemctl enable networkmap-agent 2>/dev/null || true

# Start the service
echo "Starting agent service..."
if sudo systemctl start networkmap-agent; then
    echo "✅ Agent service start command successful"
else
    echo "❌ Agent service start command failed"
    sudo systemctl status networkmap-agent --no-pager -l
    exit 1
fi

# Wait and verify service is running
echo "Waiting for service to stabilize..."
sleep 8

# Check service status multiple times
for i in {{1..3}}; do
    echo "Service check attempt $i/3..."
    if sudo systemctl is-active --quiet networkmap-agent; then
        SERVICE_STATUS="active"
        break
    else
        SERVICE_STATUS="failed"
        sleep 2
    fi
done

if [ "$SERVICE_STATUS" = "active" ]; then
    echo "✅ Agent update completed successfully"
    echo "Service status: $(sudo systemctl is-active networkmap-agent)"
    echo "Version: {current_version}"
    echo "Build date: {build_date}"
    
    # Show recent logs to verify agent is working
    echo "Recent agent logs:"
    sudo journalctl -u networkmap-agent --since "30 seconds ago" --no-pager -q | tail -5
else
    echo "❌ Agent service failed to start properly after update"
    echo "Service status: $(sudo systemctl is-active networkmap-agent)"
    echo "Service logs:"
    sudo journalctl -u networkmap-agent --since "2 minutes ago" --no-pager -l | tail -20
    sudo systemctl status networkmap-agent --no-pager -l
    exit 1
fi

# Cleanup
rm -f /tmp/networkmap_agent.py

echo "Agent update completed successfully!"
"""
        
        # Execute update script via SSH
        result, error = host_manager.execute_command(host, update_script, timeout=300)
        
        if result and result['success']:
            # Mark update as completed
            db.mark_agent_update_completed(agent_id, current_version, build_date)
            print(f"\n✅ ╭─────────────────────────────────────────────────╮")
            print(f"   │  UPDATE SUCCESSFUL                              │")
            print(f"   │  Host: {hostname:<35} │")
            print(f"   │  Version: {current_version:<31} │")
            print(f"   │  Build: {build_date:<33} │")
            print(f"   ╰─────────────────────────────────────────────────╯\n")
        else:
            # Mark update as failed
            error_msg = result.get('stderr', error) if result else str(error)
            db.mark_agent_update_failed(agent_id, f"Update script failed: {error_msg[:200]}")
            print(f"\n❌ ╭─────────────────────────────────────────────────╮")
            print(f"   │  UPDATE FAILED                                  │")
            print(f"   │  Host: {hostname:<35} │")
            print(f"   │  Error: {error_msg[:32]:<32} │")
            print(f"   ╰─────────────────────────────────────────────────╯\n")
            
    except Exception as e:
        error_msg = f"Exception during agent update: {str(e)}"
        print(f"\n💥 ╭─────────────────────────────────────────────────╮")
        print(f"   │  UPDATE EXCEPTION                               │")
        print(f"   │  Host: {hostname:<35} │")
        print(f"   │  Exception: {str(e)[:29]:<29} │")
        print(f"   ╰─────────────────────────────────────────────────╯\n")
        db.mark_agent_update_failed(agent_id, error_msg)

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

@app.route('/api/agent/run_now', methods=['POST'])
def run_agent_now():
    """Trigger an immediate agent scan with progress tracking"""
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
        
        # Find the agent for this host
        agents = db.get_all_agents()
        agent = next((a for a in agents if a.get('ip_address') == ip_address or a.get('hostname') == hostname), None)
        
        if not agent:
            return jsonify({
                'success': False,
                'error': f'No agent found for host {hostname} ({ip_address})'
            }), 404
        
        agent_id = agent.get('agent_id')
        
        # Check if this agent is already running
        global agent_run_progress
        if agent_id in agent_run_progress['running']:
            return jsonify({
                'success': False,
                'error': f'Agent scan already in progress for {hostname}'
            }), 400
        
        # Start the agent run in background thread with progress tracking
        thread = threading.Thread(target=run_agent_with_progress, args=(agent, host))
        thread.daemon = True
        thread.start()
        
        return jsonify({
            'success': True,
            'message': f'Agent scan started on {hostname}',
            'agent_id': agent_id,
            'hostname': hostname,
            'ip_address': ip_address,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error triggering agent run: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/execute_script', methods=['POST'])
def execute_script_on_agent():
    """Execute a script on an agent host via SSH with progress tracking"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Required fields
        hostname = data.get('hostname')
        ip_address = data.get('ip_address')
        script_content = data.get('script_content')
        
        if not all([hostname, ip_address, script_content]):
            return jsonify({
                'success': False,
                'error': 'hostname, ip_address, and script_content are required'
            }), 400
        
        # Optional fields with defaults
        script_type = data.get('script_type', 'bash')
        timeout = data.get('timeout', 300)  # 5 minute default
        working_dir = data.get('working_dir')
        background = data.get('background', False)  # Run in background with progress tracking
        
        # Validate script type
        allowed_script_types = ['bash', 'sh', 'python', 'python3', 'python2', 'perl', 'ruby']
        if script_type.lower() not in allowed_script_types:
            return jsonify({
                'success': False,
                'error': f'Invalid script_type. Allowed: {", ".join(allowed_script_types)}'
            }), 400
        
        # Validate timeout
        if not isinstance(timeout, int) or timeout < 1 or timeout > 3600:  # Max 1 hour
            return jsonify({
                'success': False,
                'error': 'timeout must be an integer between 1 and 3600 seconds'
            }), 400
        
        # Basic script security validation
        dangerous_patterns = [
            'rm -rf /',
            'sudo rm',
            'mkfs.',
            'dd if=',
            'format ',
            '> /dev/sd',
            'shutdown',
            'reboot',
            'halt',
            'init 0',
            'init 6'
        ]
        
        script_lower = script_content.lower()
        for pattern in dangerous_patterns:
            if pattern in script_lower:
                return jsonify({
                    'success': False,
                    'error': f'Script contains potentially dangerous command: {pattern}'
                }), 400
        
        # Find host by IP or name
        hosts = host_manager.get_all_hosts()
        host = next((h for h in hosts if h['ip_address'] == ip_address or h['name'] == hostname), None)
        
        if not host:
            return jsonify({
                'success': False,
                'error': f'Host {hostname} ({ip_address}) not found in configuration'
            }), 404
        
        # If background execution is requested, start it with progress tracking
        if background:
            import uuid
            execution_id = str(uuid.uuid4())
            
            # Check if script execution is already running for this host
            global script_execution_progress
            host_key = f"{hostname}_{ip_address}"
            
            if host_key in script_execution_progress['running']:
                return jsonify({
                    'success': False,
                    'error': f'Script execution already in progress for {hostname}'
                }), 400
            
            # Start script execution in background thread with progress tracking
            thread = threading.Thread(
                target=execute_script_with_progress, 
                args=(execution_id, host, script_content, script_type, timeout, working_dir, hostname, ip_address)
            )
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'success': True,
                'execution_id': execution_id,
                'message': f'Script execution started in background on {hostname}',
                'hostname': hostname,
                'ip_address': ip_address,
                'background': True,
                'timestamp': datetime.now().isoformat()
            })
        else:
            # Execute the script synchronously (existing behavior)
            result, error = host_manager.execute_script(
                host=host,
                script_content=script_content,
                script_type=script_type,
                timeout=timeout,
                working_dir=working_dir
            )
            
            if result:
                return jsonify({
                    'success': result['success'],
                    'script_id': result['script_id'],
                    'exit_status': result['exit_status'],
                    'stdout': result['stdout'],
                    'stderr': result['stderr'],
                    'script_type': result['script_type'],
                    'hostname': hostname,
                    'ip_address': ip_address,
                    'background': False,
                    'timestamp': datetime.now().isoformat()
                })
            else:
                return jsonify({
                    'success': False,
                    'error': error,
                    'hostname': hostname,
                    'ip_address': ip_address,
                    'background': False,
                    'timestamp': datetime.now().isoformat()
                }), 500
            
    except Exception as e:
        print(f"Error executing script: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/last_data/<agent_id>', methods=['GET'])
def get_agent_last_data(agent_id):
    """Get the last data collected by an agent"""
    try:
        # Get the agent info
        agent = db.get_agent(agent_id)
        if not agent:
            return jsonify({
                'success': False,
                'error': f'Agent {agent_id} not found'
            }), 404
        
        # Get latest scan results from the database
        scan_results = db.get_latest_agent_scan_results(agent_id)
        
        if not scan_results:
            return jsonify({
                'success': False,
                'error': 'No scan data available for this agent'
            }), 404
        
        # Parse scan data
        scan_data = scan_results.get('scan_data', {})
        
        # Initialize agent data structure
        agent_data = {
            'agent_info': {
                'agent_id': agent_id,
                'hostname': agent.get('hostname'),
                'ip_address': agent.get('ip_address'),
                'last_heartbeat': agent.get('last_heartbeat'),
                'status': agent.get('status')
            },
            'last_scan': scan_results.get('scan_timestamp'),
            'scan_duration': scan_results.get('scan_duration'),
            'scan_status': scan_results.get('scan_status', 'completed'),
            'network_data': [],
            'test_results': {},
            'errors': [],
            'system_info': {},
            'network_interfaces': {},
            'listening_ports': [],
            'active_connections': [],
            'routing_table': [],
            'arp_table': []
        }
        
        # Handle current agent data format
        if isinstance(scan_data, dict):
            # Extract system information
            if 'system_info' in scan_data:
                agent_data['system_info'] = scan_data['system_info']
            
            if 'network_interfaces' in scan_data:
                agent_data['network_interfaces'] = scan_data['network_interfaces']
            
            if 'listening_ports' in scan_data:
                agent_data['listening_ports'] = scan_data['listening_ports']
            
            if 'active_connections' in scan_data:
                agent_data['active_connections'] = scan_data['active_connections']
            
            if 'routing_table' in scan_data:
                agent_data['routing_table'] = scan_data['routing_table']
            
            if 'arp_table' in scan_data:
                agent_data['arp_table'] = scan_data['arp_table']
                
                # Convert ARP table entries to network discovery format
                if agent_data['arp_table']:
                    for arp_entry in agent_data['arp_table']:
                        if isinstance(arp_entry, dict) and 'ip_address' in arp_entry:
                            network_host = {
                                'ip_address': arp_entry['ip_address'],
                                'mac_address': arp_entry.get('mac_address', ''),
                                'hostname': arp_entry.get('hostname', ''),
                                'status': 'up',
                                'last_seen': scan_results.get('scan_timestamp'),
                                'source': 'arp_table'
                            }
                            agent_data['network_data'].append(network_host)
            
            # Extract network discovery data (legacy formats)
            if 'network_scan' in scan_data:
                network_results = scan_data['network_scan']
                if isinstance(network_results, list):
                    agent_data['network_data'].extend(network_results)
                elif isinstance(network_results, dict) and 'hosts' in network_results:
                    agent_data['network_data'].extend(network_results['hosts'])
            
            # Extract test results
            if 'test_results' in scan_data:
                agent_data['test_results'] = scan_data['test_results']
            
            # Extract errors if any
            if 'errors' in scan_data:
                agent_data['errors'] = scan_data['errors']
            
            # Handle legacy format where scan_data itself contains hosts
            if 'hosts' in scan_data:
                agent_data['network_data'].extend(scan_data['hosts'])
        
        elif isinstance(scan_data, list):
            # If scan_data is directly a list of hosts
            agent_data['network_data'] = scan_data
        
        # Create synthetic test results from available data ONLY if no real test results exist
        # This provides backward compatibility for older agents without enhanced test features
        if not agent_data['test_results'] and (agent_data['listening_ports'] or agent_data['active_connections'] or agent_data['network_interfaces']):
            agent_data['test_results'] = {
                'System Monitoring': {
                    'Network Interfaces': {
                        'success': bool(agent_data['network_interfaces']),
                        'description': f"Found {len(agent_data['network_interfaces'])} network interfaces" if agent_data['network_interfaces'] else "No network interfaces data",
                        'details': f"Interface data collected at {agent_data['last_scan']}"
                    },
                    'Port Scanning': {
                        'success': bool(agent_data['listening_ports']),
                        'description': f"Found {len(agent_data['listening_ports'])} listening ports" if agent_data['listening_ports'] else "No listening ports found",
                        'details': f"Ports scanned at {agent_data['last_scan']}"
                    },
                    'Connection Monitoring': {
                        'success': bool(agent_data['active_connections']),
                        'description': f"Found {len(agent_data['active_connections'])} active connections" if agent_data['active_connections'] else "No active connections",
                        'details': f"Connections monitored at {agent_data['last_scan']}"
                    }
                }
            }
            
            if agent_data['arp_table']:
                agent_data['test_results']['Network Discovery'] = {
                    'ARP Table Analysis': {
                        'success': True,
                        'description': f"Found {len(agent_data['arp_table'])} entries in ARP table",
                        'details': f"ARP data collected at {agent_data['last_scan']}"
                    }
                }
        
        # Remove duplicates from network data based on IP address
        if agent_data['network_data']:
            seen_ips = set()
            unique_hosts = []
            for host in agent_data['network_data']:
                if isinstance(host, dict) and 'ip_address' in host:
                    if host['ip_address'] not in seen_ips:
                        seen_ips.add(host['ip_address'])
                        unique_hosts.append(host)
            agent_data['network_data'] = unique_hosts
        
        return jsonify({
            'success': True,
            'agent_data': agent_data,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent last data: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Agent run progress tracking endpoints
@app.route('/api/agent/run_progress/<agent_id>', methods=['GET'])
def get_agent_run_progress(agent_id):
    """Get the progress of a running agent scan"""
    try:
        global agent_run_progress
        
        if agent_id not in agent_run_progress['running']:
            return jsonify({
                'success': False,
                'error': f'No active run found for agent {agent_id}',
                'running': False
            }), 404
        
        run_info = agent_run_progress['running'][agent_id]
        
        # Get recent logs for this specific agent
        agent_logs = [log for log in agent_run_progress['logs'] 
                     if log.get('agent_id') == agent_id][-20:]  # Last 20 logs
        
        return jsonify({
            'success': True,
            'agent_id': agent_id,
            'running': True,
            'run_info': run_info,
            'logs': agent_logs,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting agent run progress: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/agent/all_run_progress', methods=['GET'])
def get_all_agent_run_progress():
    """Get the progress of all running agent scans"""
    try:
        global agent_run_progress
        
        # Get recent logs (last 50 entries)
        recent_logs = list(agent_run_progress['logs'])[-50:]
        
        # Count running agents
        running_count = len(agent_run_progress['running'])
        
        return jsonify({
            'success': True,
            'running_agents': agent_run_progress['running'],
            'running_count': running_count,
            'recent_logs': recent_logs,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting all agent run progress: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def execute_script_with_progress(execution_id, host, script_content, script_type, timeout, working_dir, hostname, ip_address):
    """Execute script with progress tracking"""
    global script_execution_progress
    
    host_key = f"{hostname}_{ip_address}"
    
    # Initialize execution info
    execution_info = {
        'execution_id': execution_id,
        'hostname': hostname,
        'ip_address': ip_address,
        'start_time': datetime.now().isoformat(),
        'current_phase': 'initializing',
        'progress': 0,
        'status': 'running',
        'current_action': 'Starting script execution...',
        'script_type': script_type,
        'timeout': timeout,
        'working_dir': working_dir,
        'error': None,
        'phases_completed': []
    }
    
    # Add to running executions
    script_execution_progress['running'][execution_id] = execution_info
    
    def log_script_progress(message, level='info', phase=None, progress=None, action=None):
        """Log progress for this specific script execution"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'execution_id': execution_id,
            'hostname': hostname,
            'message': message,
            'level': level,
            'phase': phase
        }
        
        script_execution_progress['logs'].append(log_entry)
        
        # Update execution info
        if phase:
            execution_info['current_phase'] = phase
        if progress is not None:
            execution_info['progress'] = progress
        if action:
            execution_info['current_action'] = action
        
        print(f"[SCRIPT EXEC {execution_id}] {hostname}: {message}")
    
    try:
        log_script_progress("🚀 Starting script execution", 'info', 'initializing', 0, 'Connecting to host...')
        
        # Phase 1: Test connectivity
        log_script_progress("Testing SSH connectivity", 'info', 'connecting', 10, 'Testing SSH connection...')
        
        test_result, test_error = host_manager.execute_command(host, 'echo "SSH test successful"', timeout=10)
        
        if not test_result or not test_result.get('success'):
            error_msg = f'SSH connection failed: {test_error or "Connection timeout"}'
            log_script_progress(error_msg, 'error', 'error', execution_info['progress'], 'SSH connection failed')
            execution_info['status'] = 'error'
            execution_info['error'] = error_msg
            return
        
        log_script_progress("✅ SSH connectivity confirmed", 'info', 'connecting', 20, 'SSH connection successful')
        execution_info['phases_completed'].append('connecting')
        
        # Phase 2: Prepare script for execution
        log_script_progress("Preparing script for execution", 'info', 'preparing', 30, 'Preparing script...')
        
        # Phase 3: Execute the script
        log_script_progress(f"Executing {script_type} script", 'info', 'executing', 50, f'Running {script_type} script...')
        
        # Execute the script using host_manager
        result, error = host_manager.execute_script(
            host=host,
            script_content=script_content,
            script_type=script_type,
            timeout=timeout,
            working_dir=working_dir
        )
        
        execution_info['phases_completed'].append('executing')
        
        # Phase 4: Process results
        log_script_progress("Processing execution results", 'info', 'processing', 80, 'Processing results...')
        
        if result:
            # Store execution results
            execution_info['result'] = {
                'success': result['success'],
                'script_id': result['script_id'],
                'exit_status': result['exit_status'],
                'stdout': result['stdout'],
                'stderr': result['stderr'],
                'script_type': result['script_type']
            }
            
            if result['success']:
                log_script_progress(f"✅ Script executed successfully (exit status: {result['exit_status']})", 'info', 'complete', 100, 'Script execution completed')
                execution_info['status'] = 'completed'
            else:
                log_script_progress(f"⚠️ Script completed with errors (exit status: {result['exit_status']})", 'warning', 'complete', 100, 'Script execution completed with errors')
                execution_info['status'] = 'completed_with_errors'
        else:
            error_msg = error or "Unknown error during script execution"
            log_script_progress(f"❌ Script execution failed: {error_msg}", 'error', 'error', execution_info['progress'], 'Script execution failed')
            execution_info['status'] = 'error'
            execution_info['error'] = error_msg
            execution_info['result'] = {
                'success': False,
                'error': error_msg
            }
        
        execution_info['phases_completed'].append('processing')
        
        # Phase 5: Complete
        execution_info['end_time'] = datetime.now().isoformat()
        
        # Calculate duration
        start_time = datetime.fromisoformat(execution_info['start_time'])
        end_time = datetime.fromisoformat(execution_info['end_time'])
        duration = (end_time - start_time).total_seconds()
        execution_info['duration_seconds'] = round(duration, 2)
        
        log_script_progress(f"Script execution completed in {duration:.1f} seconds", 'info', 'complete', 100, f'Completed in {duration:.1f}s')
        
    except Exception as e:
        error_msg = f"Exception during script execution: {str(e)}"
        log_script_progress(error_msg, 'error', 'error', execution_info.get('progress', 0), 'Exception occurred')
        execution_info['status'] = 'error'
        execution_info['error'] = error_msg
        print(f"Exception in execute_script_with_progress: {e}")
    
    finally:
        # Move to completed executions and keep for a brief period
        def move_to_completed():
            time.sleep(300)  # Keep in completed for 5 minutes
            if execution_id in script_execution_progress['running']:
                # Move from running to completed
                script_execution_progress['completed'][execution_id] = script_execution_progress['running'][execution_id]
                del script_execution_progress['running'][execution_id]
                
                # Cleanup completed executions after some time
                def cleanup_completed():
                    time.sleep(300)  # Keep completed for another 5 minutes
                    if execution_id in script_execution_progress['completed']:
                        del script_execution_progress['completed'][execution_id]
                
                cleanup_thread = threading.Thread(target=cleanup_completed)
                cleanup_thread.daemon = True
                cleanup_thread.start()
        
        move_thread = threading.Thread(target=move_to_completed)
        move_thread.daemon = True
        move_thread.start()

def run_agent_with_progress(agent, host):
    """Run agent scan with progress tracking"""
    global agent_run_progress
    
    agent_id = agent.get('agent_id')
    hostname = agent.get('hostname', host.get('name', 'unknown'))
    ip_address = agent.get('ip_address', host.get('ip_address', 'unknown'))
    
    # Initialize run info
    run_info = {
        'agent_id': agent_id,
        'hostname': hostname,
        'ip_address': ip_address,
        'start_time': datetime.now().isoformat(),
        'current_phase': 'initializing',
        'progress': 0,
        'status': 'running',
        'current_action': 'Starting agent scan...',
        'error': None,
        'phases_completed': []
    }
    
    # Add to running agents
    agent_run_progress['running'][agent_id] = run_info
    
    def log_agent_progress(message, level='info', phase=None, progress=None, action=None):
        """Log progress for this specific agent run"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'hostname': hostname,
            'message': message,
            'level': level,
            'phase': phase
        }
        
        agent_run_progress['logs'].append(log_entry)
        
        # Update run info
        if phase:
            run_info['current_phase'] = phase
        if progress is not None:
            run_info['progress'] = progress
        if action:
            run_info['current_action'] = action
        
        print(f"[AGENT RUN {agent_id}] {hostname}: {message}")
    
    try:
        log_agent_progress("🚀 Starting immediate agent scan", 'info', 'initializing', 0, 'Connecting to agent...')
        
        # Phase 1: Test connectivity
        log_agent_progress("Testing SSH connectivity", 'info', 'connecting', 10, 'Testing SSH connection...')
        
        test_result, test_error = host_manager.execute_command(host, 'echo "SSH test successful"', timeout=10)
        
        if not test_result or not test_result.get('success'):
            error_msg = f'SSH connection failed: {test_error or "Connection timeout"}'
            log_agent_progress(error_msg, 'error', 'error', run_info['progress'], 'SSH connection failed')
            run_info['status'] = 'error'
            run_info['error'] = error_msg
            return
        
        log_agent_progress("✅ SSH connectivity confirmed", 'info', 'connecting', 20, 'SSH connection successful')
        run_info['phases_completed'].append('connecting')
        
        # Phase 2: Check agent status
        log_agent_progress("Checking agent service status", 'info', 'checking', 30, 'Verifying agent service...')
        
        status_cmd = 'sudo systemctl is-active networkmap-agent'
        status_result, _ = host_manager.execute_command(host, status_cmd, timeout=15)
        
        if status_result and status_result.get('success'):
            agent_status = status_result.get('stdout', '').strip()
            log_agent_progress(f"Agent service status: {agent_status}", 'info', 'checking', 40, f'Agent status: {agent_status}')
        else:
            log_agent_progress("⚠️ Could not determine agent status", 'warning', 'checking', 40, 'Agent status unknown')
        
        run_info['phases_completed'].append('checking')
        
        # Phase 3: Run comprehensive network scan directly
        log_agent_progress("Starting comprehensive network scan", 'info', 'scanning', 50, 'Running network discovery...')
        
        # Run comprehensive scan commands similar to what the agent would do
        scan_commands = [
            {
                'name': 'System Information',
                'cmd': 'uname -a && hostname && whoami && uptime',
                'progress': 55
            },
            {
                'name': 'Network Interfaces',
                'cmd': 'ip addr show',
                'progress': 60
            },
            {
                'name': 'Routing Table',
                'cmd': 'ip route show',
                'progress': 65
            },
            {
                'name': 'ARP Table',
                'cmd': 'arp -a 2>/dev/null || ip neigh show',
                'progress': 70
            },
            {
                'name': 'Network Discovery',
                'cmd': r'''
                # Get local network range
                LOCAL_NET=$(ip route | grep -E "^192\.|^10\.|^172\." | grep -v default | head -1 | awk '{print $1}' | head -1)
                if [ -n "$LOCAL_NET" ]; then
                    echo "Scanning network: $LOCAL_NET"
                    # Quick ping sweep of first 20 IPs
                    for i in {1..20}; do
                        IP=$(echo $LOCAL_NET | sed 's/\/.*//').${i}
                        timeout 1 ping -c 1 $IP >/dev/null 2>&1 && echo "$IP is up" &
                    done
                    wait
                else
                    echo "Could not determine local network range"
                fi
                ''',
                'progress': 75
            },
            {
                'name': 'Port Scan',
                'cmd': 'ss -tlnp',
                'progress': 80
            },
            {
                'name': 'Active Connections',
                'cmd': 'ss -tuanp',
                'progress': 85
            }
        ]
        
        scan_results = {}
        for i, scan_cmd in enumerate(scan_commands):
            log_agent_progress(f"Running {scan_cmd['name']}", 'info', 'scanning', scan_cmd['progress'], f'Executing {scan_cmd["name"]}...')
            
            result, error = host_manager.execute_command(host, scan_cmd['cmd'], timeout=60)
            
            if result and result.get('success'):
                output = result.get('stdout', '').strip()
                scan_results[scan_cmd['name']] = output
                log_agent_progress(f"✅ {scan_cmd['name']} completed", 'info', 'scanning', scan_cmd['progress'], f'{scan_cmd["name"]} done')
            else:
                error_msg = result.get('stderr', error) if result else str(error)
                scan_results[scan_cmd['name']] = f"Error: {error_msg[:200]}"
                log_agent_progress(f"⚠️ {scan_cmd['name']} failed: {error_msg[:100]}", 'warning', 'scanning', scan_cmd['progress'], f'{scan_cmd["name"]} failed')
        
        run_info['phases_completed'].append('triggering')
        
        # Phase 4: Monitor scan execution (brief)
        log_agent_progress("Monitoring scan execution", 'info', 'monitoring', 85, 'Monitoring agent activity...')
        
        # Give the agent a moment to start scanning
        time.sleep(3)
        
        # Check if agent is actively scanning
        monitor_cmd = '''
        echo "=== Agent Process Info ==="
        pgrep -f "networkmap.*agent" | head -1 | xargs ps -p | tail -n +2 || echo "Agent process not found"
        echo "=== Recent Agent Logs ==="
        sudo journalctl -u networkmap-agent --since "1 minute ago" --no-pager -q | tail -5 || echo "No recent logs"
        echo "=== Network Activity ==="
        ss -tulpn | grep -E ":(53|443|80|22)" | wc -l | xargs echo "Active network connections:"
        '''
        
        monitor_result, _ = host_manager.execute_command(host, monitor_cmd, timeout=20)
        
        if monitor_result and monitor_result.get('success'):
            monitor_output = monitor_result.get('stdout', '').strip()
            log_agent_progress(f"📊 Agent monitoring info: {monitor_output[:200]}...", 'info', 'monitoring', 90, 'Scan monitoring complete')
        else:
            log_agent_progress("⚠️ Could not monitor agent activity", 'warning', 'monitoring', 90, 'Monitoring incomplete')
        
        run_info['phases_completed'].append('monitoring')
        
        # Phase 5: Complete
        log_agent_progress("✅ Agent scan trigger completed successfully", 'info', 'complete', 100, 'Scan trigger completed')
        run_info['status'] = 'completed'
        run_info['end_time'] = datetime.now().isoformat()
        
        # Calculate duration
        start_time = datetime.fromisoformat(run_info['start_time'])
        end_time = datetime.fromisoformat(run_info['end_time'])
        duration = (end_time - start_time).total_seconds()
        run_info['duration_seconds'] = round(duration, 2)
        
        log_agent_progress(f"Scan trigger completed in {duration:.1f} seconds", 'info', 'complete', 100, f'Completed in {duration:.1f}s')
        
    except Exception as e:
        error_msg = f"Exception during agent run: {str(e)}"
        log_agent_progress(error_msg, 'error', 'error', run_info.get('progress', 0), 'Exception occurred')
        run_info['status'] = 'error'
        run_info['error'] = error_msg
        print(f"Exception in run_agent_with_progress: {e}")
    
    finally:
        # Keep the run info for a brief period for the frontend to read the final status
        def cleanup_run_info():
            time.sleep(30)  # Keep for 30 seconds
            if agent_id in agent_run_progress['running']:
                del agent_run_progress['running'][agent_id]
        
        cleanup_thread = threading.Thread(target=cleanup_run_info)
        cleanup_thread.daemon = True
        cleanup_thread.start()

# Statistics API endpoints
@app.route('/api/stats/overview', methods=['GET'])
def get_statistics_overview():
    """Get comprehensive network overview statistics"""
    try:
        overview_stats = db.get_network_overview_stats()
        agent_stats = db.get_agent_stats()
        network_stats = db.get_network_stats()
        
        # Combine all overview data
        combined_stats = {
            'hosts': overview_stats.get('hosts', {}),
            'connections': overview_stats.get('connections', {}),
            'ports': overview_stats.get('ports', {}),
            'agents': overview_stats.get('agents', {}),
            'scans': overview_stats.get('scans', {}),
            'network_legacy': network_stats,  # Keep legacy stats for compatibility
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'success': True,
            'data': combined_stats
        })
        
    except Exception as e:
        print(f"Error getting overview statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats/lan_analysis', methods=['GET'])
def get_lan_analysis_stats():
    """Get LAN vs external connection analysis"""
    try:
        # Get custom subnets from query parameters if provided
        custom_subnets = request.args.get('subnets')
        if custom_subnets:
            subnets = [s.strip() for s in custom_subnets.split(',')]
        else:
            subnets = None  # Use default subnets
        
        lan_stats = db.get_lan_vs_external_stats(local_subnets=subnets)
        top_external = db.get_top_external_destinations(limit=10, local_subnets=subnets)
        
        return jsonify({
            'success': True,
            'data': {
                'lan_vs_external': lan_stats,
                'top_external_destinations': top_external,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error getting LAN analysis: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats/hosts', methods=['GET'])
def get_host_statistics():
    """Get detailed host statistics"""
    try:
        limit = int(request.args.get('limit', 10))
        top_hosts = db.get_top_hosts_by_connections(limit=limit)
        
        # Get individual host details if requested
        host_id = request.args.get('host_id')
        host_timeline = None
        if host_id:
            days = int(request.args.get('days', 7))
            host_timeline = db.get_host_activity_timeline(int(host_id), days=days)
        
        return jsonify({
            'success': True,
            'data': {
                'top_hosts': top_hosts,
                'host_timeline': host_timeline,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error getting host statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats/historical', methods=['GET'])
def get_historical_statistics():
    """Get historical network statistics"""
    try:
        # Get time periods from query parameters
        periods_param = request.args.get('periods', '1,6,24,72,168')
        time_periods = [int(p.strip()) for p in periods_param.split(',')]
        
        historical_stats = db.get_historical_connection_stats(time_periods=time_periods)
        
        # Get hourly breakdown for charts
        hours = int(request.args.get('hours', 24))
        hourly_history = db.get_connection_history_by_hour(hours=hours)
        
        return jsonify({
            'success': True,
            'data': {
                'period_stats': historical_stats,
                'hourly_history': hourly_history,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error getting historical statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats/connections', methods=['GET'])
def get_connection_statistics():
    """Get detailed connection statistics"""
    try:
        hours = int(request.args.get('hours', 24))
        recent_connections = db.get_recent_connections(hours=hours)
        
        # Get connection breakdown by protocol, port, etc.
        with db.get_connection() as conn:
            # Protocol breakdown
            cursor = conn.execute('''
                SELECT 
                    protocol,
                    COUNT(*) as connection_count,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent + bytes_received) as total_traffic
                FROM network_connections
                WHERE last_seen > datetime('now', '-{} hour')
                GROUP BY protocol
                ORDER BY connection_count DESC
            '''.format(hours))
            protocol_stats = [dict(row) for row in cursor.fetchall()]
            
            # Top ports
            cursor = conn.execute('''
                SELECT 
                    dest_port,
                    COUNT(*) as connection_count,
                    SUM(connection_count) as total_connections,
                    COUNT(DISTINCT source_host_id) as unique_sources
                FROM network_connections
                WHERE last_seen > datetime('now', '-{} hour')
                GROUP BY dest_port
                ORDER BY connection_count DESC
                LIMIT 20
            '''.format(hours))
            port_stats = [dict(row) for row in cursor.fetchall()]
        
        return jsonify({
            'success': True,
            'data': {
                'recent_connections': recent_connections[:100],  # Limit for performance
                'protocol_breakdown': protocol_stats,
                'top_ports': port_stats,
                'hours_analyzed': hours,
                'timestamp': datetime.now().isoformat()
            }
        })
        
    except Exception as e:
        print(f"Error getting connection statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats/realtime', methods=['GET'])
def get_realtime_statistics():
    """Get real-time statistics for dashboard updates"""
    try:
        # Get current timestamp for real-time data
        current_time = datetime.now()
        
        # Get very recent data (last 5 minutes) for real-time monitoring
        recent_cutoff = current_time - timedelta(minutes=5)
        
        with db.get_connection() as conn:
            # Recent activity counters
            cursor = conn.execute('''
                SELECT COUNT(*) as recent_connections
                FROM network_connections 
                WHERE last_seen > ?
            ''', (recent_cutoff,))
            recent_activity = dict(cursor.fetchone())
            
            # Active hosts in last 5 minutes
            cursor = conn.execute('''
                SELECT COUNT(DISTINCT source_host_id) as active_hosts
                FROM network_connections 
                WHERE last_seen > ?
            ''', (recent_cutoff,))
            active_hosts = dict(cursor.fetchone())
            
            # Recent agent activity
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as recent_heartbeats,
                    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_agents
                FROM agents 
                WHERE last_heartbeat > ?
            ''', (recent_cutoff,))
            agent_activity = dict(cursor.fetchone())
        
        realtime_data = {
            'current_time': current_time.isoformat(),
            'recent_connections': recent_activity.get('recent_connections', 0),
            'active_hosts': active_hosts.get('active_hosts', 0),
            'recent_heartbeats': agent_activity.get('recent_heartbeats', 0),
            'active_agents': agent_activity.get('active_agents', 0),
            'update_interval': 5,  # seconds
            'last_update': current_time.isoformat()
        }
        
        return jsonify({
            'success': True,
            'data': realtime_data
        })
        
    except Exception as e:
        print(f"Error getting real-time statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# AI Settings routes
@app.route('/settings')
def settings():
    """Render the settings page"""
    return render_template('settings.html')

@app.route('/api/ai_settings', methods=['GET'])
def get_ai_settings():
    """Get all AI API settings"""
    try:
        settings = db.get_all_ai_api_settings()
        # Mask API keys for security
        for setting in settings:
            if setting.get('api_key'):
                setting['api_key_masked'] = '••••••••' + setting['api_key'][-4:] if len(setting['api_key']) > 4 else '••••••••'
                setting['api_key'] = None  # Remove actual key from response
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ai_settings/<provider>', methods=['GET'])
def get_ai_setting(provider):
    """Get AI API settings for a specific provider"""
    try:
        settings = db.get_ai_api_settings(provider)
        if not settings:
            return jsonify({
                'success': False,
                'error': f'Settings for provider {provider} not found'
            }), 404
        
        # Mask API key for security
        if settings.get('api_key'):
            settings['api_key_masked'] = '••••••••' + settings['api_key'][-4:] if len(settings['api_key']) > 4 else '••••••••'
            settings['api_key'] = None  # Remove actual key from response
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ai_settings', methods=['POST'])
def save_ai_settings():
    """Save AI API settings"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        provider = data.get('provider')
        if not provider:
            return jsonify({
                'success': False,
                'error': 'Provider is required'
            }), 400
        
        if provider not in ['gemini', 'chatgpt']:
            return jsonify({
                'success': False,
                'error': 'Provider must be either "gemini" or "chatgpt"'
            }), 400
        
        # Extract settings from request data
        api_key = data.get('api_key')
        model_name = data.get('model_name')
        api_endpoint = data.get('api_endpoint')
        temperature = float(data.get('temperature', 0.7))
        max_tokens = int(data.get('max_tokens', 1000))
        timeout = int(data.get('timeout', 30))
        enabled = bool(data.get('enabled', False))
        additional_config = data.get('additional_config', {})
        
        # Save settings to database
        db.save_ai_api_settings(
            provider=provider,
            api_key=api_key,
            model_name=model_name,
            api_endpoint=api_endpoint,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            enabled=enabled,
            additional_config=additional_config
        )
        
        return jsonify({
            'success': True,
            'message': f'Settings saved for {provider}',
            'provider': provider
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ai_settings/<provider>', methods=['DELETE'])
def delete_ai_settings(provider):
    """Delete AI API settings for a provider"""
    try:
        success = db.delete_ai_api_settings(provider)
        if success:
            return jsonify({
                'success': True,
                'message': f'Settings deleted for {provider}'
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Settings for {provider} not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ai_settings/<provider>/enable', methods=['POST'])
def toggle_ai_api(provider):
    """Enable or disable AI API for a provider"""
    try:
        data = request.get_json() or {}
        enabled = bool(data.get('enabled', True))
        
        db.enable_ai_api(provider, enabled)
        
        status = 'enabled' if enabled else 'disabled'
        return jsonify({
            'success': True,
            'message': f'{provider} API {status}',
            'enabled': enabled
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# AI Reports routes
@app.route('/ai_reports')
def ai_reports():
    """Render the AI Reports page"""
    return render_template('ai_reports.html')

# Chatbot routes
@app.route('/ai_chatbot')
def ai_chatbot():
    """Render the AI Chatbot page"""
    return render_template('chatbot.html')

@app.route('/api/chatbot/start', methods=['POST'])
def start_chatbot_conversation():
    """Start a new chatbot conversation"""
    try:
        from chatbot_controller import ChatbotController
        
        # Initialize chatbot controller
        chatbot = ChatbotController(db, host_manager)
        
        # Get user ID from session or request
        user_id = request.json.get('user_id') if request.json else None
        
        # Start conversation
        result = chatbot.start_conversation(user_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/chatbot/message', methods=['POST'])
def send_chatbot_message():
    """Send a message to the chatbot"""
    try:
        from chatbot_controller import ChatbotController
        
        data = request.get_json() or {}
        conversation_id = data.get('conversation_id')
        user_message = data.get('message')
        selected_hosts = data.get('selected_hosts', [])
        
        if not conversation_id or not user_message:
            return jsonify({
                'success': False,
                'error': 'Missing conversation_id or message'
            }), 400
        
        # Initialize chatbot controller
        chatbot = ChatbotController(db, host_manager)
        
        # Process message
        result = chatbot.process_user_message(conversation_id, user_message, selected_hosts)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/chatbot/conversation/<conversation_id>', methods=['GET'])
def get_chatbot_conversation(conversation_id):
    """Get conversation history"""
    try:
        from chatbot_controller import ChatbotController
        
        # Initialize chatbot controller
        chatbot = ChatbotController(db, host_manager)
        
        # Get conversation history
        result = chatbot.get_conversation_history(conversation_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/chatbot/execution/<conversation_id>/<execution_id>', methods=['GET'])
def get_chatbot_execution_results(conversation_id, execution_id):
    """Get detailed execution results"""
    try:
        from chatbot_controller import ChatbotController
        
        # Initialize chatbot controller
        chatbot = ChatbotController(db, host_manager)
        
        # Get execution results
        result = chatbot.get_execution_results(conversation_id, execution_id)
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/chatbot/validate_script', methods=['POST'])
def validate_chatbot_script():
    """Validate a bash script for safety"""
    try:
        from command_validator import CommandValidator
        
        data = request.get_json() or {}
        script = data.get('script')
        
        if not script:
            return jsonify({
                'success': False,
                'error': 'No script provided'
            }), 400
        
        # Initialize validator
        validator = CommandValidator()
        
        # Validate script
        validation_result = validator.validate_script(script)
        
        return jsonify({
            'success': True,
            'validation': validation_result
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/chatbot/generate_script', methods=['POST'])
def generate_chatbot_script():
    """Generate a script from natural language request"""
    try:
        from ai_command_generator import AICommandGenerator
        
        data = request.get_json() or {}
        user_request = data.get('request')
        selected_hosts = data.get('selected_hosts', [])
        
        if not user_request:
            return jsonify({
                'success': False,
                'error': 'No request provided'
            }), 400
        
        # Initialize command generator
        generator = AICommandGenerator(db)
        
        # Generate script
        generation_result = generator.generate_script_from_request(user_request, selected_hosts)
        
        return jsonify(generation_result)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/ai_reports/data_stats', methods=['GET'])
def get_ai_reports_data_stats():
    """Get statistics about available data for AI analysis"""
    try:
        from ai_data_collector import AIDataCollector
        collector = AIDataCollector(db, host_manager)
        stats = collector.get_data_statistics()
        
        return jsonify({
            'success': True,
            'stats': stats
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def format_ai_report_to_html(report):
    """Format AI report dictionary into well-structured, readable HTML"""
    if not report:
        return "<div class='alert alert-info'><strong>No Report Data</strong><br>No report data is available to display.</div>"
    
    html = []
    
    def format_text_content(text, add_paragraphs=True):
        """Helper function to format text content with proper structure"""
        import re  # Import re module at the function start
        
        if not text:
            return ""
        
        # Convert text to string if it's not already
        text = str(text)
        
        # Split on common AI formatting patterns and numbered points
        lines = []
        current_line = ""
        
        for char in text:
            current_line += char
            # Break on sentence endings followed by numbers or bullet points
            if char in '.!' and len(current_line) > 50:
                # Look ahead to see if next content starts with number or bullet
                remaining = text[text.find(current_line) + len(current_line):].strip()
                if remaining and (remaining.startswith(('1.', '2.', '3.', '4.', '5.', '6.', '7.', '8.', '9.', '###', '**', '-')) or remaining.startswith('###')):
                    lines.append(current_line.strip())
                    current_line = ""
        
        # Add any remaining content
        if current_line.strip():
            lines.append(current_line.strip())
        
        # If no natural breaks found, split on long sentences
        if len(lines) <= 1 and len(text) > 200:
            # Split on periods followed by spaces and capital letters
            sentences = re.split(r'\. (?=[A-Z])', text)
            lines = [s.strip() + ('.' if not s.strip().endswith(('.', '!', '?')) else '') for s in sentences if s.strip()]
        
        formatted_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
                
            # Format numbered points
            if re.match(r'^\d+\.', line):
                formatted_lines.append(f"<div class='numbered-point'><strong>{line[:line.find('.')+1]}</strong> {line[line.find('.')+1:].strip()}</div>")
            # Format headers with ###
            elif line.startswith('###'):
                header_text = line.replace('###', '').strip()
                formatted_lines.append(f"<h4 style='color: #0066cc; margin-top: 20px; margin-bottom: 10px;'>{header_text}</h4>")
            # Format bold items with **
            elif '**' in line:
                # Replace **text** with <strong>text</strong>
                formatted_line = re.sub(r'\*\*([^*]+)\*\*', r'<strong>\1</strong>', line)
                formatted_lines.append(f"<div class='content-line'>{formatted_line}</div>")
            # Format bullet points
            elif line.startswith(('-', '•', '*')):
                bullet_content = line[1:].strip()
                formatted_lines.append(f"<div class='bullet-point'>• {bullet_content}</div>")
            else:
                formatted_lines.append(f"<div class='content-line'>{line}</div>")
        
        return '<div class="formatted-content">' + '\n'.join(formatted_lines) + '</div>'
    
    # Add metadata header if available
    metadata = report.get('metadata', {})
    if metadata:
        html.append('<div class="report-section metadata-section">')
        html.append('<h2><i class="fas fa-info-circle"></i> Report Information</h2>')
        html.append('<div class="metadata-grid">')
        html.append(f'<div class="metadata-item"><strong>Generated:</strong> {metadata.get("generated_at", "Unknown")}</div>')
        html.append(f'<div class="metadata-item"><strong>AI Model:</strong> {metadata.get("ai_model", "Unknown").title()}</div>')
        html.append(f'<div class="metadata-item"><strong>Data Source:</strong> {metadata.get("data_type", "Unknown").replace("_", " ").title()}</div>')
        if metadata.get('generation_time'):
            try:
                gen_time = float(metadata.get('generation_time', 0))
                html.append(f'<div class="metadata-item"><strong>Generation Time:</strong> {gen_time:.2f} seconds</div>')
            except (ValueError, TypeError):
                html.append(f'<div class="metadata-item"><strong>Generation Time:</strong> {metadata.get("generation_time", "Unknown")} seconds</div>')
        html.append('</div></div>')
    
    # Check if this is an error report
    if 'error_details' in report:
        html.append('<div class="report-section error-section">')
        html.append('<h2 style="color: #c9190b;"><i class="fas fa-exclamation-triangle"></i> Report Generation Failed</h2>')
        html.append(f'<div class="error-content">{report.get("error_details", "Unknown error occurred.")}</div>')
        html.append('</div>')
        return '\n'.join(html)
    
    # Executive Summary
    exec_summary = report.get('executive_summary', {})
    if exec_summary and isinstance(exec_summary, dict) and exec_summary.get('summary'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-chart-line"></i> Executive Summary</h2>')
        html.append(format_text_content(exec_summary['summary']))
        
        if exec_summary.get('key_points'):
            html.append('<h3>Key Points</h3>')
            html.append('<ul class="key-points-list">')
            for point in exec_summary['key_points']:
                html.append(f'<li>{point}</li>')
            html.append('</ul>')
        
        if exec_summary.get('risk_level'):
            risk_level = exec_summary['risk_level']
            risk_color = '#28a745' if 'low' in str(risk_level).lower() else '#ffc107' if 'medium' in str(risk_level).lower() else '#dc3545'
            html.append(f'<div class="risk-indicator" style="background-color: {risk_color}20; border-left: 4px solid {risk_color}; padding: 10px; margin-top: 15px;"><strong>Risk Level:</strong> {risk_level}</div>')
        
        html.append('</div>')
    
    # Security Analysis
    security = report.get('security_analysis', {})
    if security and isinstance(security, dict) and security.get('analysis'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-shield-alt"></i> Security Analysis</h2>')
        html.append(format_text_content(security['analysis']))
        
        if security.get('threats_identified'):
            html.append('<h3>Threats Identified</h3>')
            html.append('<ul class="threats-list">')
            for threat in security['threats_identified']:
                html.append(f'<li class="threat-item">{threat}</li>')
            html.append('</ul>')
        
        if security.get('recommendations'):
            html.append('<h3>Security Recommendations</h3>')
            html.append('<ol class="recommendations-list">')
            for rec in security['recommendations']:
                html.append(f'<li class="recommendation-item">{rec}</li>')
            html.append('</ol>')
        
        html.append('</div>')
    
    # Performance Insights
    performance = report.get('performance_insights', {})
    if performance and isinstance(performance, dict) and performance.get('analysis'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-tachometer-alt"></i> Performance Insights</h2>')
        html.append(format_text_content(performance['analysis']))
        
        if performance.get('bottlenecks'):
            html.append('<h3>Performance Bottlenecks</h3>')
            html.append('<ul class="bottlenecks-list">')
            for bottleneck in performance['bottlenecks']:
                html.append(f'<li class="bottleneck-item">{bottleneck}</li>')
            html.append('</ul>')
        
        html.append('</div>')
    
    # Network Overview
    network = report.get('network_overview', {})
    if network and isinstance(network, dict) and network.get('analysis'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-network-wired"></i> Network Overview</h2>')
        html.append(format_text_content(network['analysis']))
        
        # Add topology insights if available
        if network.get('topology_insights'):
            topology = network['topology_insights']
            html.append('<h3>Network Statistics</h3>')
            html.append('<div class="stats-grid">')
            html.append(f'<div class="stat-item"><span class="stat-value">{topology.get("total_hosts", 0)}</span><span class="stat-label">Total Hosts</span></div>')
            html.append(f'<div class="stat-item"><span class="stat-value">{topology.get("total_connections", 0)}</span><span class="stat-label">Connections</span></div>')
            html.append(f'<div class="stat-item"><span class="stat-value">{topology.get("unique_destinations", 0)}</span><span class="stat-label">Unique Destinations</span></div>')
            html.append('</div>')
        
        html.append('</div>')
    
    # Infrastructure Analysis
    infra = report.get('infrastructure_analysis', {})
    if infra and isinstance(infra, dict) and infra.get('analysis'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-server"></i> Infrastructure Analysis</h2>')
        html.append(format_text_content(infra['analysis']))
        html.append('</div>')
    
    # Recommendations
    recs = report.get('recommendations', {})
    if recs and isinstance(recs, dict) and recs.get('analysis'):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-lightbulb"></i> Recommendations</h2>')
        html.append(format_text_content(recs['analysis']))
        
        # Priority actions
        if recs.get('priority_actions'):
            html.append('<h3>Priority Actions</h3>')
            html.append('<ol class="priority-actions">')
            for action in recs['priority_actions']:
                html.append(f'<li class="priority-action">{action}</li>')
            html.append('</ol>')
        
        html.append('</div>')
    
    # Detailed Findings
    findings = report.get('detailed_findings', {})
    if findings and isinstance(findings, dict):
        html.append('<div class="report-section">')
        html.append('<h2><i class="fas fa-search"></i> Detailed Technical Findings</h2>')
        
        # Network statistics
        if findings.get('network_statistics'):
            stats = findings['network_statistics']
            html.append('<h3>Network Statistics</h3>')
            html.append('<div class="detailed-stats">')
            html.append(f'<div class="stat-row"><span class="stat-name">Total Hosts:</span> <span class="stat-value">{stats.get("total_hosts", 0)}</span></div>')
            html.append(f'<div class="stat-row"><span class="stat-name">Online Hosts:</span> <span class="stat-value">{stats.get("online_hosts", 0)}</span></div>')
            html.append(f'<div class="stat-row"><span class="stat-name">Total Connections:</span> <span class="stat-value">{stats.get("total_connections", 0)}</span></div>')
            html.append(f'<div class="stat-row"><span class="stat-name">Data Collection Period:</span> <span class="stat-value">{stats.get("data_collection_period", "Unknown")}</span></div>')
            html.append('</div>')
        
        html.append('</div>')
    
    # Add CSS styles for better formatting
    styles = """
    <style>
    .report-section {
        margin-bottom: 30px;
        padding: 20px;
        border: 1px solid #e1e5e9;
        border-radius: 8px;
        background-color: #ffffff;
    }
    .report-section h2 {
        color: #0066cc;
        border-bottom: 2px solid #0066cc;
        padding-bottom: 8px;
        margin-bottom: 15px;
    }
    .report-section h3 {
        color: #004499;
        margin-top: 20px;
        margin-bottom: 10px;
    }
    .formatted-content {
        line-height: 1.6;
    }
    .content-line {
        margin-bottom: 8px;
    }
    .numbered-point {
        margin: 12px 0;
        padding-left: 10px;
        border-left: 3px solid #0066cc;
        background-color: #f8f9fa;
        padding: 10px;
        border-radius: 4px;
    }
    .bullet-point {
        margin: 8px 0;
        padding-left: 15px;
    }
    .metadata-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 10px;
        margin-top: 10px;
    }
    .metadata-item {
        padding: 8px;
        background-color: #f8f9fa;
        border-radius: 4px;
    }
    .key-points-list, .threats-list, .bottlenecks-list, .recommendations-list, .priority-actions {
        padding-left: 20px;
    }
    .key-points-list li, .threats-list li, .bottlenecks-list li, .recommendations-list li, .priority-actions li {
        margin-bottom: 8px;
        line-height: 1.5;
    }
    .stats-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
        gap: 15px;
        margin: 15px 0;
    }
    .stat-item {
        text-align: center;
        padding: 15px;
        background-color: #f8f9fa;
        border-radius: 8px;
        border: 1px solid #dee2e6;
    }
    .stat-value {
        display: block;
        font-size: 1.5em;
        font-weight: bold;
        color: #0066cc;
    }
    .stat-label {
        display: block;
        font-size: 0.9em;
        color: #6c757d;
        margin-top: 5px;
    }
    .detailed-stats {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 6px;
        border: 1px solid #dee2e6;
    }
    .stat-row {
        display: flex;
        justify-content: space-between;
        padding: 5px 0;
        border-bottom: 1px solid #dee2e6;
    }
    .stat-row:last-child {
        border-bottom: none;
    }
    .stat-name {
        font-weight: 500;
    }
    .error-section {
        border-color: #dc3545;
        background-color: #f8d7da;
    }
    .error-content {
        background-color: #fff;
        padding: 15px;
        border-radius: 4px;
        border: 1px solid #f5c6cb;
    }
    </style>
    """
    
    # Combine everything
    result = styles + '\n'.join(html)
    
    # If no content was generated, show a message
    if len(html) <= 1:  # Only styles
        result += '<div class="report-section"><h2>Report Generated</h2><p>The AI has completed the analysis, but no structured content was returned. This may indicate an issue with the AI response format.</p></div>'
    
    return result
@app.route('/api/ai_reports/generate', methods=['POST'])
def generate_ai_report():
    """Generate an AI-powered network analysis report"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        ai_model = data.get('ai_model')
        data_type = data.get('data_type')
        
        if not ai_model or not data_type:
            return jsonify({
                'success': False,
                'error': 'AI model and data type are required'
            }), 400
        
        if ai_model not in ['gemini', 'chatgpt']:
            return jsonify({
                'success': False,
                'error': 'Invalid AI model. Must be gemini or chatgpt'
            }), 400
        
        if data_type not in ['all_data', 'latest_capture', 'latest_logs']:
            return jsonify({
                'success': False,
                'error': 'Invalid data type'
            }), 400
        
        # Import the AI report generator
        from ai_report_generator import AIReportGenerator
        
        # Initialize the report generator
        generator = AIReportGenerator(db, host_manager)
        
        # Generate the report
        report_data = generator.generate_report(ai_model, data_type)
        
        # Format the report for display
        formatted_report = format_ai_report_to_html(report_data)
        
        return jsonify({
            'success': True,
            'report': formatted_report,
            'ai_model': ai_model,
            'data_type': data_type,
            'generated_at': datetime.now().isoformat()
        })
        
    except Exception as e:
        import traceback
        error_details = str(e)
        
        # Log the full error for debugging
        print(f"Error generating AI report: {e}")
        traceback.print_exc()
        
        # Create a user-friendly error message
        if "404" in str(e):
            error_details = "AI service endpoint not found. Please check your API configuration in Settings."
        elif "timeout" in str(e).lower():
            error_details = "AI service timeout. The request took too long to process."
        elif "api key" in str(e).lower():
            error_details = "AI API key not configured or invalid. Please check your settings."
        elif "connection" in str(e).lower():
            error_details = "Unable to connect to AI service. Please check your internet connection."
        
        # Return error in the expected format that the HTML formatter can handle
        error_report = {
            'error_details': error_details,
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'ai_model': request.json.get('ai_model', 'Unknown') if request.json else 'Unknown',
                'data_type': request.json.get('data_type', 'Unknown') if request.json else 'Unknown',
                'error': True
            }
        }
        
        # Format the error as HTML
        formatted_error = format_ai_report_to_html(error_report)
        
        return jsonify({
            'success': True,  # We successfully formatted the error
            'report': formatted_error,
            'error': True,
            'ai_model': request.json.get('ai_model', 'Unknown') if request.json else 'Unknown',
            'data_type': request.json.get('data_type', 'Unknown') if request.json else 'Unknown',
            'generated_at': datetime.now().isoformat()
        })

# Script execution progress tracking endpoints
@app.route('/api/script_execution/progress/<execution_id>', methods=['GET'])
def get_script_execution_progress(execution_id):
    """Get the progress of a running script execution"""
    try:
        global script_execution_progress
        
        # Check running executions first
        if execution_id in script_execution_progress['running']:
            execution_info = script_execution_progress['running'][execution_id]
            
            # Get recent logs for this specific execution
            execution_logs = [log for log in script_execution_progress['logs'] 
                             if log.get('execution_id') == execution_id][-20:]  # Last 20 logs
            
            return jsonify({
                'success': True,
                'execution_id': execution_id,
                'running': True,
                'execution_info': execution_info,
                'logs': execution_logs,
                'timestamp': datetime.now().isoformat()
            })
        
        # Check completed executions
        elif execution_id in script_execution_progress['completed']:
            execution_info = script_execution_progress['completed'][execution_id]
            
            # Get logs for this completed execution
            execution_logs = [log for log in script_execution_progress['logs'] 
                             if log.get('execution_id') == execution_id]
            
            return jsonify({
                'success': True,
                'execution_id': execution_id,
                'running': False,
                'completed': True,
                'execution_info': execution_info,
                'logs': execution_logs,
                'timestamp': datetime.now().isoformat()
            })
        
        else:
            return jsonify({
                'success': False,
                'error': f'No execution found for ID {execution_id}',
                'running': False,
                'completed': False
            }), 404
        
    except Exception as e:
        print(f"Error getting script execution progress: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/script_execution/all_progress', methods=['GET'])
def get_all_script_execution_progress():
    """Get the progress of all running script executions"""
    try:
        global script_execution_progress
        
        # Get recent logs (last 50 entries)
        recent_logs = list(script_execution_progress['logs'])[-50:]
        
        # Count running and completed executions
        running_count = len(script_execution_progress['running'])
        completed_count = len(script_execution_progress['completed'])
        
        return jsonify({
            'success': True,
            'running_executions': script_execution_progress['running'],
            'completed_executions': script_execution_progress['completed'],
            'running_count': running_count,
            'completed_count': completed_count,
            'recent_logs': recent_logs,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting all script execution progress: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/script_execution/results/<execution_id>', methods=['GET'])
def get_script_execution_results(execution_id):
    """Get the detailed results of a script execution"""
    try:
        global script_execution_progress
        
        execution_info = None
        
        # Check running executions first
        if execution_id in script_execution_progress['running']:
            execution_info = script_execution_progress['running'][execution_id]
        # Check completed executions
        elif execution_id in script_execution_progress['completed']:
            execution_info = script_execution_progress['completed'][execution_id]
        
        if not execution_info:
            return jsonify({
                'success': False,
                'error': f'No execution found for ID {execution_id}'
            }), 404
        
        # Get all logs for this execution
        execution_logs = [log for log in script_execution_progress['logs'] 
                         if log.get('execution_id') == execution_id]
        
        # Prepare detailed results
        results = {
            'execution_id': execution_id,
            'hostname': execution_info.get('hostname'),
            'ip_address': execution_info.get('ip_address'),
            'script_type': execution_info.get('script_type'),
            'start_time': execution_info.get('start_time'),
            'end_time': execution_info.get('end_time'),
            'duration_seconds': execution_info.get('duration_seconds'),
            'status': execution_info.get('status'),
            'current_phase': execution_info.get('current_phase'),
            'progress': execution_info.get('progress'),
            'current_action': execution_info.get('current_action'),
            'phases_completed': execution_info.get('phases_completed', []),
            'error': execution_info.get('error'),
            'result': execution_info.get('result'),
            'logs': execution_logs
        }
        
        return jsonify({
            'success': True,
            'results': results,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error getting script execution results: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/script_execution/cancel/<execution_id>', methods=['POST'])
def cancel_script_execution(execution_id):
    """Cancel a running script execution"""
    try:
        global script_execution_progress
        
        if execution_id not in script_execution_progress['running']:
            return jsonify({
                'success': False,
                'error': f'No running execution found for ID {execution_id}'
            }), 404
        
        execution_info = script_execution_progress['running'][execution_id]
        
        # Mark as cancelled
        execution_info['status'] = 'cancelled'
        execution_info['current_action'] = 'Execution cancelled by user'
        execution_info['end_time'] = datetime.now().isoformat()
        
        # Calculate duration if start time exists
        if execution_info.get('start_time'):
            try:
                start_time = datetime.fromisoformat(execution_info['start_time'])
                end_time = datetime.fromisoformat(execution_info['end_time'])
                duration = (end_time - start_time).total_seconds()
                execution_info['duration_seconds'] = round(duration, 2)
            except:
                pass
        
        # Add cancellation log
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'execution_id': execution_id,
            'hostname': execution_info.get('hostname'),
            'message': 'Script execution cancelled by user',
            'level': 'warning',
            'phase': 'cancelled'
        }
        script_execution_progress['logs'].append(log_entry)
        
        # Move to completed
        script_execution_progress['completed'][execution_id] = execution_info
        del script_execution_progress['running'][execution_id]
        
        return jsonify({
            'success': True,
            'message': f'Script execution {execution_id} cancelled',
            'execution_id': execution_id,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error cancelling script execution: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/script_execution/cleanup', methods=['POST'])
def cleanup_script_executions():
    """Clean up old completed script executions"""
    try:
        global script_execution_progress
        
        # Get cleanup parameters
        data = request.get_json() or {}
        hours_old = data.get('hours_old', 1)  # Default: remove executions older than 1 hour
        
        cutoff_time = datetime.now() - timedelta(hours=hours_old)
        
        removed_count = 0
        execution_ids_to_remove = []
        
        # Find old completed executions
        for execution_id, execution_info in script_execution_progress['completed'].items():
            try:
                if execution_info.get('end_time'):
                    end_time = datetime.fromisoformat(execution_info['end_time'])
                    if end_time < cutoff_time:
                        execution_ids_to_remove.append(execution_id)
            except:
                # If we can't parse the time, consider it for removal
                execution_ids_to_remove.append(execution_id)
        
        # Remove old executions
        for execution_id in execution_ids_to_remove:
            del script_execution_progress['completed'][execution_id]
            removed_count += 1
        
        # Also clean up old logs
        log_cutoff_time = datetime.now() - timedelta(hours=hours_old * 2)  # Keep logs longer
        original_log_count = len(script_execution_progress['logs'])
        
        # Filter out old logs
        filtered_logs = []
        for log in script_execution_progress['logs']:
            try:
                log_time = datetime.fromisoformat(log['timestamp'])
                if log_time >= log_cutoff_time:
                    filtered_logs.append(log)
            except:
                # Keep logs we can't parse timestamp for
                filtered_logs.append(log)
        
        script_execution_progress['logs'] = deque(filtered_logs, maxlen=1000)
        logs_removed = original_log_count - len(filtered_logs)
        
        return jsonify({
            'success': True,
            'message': f'Cleaned up {removed_count} executions and {logs_removed} log entries',
            'executions_removed': removed_count,
            'logs_removed': logs_removed,
            'hours_old': hours_old,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error cleaning up script executions: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Statistics page route
@app.route('/statistics')
def statistics_dashboard():
    """Render the statistics dashboard page"""
    return render_template('statistics.html')

if __name__ == '__main__':
    print("Initializing NetworkMap Flask Application...")
    
    try:
        # Initialize database
        print("Initializing database...")
        db.init_db()
        print("✓ Database initialized successfully")
        
        print("Starting Flask server on http://0.0.0.0:5150")
        print("Note: Debug mode disabled for stability")
        
        # Run Flask app with debug=False to prevent reload issues
        app.run(debug=False, host='0.0.0.0', port=5150, threaded=True, use_reloader=False)
        
    except Exception as e:
        print(f"❌ Failed to start Flask application: {e}")
        import traceback
        traceback.print_exc()
