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

@app.route('/api/network_data')
def network_data():
    """API endpoint for network topology data"""
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
    """Get enhanced network data with role classification"""
    try:
        # Get basic topology
        basic_topology = scanner.get_network_topology()
        
        # Get device roles from stored analysis
        with db.get_connection() as conn:
            cursor = conn.execute('''
                SELECT analysis_data FROM topology_analysis 
                WHERE analysis_type = 'device_roles' 
                ORDER BY timestamp DESC LIMIT 1
            ''')
            device_roles_row = cursor.fetchone()
            
        device_roles = {}
        if device_roles_row:
            try:
                device_roles = json.loads(device_roles_row['analysis_data'])
            except json.JSONDecodeError:
                pass
        
        # Enhance nodes with role information
        enhanced_nodes = []
        for node in basic_topology['nodes']:
            host_id = str(node['id'])
            role_info = device_roles.get(host_id, {})
            
            enhanced_node = node.copy()
            enhanced_node.update({
                'roles': role_info.get('roles', []),
                'primary_role': role_info.get('primary_role', 'unknown'),
                'confidence': role_info.get('confidence', {})
            })
            enhanced_nodes.append(enhanced_node)
        
        return jsonify({
            'nodes': enhanced_nodes,
            'edges': basic_topology['edges']
        })
        
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
            update_scan_status('analyzing', 'Running advanced topology analysis...', 92)
            topology_analyzer.analyze_network_topology()
            update_scan_status('analyzing', 'Topology analysis complete', 96)
        except Exception as e:
            print(f"Topology analysis error: {e}")
            update_scan_status('analyzing', f'Topology analysis failed: {str(e)[:50]}', 96)
        
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
