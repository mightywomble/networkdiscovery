#!/usr/bin/env python3
"""
Database module for Network Map application
Handles SQLite storage of hosts, connections, and statistics
"""

import sqlite3
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
import json

class Database:
    def __init__(self, db_path='networkmap.db'):
        self.db_path = db_path
        
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def init_db(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Hosts table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    ip_address TEXT NOT NULL,
                    username TEXT DEFAULT 'root',
                    ssh_port INTEGER DEFAULT 22,
                    description TEXT,
                    status TEXT DEFAULT 'unknown',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Network connections table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS network_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_host_id INTEGER,
                    dest_host_id INTEGER,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    protocol TEXT,
                    connection_count INTEGER DEFAULT 1,
                    bytes_sent INTEGER DEFAULT 0,
                    bytes_received INTEGER DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (source_host_id) REFERENCES hosts (id),
                    FOREIGN KEY (dest_host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Port scan results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS port_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    port INTEGER,
                    service TEXT,
                    state TEXT,
                    version TEXT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Network traffic statistics
            conn.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    bytes_in INTEGER DEFAULT 0,
                    bytes_out INTEGER DEFAULT 0,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    connections_active INTEGER DEFAULT 0,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # System information
            conn.execute('''
                CREATE TABLE IF NOT EXISTS host_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    hostname TEXT,
                    os_info TEXT,
                    kernel_version TEXT,
                    cpu_info TEXT,
                    memory_total INTEGER,
                    disk_info TEXT,
                    network_interfaces TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Network discovery data
            conn.execute('''
                CREATE TABLE IF NOT EXISTS network_discovery (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER,
                    discovery_type TEXT,
                    discovery_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Topology analysis results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS topology_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_type TEXT,
                    analysis_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Network diagram layouts
            conn.execute('''
                CREATE TABLE IF NOT EXISTS diagram_layouts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    layout_name TEXT DEFAULT 'default',
                    layout_data TEXT,
                    created_by TEXT DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Agent management
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT UNIQUE NOT NULL,
                    host_id INTEGER,
                    hostname TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    username TEXT NOT NULL,
                    agent_version TEXT,
                    status TEXT DEFAULT 'inactive',
                    last_heartbeat TIMESTAMP,
                    last_scan TIMESTAMP,
                    config_hash TEXT,
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (host_id) REFERENCES hosts (id)
                )
            ''')
            
            # Agent configuration
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agent_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    server_url TEXT NOT NULL,
                    scan_interval INTEGER DEFAULT 300,
                    heartbeat_interval INTEGER DEFAULT 60,
                    log_collection_enabled BOOLEAN DEFAULT 1,
                    log_paths TEXT DEFAULT '/var/log',
                    scan_enabled BOOLEAN DEFAULT 1,
                    config_version INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # Agent logs collection
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agent_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    log_source TEXT NOT NULL,
                    log_level TEXT,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            # Agent scan results
            conn.execute('''
                CREATE TABLE IF NOT EXISTS agent_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scan_data TEXT NOT NULL,
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed BOOLEAN DEFAULT 0,
                    FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                )
            ''')
            
            conn.commit()
    
    # Host management
    def add_host(self, name, ip_address, username='root', ssh_port=22, description=''):
        """Add a new host"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                INSERT INTO hosts (name, ip_address, username, ssh_port, description)
                VALUES (?, ?, ?, ?, ?)
            ''', (name, ip_address, username, ssh_port, description))
            conn.commit()
            return cursor.lastrowid
    
    def get_host(self, host_id):
        """Get a specific host"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM hosts WHERE id = ?', (host_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_all_hosts(self):
        """Get all hosts"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM hosts ORDER BY name')
            hosts = []
            for row in cursor.fetchall():
                host = dict(row)
                # Convert last_seen string to datetime object if it exists
                if host.get('last_seen'):
                    try:
                        # Parse SQLite timestamp string to datetime object
                        host['last_seen'] = datetime.fromisoformat(host['last_seen'].replace(' ', 'T'))
                    except (ValueError, AttributeError):
                        # If parsing fails, set to None
                        host['last_seen'] = None
                hosts.append(host)
            return hosts
    
    def update_host_status(self, host_id, status, last_seen=None):
        """Update host status and last seen time"""
        if last_seen is None:
            last_seen = datetime.now()
        
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE hosts 
                SET status = ?, last_seen = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (status, last_seen, host_id))
            conn.commit()
    
    def remove_host(self, host_id):
        """Remove a host and all related data"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM traffic_stats WHERE host_id = ?', (host_id,))
            conn.execute('DELETE FROM port_scans WHERE host_id = ?', (host_id,))
            conn.execute('DELETE FROM host_info WHERE host_id = ?', (host_id,))
            conn.execute('DELETE FROM network_connections WHERE source_host_id = ? OR dest_host_id = ?', 
                        (host_id, host_id))
            conn.execute('DELETE FROM hosts WHERE id = ?', (host_id,))
            conn.commit()
    
    # Network connections
    def add_connection(self, source_host_id, dest_ip, dest_port, protocol, dest_host_id=None, 
                      bytes_sent=0, bytes_received=0):
        """Add or update a network connection"""
        with self.get_connection() as conn:
            # Check if connection already exists
            cursor = conn.execute('''
                SELECT id, connection_count FROM network_connections 
                WHERE source_host_id = ? AND dest_ip = ? AND dest_port = ? AND protocol = ?
            ''', (source_host_id, dest_ip, dest_port, protocol))
            
            existing = cursor.fetchone()
            if existing:
                # Update existing connection
                conn.execute('''
                    UPDATE network_connections 
                    SET connection_count = connection_count + 1,
                        bytes_sent = bytes_sent + ?,
                        bytes_received = bytes_received + ?,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (bytes_sent, bytes_received, existing['id']))
            else:
                # Insert new connection
                conn.execute('''
                    INSERT INTO network_connections 
                    (source_host_id, dest_host_id, dest_ip, dest_port, protocol, 
                     bytes_sent, bytes_received)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (source_host_id, dest_host_id, dest_ip, dest_port, protocol, 
                     bytes_sent, bytes_received))
            
            conn.commit()
    
    def get_recent_connections(self, hours=24):
        """Get recent network connections"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT nc.*, h1.name as source_name, h2.name as dest_name
                FROM network_connections nc
                LEFT JOIN hosts h1 ON nc.source_host_id = h1.id
                LEFT JOIN hosts h2 ON nc.dest_host_id = h2.id
                WHERE nc.last_seen > ?
                ORDER BY nc.last_seen DESC
            ''', (cutoff,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Port scan results
    def save_port_scan(self, host_id, ports):
        """Save port scan results"""
        with self.get_connection() as conn:
            # Clear old scan results for this host
            conn.execute('DELETE FROM port_scans WHERE host_id = ?', (host_id,))
            
            # Insert new results
            for port_info in ports:
                conn.execute('''
                    INSERT INTO port_scans (host_id, port, service, state, version)
                    VALUES (?, ?, ?, ?, ?)
                ''', (host_id, port_info['port'], port_info.get('service'), 
                     port_info.get('state', 'open'), port_info.get('version')))
            
            conn.commit()
    
    def get_host_ports(self, host_id):
        """Get port scan results for a host"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM port_scans WHERE host_id = ? ORDER BY port
            ''', (host_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Traffic statistics
    def add_traffic_stats(self, host_id, bytes_in=0, bytes_out=0, packets_in=0, 
                         packets_out=0, connections_active=0):
        """Add traffic statistics for a host"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO traffic_stats 
                (host_id, bytes_in, bytes_out, packets_in, packets_out, connections_active)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (host_id, bytes_in, bytes_out, packets_in, packets_out, connections_active))
            conn.commit()
    
    def get_traffic_stats(self, hours=24):
        """Get traffic statistics for the specified time period"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT ts.*, h.name, h.ip_address
                FROM traffic_stats ts
                JOIN hosts h ON ts.host_id = h.id
                WHERE ts.timestamp > ?
                ORDER BY ts.timestamp DESC
            ''', (cutoff,))
            return [dict(row) for row in cursor.fetchall()]
    
    # Host system information
    def save_host_info(self, host_id, hostname, os_info, kernel_version, cpu_info, 
                      memory_total, disk_info, network_interfaces):
        """Save system information for a host"""
        with self.get_connection() as conn:
            # Delete existing info
            conn.execute('DELETE FROM host_info WHERE host_id = ?', (host_id,))
            
            # Insert new info
            conn.execute('''
                INSERT INTO host_info 
                (host_id, hostname, os_info, kernel_version, cpu_info, 
                 memory_total, disk_info, network_interfaces)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (host_id, hostname, os_info, kernel_version, cpu_info, 
                 memory_total, json.dumps(disk_info), json.dumps(network_interfaces)))
            conn.commit()
    
    def get_host_info(self, host_id):
        """Get system information for a host"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM host_info WHERE host_id = ?', (host_id,))
            row = cursor.fetchone()
            if row:
                info = dict(row)
                info['disk_info'] = json.loads(info['disk_info'])
                info['network_interfaces'] = json.loads(info['network_interfaces'])
                return info
            return None
    
    # Statistics and analytics
    def get_network_stats(self):
        """Get overall network statistics"""
        with self.get_connection() as conn:
            # Host counts
            cursor = conn.execute('SELECT COUNT(*) as total_hosts FROM hosts')
            total_hosts = cursor.fetchone()['total_hosts']
            
            cursor = conn.execute("SELECT COUNT(*) as online_hosts FROM hosts WHERE status = 'online'")
            online_hosts = cursor.fetchone()['online_hosts']
            
            # Connection counts
            cursor = conn.execute('SELECT COUNT(*) as total_connections FROM network_connections')
            total_connections = cursor.fetchone()['total_connections']
            
            # Recent activity
            cutoff = datetime.now() - timedelta(hours=24)
            cursor = conn.execute('''
                SELECT COUNT(*) as recent_connections 
                FROM network_connections WHERE last_seen > ?
            ''', (cutoff,))
            recent_connections = cursor.fetchone()['recent_connections']
            
            return {
                'total_hosts': total_hosts,
                'online_hosts': online_hosts,
                'total_connections': total_connections,
                'recent_connections': recent_connections
            }
    
    def get_host_stats(self, host_id):
        """Get detailed statistics for a specific host"""
        with self.get_connection() as conn:
            # Basic host info
            cursor = conn.execute('SELECT * FROM hosts WHERE id = ?', (host_id,))
            host = dict(cursor.fetchone())
            
            # Port count
            cursor = conn.execute('SELECT COUNT(*) as open_ports FROM port_scans WHERE host_id = ?', (host_id,))
            open_ports = cursor.fetchone()['open_ports']
            
            # Connection stats
            cursor = conn.execute('''
                SELECT COUNT(*) as outbound_connections 
                FROM network_connections WHERE source_host_id = ?
            ''', (host_id,))
            outbound = cursor.fetchone()['outbound_connections']
            
            cursor = conn.execute('''
                SELECT COUNT(*) as inbound_connections 
                FROM network_connections WHERE dest_host_id = ?
            ''', (host_id,))
            inbound = cursor.fetchone()['inbound_connections']
            
            # Traffic stats (last 24 hours)
            cutoff = datetime.now() - timedelta(hours=24)
            cursor = conn.execute('''
                SELECT SUM(bytes_in) as total_bytes_in, SUM(bytes_out) as total_bytes_out
                FROM traffic_stats WHERE host_id = ? AND timestamp > ?
            ''', (host_id, cutoff))
            traffic = cursor.fetchone()
            
            return {
                'host': host,
                'open_ports': open_ports,
                'outbound_connections': outbound,
                'inbound_connections': inbound,
                'bytes_in_24h': traffic['total_bytes_in'] or 0,
                'bytes_out_24h': traffic['total_bytes_out'] or 0
            }
    
    # Network discovery data
    def save_network_discovery(self, host_id, discovery_type, discovery_data):
        """Save network discovery data for a host"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO network_discovery (host_id, discovery_type, discovery_data)
                VALUES (?, ?, ?)
            ''', (host_id, discovery_type, json.dumps(discovery_data)))
            conn.commit()
    
    def get_network_discovery(self, host_id=None, discovery_type=None, hours=24):
        """Get network discovery data"""
        cutoff = datetime.now() - timedelta(hours=hours)
        query = 'SELECT * FROM network_discovery WHERE timestamp > ?'
        params = [cutoff]
        
        if host_id:
            query += ' AND host_id = ?'
            params.append(host_id)
        
        if discovery_type:
            query += ' AND discovery_type = ?'
            params.append(discovery_type)
        
        query += ' ORDER BY timestamp DESC'
        
        with self.get_connection() as conn:
            cursor = conn.execute(query, params)
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['discovery_data'] = json.loads(result['discovery_data'])
                except json.JSONDecodeError:
                    result['discovery_data'] = {}
                results.append(result)
            return results
    
    # Topology analysis results
    def save_topology_analysis(self, analysis_type, analysis_data):
        """Save topology analysis results"""
        with self.get_connection() as conn:
            # Remove old analysis of the same type
            conn.execute('DELETE FROM topology_analysis WHERE analysis_type = ?', (analysis_type,))
            
            # Insert new analysis
            conn.execute('''
                INSERT INTO topology_analysis (analysis_type, analysis_data)
                VALUES (?, ?)
            ''', (analysis_type, json.dumps(analysis_data)))
            conn.commit()
    
    def get_topology_analysis(self, analysis_type=None):
        """Get topology analysis results"""
        with self.get_connection() as conn:
            if analysis_type:
                cursor = conn.execute('''
                    SELECT * FROM topology_analysis WHERE analysis_type = ?
                    ORDER BY timestamp DESC LIMIT 1
                ''', (analysis_type,))
                row = cursor.fetchone()
                if row:
                    result = dict(row)
                    try:
                        result['analysis_data'] = json.loads(result['analysis_data'])
                    except json.JSONDecodeError:
                        result['analysis_data'] = {}
                    return result
                return None
            else:
                cursor = conn.execute('''
                    SELECT * FROM topology_analysis ORDER BY timestamp DESC
                ''')
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    try:
                        result['analysis_data'] = json.loads(result['analysis_data'])
                    except json.JSONDecodeError:
                        result['analysis_data'] = {}
                    results.append(result)
                return results
    
    # Network diagram layout management
    def save_diagram_layout(self, layout_name='default', layout_data=None, created_by='system'):
        """Save network diagram layout"""
        with self.get_connection() as conn:
            # Check if layout exists
            cursor = conn.execute('SELECT id FROM diagram_layouts WHERE layout_name = ?', (layout_name,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing layout
                conn.execute('''
                    UPDATE diagram_layouts 
                    SET layout_data = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE layout_name = ?
                ''', (json.dumps(layout_data), layout_name))
            else:
                # Insert new layout
                conn.execute('''
                    INSERT INTO diagram_layouts (layout_name, layout_data, created_by)
                    VALUES (?, ?, ?)
                ''', (layout_name, json.dumps(layout_data), created_by))
            
            conn.commit()
    
    def get_diagram_layout(self, layout_name='default'):
        """Get network diagram layout"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM diagram_layouts WHERE layout_name = ?
                ORDER BY updated_at DESC LIMIT 1
            ''', (layout_name,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                try:
                    result['layout_data'] = json.loads(result['layout_data']) if result['layout_data'] else {}
                except json.JSONDecodeError:
                    result['layout_data'] = {}
                return result
            return None
    
    def get_all_diagram_layouts(self):
        """Get all available network diagram layouts"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT layout_name, created_by, created_at, updated_at 
                FROM diagram_layouts 
                ORDER BY updated_at DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def delete_diagram_layout(self, layout_name):
        """Delete a network diagram layout"""
        if layout_name == 'default':
            return False  # Don't allow deletion of default layout
            
        with self.get_connection() as conn:
            cursor = conn.execute('DELETE FROM diagram_layouts WHERE layout_name = ?', (layout_name,))
            conn.commit()
            return cursor.rowcount > 0
    
    # Agent management methods
    def register_agent(self, agent_id, hostname, ip_address, username, agent_version=None, host_id=None):
        """Register a new agent or update existing one"""
        with self.get_connection() as conn:
            # Check if agent already exists
            cursor = conn.execute('SELECT id FROM agents WHERE agent_id = ?', (agent_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing agent
                conn.execute('''
                    UPDATE agents 
                    SET hostname = ?, ip_address = ?, username = ?, agent_version = ?, 
                        host_id = ?, status = 'active', updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                ''', (hostname, ip_address, username, agent_version, host_id, agent_id))
            else:
                # Insert new agent
                conn.execute('''
                    INSERT INTO agents 
                    (agent_id, hostname, ip_address, username, agent_version, host_id, status)
                    VALUES (?, ?, ?, ?, ?, ?, 'active')
                ''', (agent_id, hostname, ip_address, username, agent_version, host_id))
            
            conn.commit()
    
    def update_agent_heartbeat(self, agent_id, status='active', error_message=None):
        """Update agent heartbeat and status"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET last_heartbeat = CURRENT_TIMESTAMP, status = ?, error_message = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (status, error_message, agent_id))
            conn.commit()
    
    def update_agent_scan_time(self, agent_id):
        """Update agent last scan time"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET last_scan = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (agent_id,))
            conn.commit()
    
    def get_agent(self, agent_id):
        """Get agent information"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM agents WHERE agent_id = ?', (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_all_agents(self):
        """Get all registered agents"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT a.*, h.name as host_name 
                FROM agents a
                LEFT JOIN hosts h ON a.host_id = h.id
                ORDER BY a.hostname
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def deactivate_agent(self, agent_id):
        """Deactivate an agent"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (agent_id,))
            conn.commit()
    
    def remove_agent(self, agent_id):
        """Remove an agent and all related data"""
        with self.get_connection() as conn:
            conn.execute('DELETE FROM agent_logs WHERE agent_id = ?', (agent_id,))
            conn.execute('DELETE FROM agent_scan_results WHERE agent_id = ?', (agent_id,))
            conn.execute('DELETE FROM agent_configs WHERE agent_id = ?', (agent_id,))
            conn.execute('DELETE FROM agents WHERE agent_id = ?', (agent_id,))
            conn.commit()
    
    def remove_agents_by_host(self, hostname=None, ip_address=None):
        """Remove agents by hostname or IP address"""
        if not hostname and not ip_address:
            return 0
        
        with self.get_connection() as conn:
            if hostname and ip_address:
                # Remove by both hostname and IP
                cursor = conn.execute('SELECT agent_id FROM agents WHERE hostname = ? OR ip_address = ?', (hostname, ip_address))
            elif hostname:
                # Remove by hostname only
                cursor = conn.execute('SELECT agent_id FROM agents WHERE hostname = ?', (hostname,))
            else:
                # Remove by IP only
                cursor = conn.execute('SELECT agent_id FROM agents WHERE ip_address = ?', (ip_address,))
            
            agent_ids = [row[0] for row in cursor.fetchall()]
            
            # Remove all related data for each agent
            for agent_id in agent_ids:
                conn.execute('DELETE FROM agent_logs WHERE agent_id = ?', (agent_id,))
                conn.execute('DELETE FROM agent_scan_results WHERE agent_id = ?', (agent_id,))
                conn.execute('DELETE FROM agent_configs WHERE agent_id = ?', (agent_id,))
            
            # Remove the agents themselves
            if hostname and ip_address:
                conn.execute('DELETE FROM agents WHERE hostname = ? OR ip_address = ?', (hostname, ip_address))
            elif hostname:
                conn.execute('DELETE FROM agents WHERE hostname = ?', (hostname,))
            else:
                conn.execute('DELETE FROM agents WHERE ip_address = ?', (ip_address,))
            
            conn.commit()
            return len(agent_ids)
    
    def cleanup_duplicate_agents(self):
        """Remove duplicate agent entries, keeping the most recent one for each hostname/IP combination"""
        with self.get_connection() as conn:
            # Find duplicates by hostname
            cursor = conn.execute('''
                SELECT hostname, COUNT(*) as count
                FROM agents 
                GROUP BY hostname 
                HAVING COUNT(*) > 1
            ''')
            hostname_duplicates = cursor.fetchall()
            
            # Find duplicates by IP address
            cursor = conn.execute('''
                SELECT ip_address, COUNT(*) as count
                FROM agents 
                GROUP BY ip_address 
                HAVING COUNT(*) > 1
            ''')
            ip_duplicates = cursor.fetchall()
            
            removed_count = 0
            
            # Remove hostname duplicates, keep the most recent
            for hostname, count in hostname_duplicates:
                cursor = conn.execute('''
                    SELECT agent_id, created_at 
                    FROM agents 
                    WHERE hostname = ? 
                    ORDER BY created_at DESC
                ''', (hostname,))
                agents = cursor.fetchall()
                
                # Keep the first (most recent), remove the rest
                for agent_id, created_at in agents[1:]:
                    conn.execute('DELETE FROM agent_logs WHERE agent_id = ?', (agent_id,))
                    conn.execute('DELETE FROM agent_scan_results WHERE agent_id = ?', (agent_id,))
                    conn.execute('DELETE FROM agent_configs WHERE agent_id = ?', (agent_id,))
                    conn.execute('DELETE FROM agents WHERE agent_id = ?', (agent_id,))
                    removed_count += 1
            
            # Remove IP duplicates, keep the most recent
            for ip_address, count in ip_duplicates:
                cursor = conn.execute('''
                    SELECT agent_id, created_at 
                    FROM agents 
                    WHERE ip_address = ? 
                    ORDER BY created_at DESC
                ''', (ip_address,))
                agents = cursor.fetchall()
                
                # Keep the first (most recent), remove the rest
                for agent_id, created_at in agents[1:]:
                    # Check if this agent wasn't already removed by hostname cleanup
                    cursor = conn.execute('SELECT 1 FROM agents WHERE agent_id = ?', (agent_id,))
                    if cursor.fetchone():
                        conn.execute('DELETE FROM agent_logs WHERE agent_id = ?', (agent_id,))
                        conn.execute('DELETE FROM agent_scan_results WHERE agent_id = ?', (agent_id,))
                        conn.execute('DELETE FROM agent_configs WHERE agent_id = ?', (agent_id,))
                        conn.execute('DELETE FROM agents WHERE agent_id = ?', (agent_id,))
                        removed_count += 1
            
            conn.commit()
            return removed_count
    
    def cleanup_stale_agents(self, hours=24):
        """Remove agents that haven't sent a heartbeat in the specified hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            # Find stale agents
            cursor = conn.execute('''
                SELECT agent_id FROM agents 
                WHERE last_heartbeat IS NULL OR last_heartbeat < ?
            ''', (cutoff,))
            agent_ids = [row[0] for row in cursor.fetchall()]
            
            # Remove all related data for each stale agent
            for agent_id in agent_ids:
                conn.execute('DELETE FROM agent_logs WHERE agent_id = ?', (agent_id,))
                conn.execute('DELETE FROM agent_scan_results WHERE agent_id = ?', (agent_id,))
                conn.execute('DELETE FROM agent_configs WHERE agent_id = ?', (agent_id,))
                conn.execute('DELETE FROM agents WHERE agent_id = ?', (agent_id,))
            
            conn.commit()
            return len(agent_ids)
    
    # Agent configuration management
    def save_agent_config(self, agent_id, server_url, scan_interval=300, heartbeat_interval=60,
                         log_collection_enabled=True, log_paths='/var/log', scan_enabled=True):
        """Save agent configuration"""
        with self.get_connection() as conn:
            # Check if config exists
            cursor = conn.execute('SELECT id FROM agent_configs WHERE agent_id = ?', (agent_id,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing config
                conn.execute('''
                    UPDATE agent_configs 
                    SET server_url = ?, scan_interval = ?, heartbeat_interval = ?,
                        log_collection_enabled = ?, log_paths = ?, scan_enabled = ?,
                        config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                ''', (server_url, scan_interval, heartbeat_interval, log_collection_enabled,
                     log_paths, scan_enabled, agent_id))
            else:
                # Insert new config
                conn.execute('''
                    INSERT INTO agent_configs 
                    (agent_id, server_url, scan_interval, heartbeat_interval, 
                     log_collection_enabled, log_paths, scan_enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (agent_id, server_url, scan_interval, heartbeat_interval,
                     log_collection_enabled, log_paths, scan_enabled))
            
            conn.commit()
    
    def get_agent_config(self, agent_id):
        """Get agent configuration"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM agent_configs WHERE agent_id = ?', (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    # Agent logs management
    def save_agent_logs(self, agent_id, logs):
        """Save logs from agent"""
        with self.get_connection() as conn:
            for log_entry in logs:
                conn.execute('''
                    INSERT INTO agent_logs 
                    (agent_id, log_source, log_level, message, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                ''', (agent_id, log_entry.get('source'), log_entry.get('level'),
                     log_entry.get('message'), log_entry.get('timestamp')))
            conn.commit()
    
    def get_agent_logs(self, agent_id=None, hours=24, limit=1000):
        """Get agent logs"""
        cutoff = datetime.now() - timedelta(hours=hours)
        
        with self.get_connection() as conn:
            if agent_id:
                cursor = conn.execute('''
                    SELECT al.*, a.hostname 
                    FROM agent_logs al
                    JOIN agents a ON al.agent_id = a.agent_id
                    WHERE al.agent_id = ? AND al.collected_at > ?
                    ORDER BY al.timestamp DESC, al.collected_at DESC
                    LIMIT ?
                ''', (agent_id, cutoff, limit))
            else:
                cursor = conn.execute('''
                    SELECT al.*, a.hostname 
                    FROM agent_logs al
                    JOIN agents a ON al.agent_id = a.agent_id
                    WHERE al.collected_at > ?
                    ORDER BY al.timestamp DESC, al.collected_at DESC
                    LIMIT ?
                ''', (cutoff, limit))
            
            return [dict(row) for row in cursor.fetchall()]
    
    # Agent scan results management
    def save_agent_scan_result(self, agent_id, scan_type, scan_data):
        """Save scan results from agent"""
        with self.get_connection() as conn:
            conn.execute('''
                INSERT INTO agent_scan_results (agent_id, scan_type, scan_data)
                VALUES (?, ?, ?)
            ''', (agent_id, scan_type, json.dumps(scan_data)))
            conn.commit()
    
    def get_unprocessed_agent_scans(self):
        """Get unprocessed agent scan results"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM agent_scan_results 
                WHERE processed = 0 
                ORDER BY scan_timestamp ASC
            ''')
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['scan_data'] = json.loads(result['scan_data'])
                except json.JSONDecodeError:
                    result['scan_data'] = {}
                results.append(result)
            return results
    
    def mark_agent_scan_processed(self, scan_id):
        """Mark agent scan result as processed"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agent_scan_results 
                SET processed = 1 
                WHERE id = ?
            ''', (scan_id,))
            conn.commit()
    
    def get_agent_stats(self):
        """Get agent statistics"""
        with self.get_connection() as conn:
            # Total agents
            cursor = conn.execute('SELECT COUNT(*) as total_agents FROM agents')
            total_agents = cursor.fetchone()['total_agents']
            
            # Active agents
            cursor = conn.execute("SELECT COUNT(*) as active_agents FROM agents WHERE status = 'active'")
            active_agents = cursor.fetchone()['active_agents']
            
            # Agents with recent heartbeat (last 5 minutes)
            cutoff = datetime.now() - timedelta(minutes=5)
            cursor = conn.execute('''
                SELECT COUNT(*) as recent_heartbeats 
                FROM agents WHERE last_heartbeat > ?
            ''', (cutoff,))
            recent_heartbeats = cursor.fetchone()['recent_heartbeats']
            
            # Recent log entries (last hour)
            log_cutoff = datetime.now() - timedelta(hours=1)
            cursor = conn.execute('''
                SELECT COUNT(*) as recent_logs 
                FROM agent_logs WHERE collected_at > ?
            ''', (log_cutoff,))
            recent_logs = cursor.fetchone()['recent_logs']
            
            return {
                'total_agents': total_agents,
                'active_agents': active_agents,
                'recent_heartbeats': recent_heartbeats,
                'recent_logs': recent_logs
            }
