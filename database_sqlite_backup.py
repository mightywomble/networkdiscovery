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
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        try:
            yield conn
        finally:
            conn.close()
    
    def init_db(self):
        """Initialize database tables"""
        print(f"DEBUG: Initializing database at {self.db_path}")
        try:
            with self.get_connection() as conn:
                print("DEBUG: Got database connection")
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
                        test_configuration TEXT DEFAULT NULL,
                        config_version INTEGER DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                    )
                ''')
                
                # Update existing agent_configs table to add test_configuration column if it doesn't exist
                try:
                    conn.execute('ALTER TABLE agent_configs ADD COLUMN test_configuration TEXT DEFAULT NULL')
                except:
                    pass  # Column already exists
                
                # Update agents table to add version tracking columns if they don't exist
                try:
                    conn.execute('ALTER TABLE agents ADD COLUMN build_date TEXT DEFAULT NULL')
                except:
                    pass  # Column already exists
                
                try:
                    conn.execute('ALTER TABLE agents ADD COLUMN last_update_date TIMESTAMP DEFAULT NULL')
                except:
                    pass  # Column already exists
                    
                try:
                    conn.execute('ALTER TABLE agents ADD COLUMN platform TEXT DEFAULT NULL')
                except:
                    pass  # Column already exists
                
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
                
                # AI API settings
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ai_api_settings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        provider TEXT UNIQUE NOT NULL,
                        api_key TEXT,
                        model_name TEXT,
                        api_endpoint TEXT,
                        temperature REAL DEFAULT 0.7,
                        max_tokens INTEGER DEFAULT 1000,
                        timeout INTEGER DEFAULT 30,
                        enabled BOOLEAN DEFAULT 0,
                        additional_config TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Update existing ai_api_settings table structure if needed
                try:
                    conn.execute('ALTER TABLE ai_api_settings ADD COLUMN additional_config TEXT DEFAULT NULL')
                except:
                    pass  # Column already exists
                    
                try:
                    conn.execute('ALTER TABLE ai_api_settings ADD COLUMN enabled BOOLEAN DEFAULT 0')
                except:
                    pass  # Column already exists
                
                conn.commit()
                print("DEBUG: Database initialization completed successfully")
        except Exception as e:
            print(f"ERROR: Database initialization failed: {e}")
            import traceback
            traceback.print_exc()
            raise
    
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
    def register_agent(self, agent_id, hostname, ip_address, username, agent_version=None, host_id=None, platform=None):
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
                        host_id = ?, platform = ?, status = 'active', updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                ''', (hostname, ip_address, username, agent_version, host_id, platform, agent_id))
            else:
                # Insert new agent
                conn.execute('''
                    INSERT INTO agents 
                    (agent_id, hostname, ip_address, username, agent_version, host_id, platform, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
                ''', (agent_id, hostname, ip_address, username, agent_version, host_id, platform))
            
            conn.commit()
    
    def update_agent_heartbeat(self, agent_id, status='active', error_message=None, agent_version=None, build_date=None):
        """Update agent heartbeat and status"""
        with self.get_connection() as conn:
            if agent_version and build_date:
                conn.execute('''
                    UPDATE agents 
                    SET last_heartbeat = CURRENT_TIMESTAMP, status = ?, error_message = ?,
                        agent_version = ?, build_date = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                ''', (status, error_message, agent_version, build_date, agent_id))
            else:
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
                         log_collection_enabled=True, log_paths='/var/log', scan_enabled=True, test_configuration=None):
        """Save agent configuration"""
        with self.get_connection() as conn:
            # Check if config exists
            cursor = conn.execute('SELECT id FROM agent_configs WHERE agent_id = ?', (agent_id,))
            existing = cursor.fetchone()
            
            # Convert test_configuration to JSON if provided
            test_config_json = json.dumps(test_configuration) if test_configuration is not None else None
            
            if existing:
                # Update existing config
                conn.execute('''
                    UPDATE agent_configs 
                    SET server_url = ?, scan_interval = ?, heartbeat_interval = ?,
                        log_collection_enabled = ?, log_paths = ?, scan_enabled = ?,
                        test_configuration = ?, config_version = config_version + 1, updated_at = CURRENT_TIMESTAMP
                    WHERE agent_id = ?
                ''', (server_url, scan_interval, heartbeat_interval, log_collection_enabled,
                     log_paths, scan_enabled, test_config_json, agent_id))
            else:
                # Insert new config
                conn.execute('''
                    INSERT INTO agent_configs 
                    (agent_id, server_url, scan_interval, heartbeat_interval, 
                     log_collection_enabled, log_paths, scan_enabled, test_configuration)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (agent_id, server_url, scan_interval, heartbeat_interval,
                     log_collection_enabled, log_paths, scan_enabled, test_config_json))
            
            conn.commit()
    
    def get_agent_config(self, agent_id):
        """Get agent configuration"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM agent_configs WHERE agent_id = ?', (agent_id,))
            row = cursor.fetchone()
            if row:
                config = dict(row)
                # Parse test_configuration JSON if present
                if config.get('test_configuration'):
                    try:
                        config['test_configuration'] = json.loads(config['test_configuration'])
                    except json.JSONDecodeError:
                        config['test_configuration'] = None
                return config
            return None
    
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
    
    def update_agent_version(self, agent_id, agent_version, build_date=None):
        """Update agent version and build date"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET agent_version = ?, build_date = ?, last_update_date = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (agent_version, build_date, agent_id))
            conn.commit()
    
    def mark_agent_update_started(self, agent_id):
        """Mark that an agent update has started"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET status = 'updating', error_message = NULL, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (agent_id,))
            conn.commit()
    
    def mark_agent_update_completed(self, agent_id, agent_version, build_date):
        """Mark that an agent update has completed successfully"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET status = 'active', agent_version = ?, build_date = ?, 
                    last_update_date = CURRENT_TIMESTAMP, error_message = NULL,
                    updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (agent_version, build_date, agent_id))
            conn.commit()
    
    def mark_agent_update_failed(self, agent_id, error_message):
        """Mark that an agent update has failed"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE agents 
                SET status = 'update_failed', error_message = ?, updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = ?
            ''', (error_message, agent_id))
            conn.commit()
    
    def get_agents_by_version(self, agent_version=None):
        """Get agents filtered by version"""
        with self.get_connection() as conn:
            if agent_version:
                cursor = conn.execute('''
                    SELECT a.*, h.name as host_name 
                    FROM agents a
                    LEFT JOIN hosts h ON a.host_id = h.id
                    WHERE a.agent_version = ?
                    ORDER BY a.hostname
                ''', (agent_version,))
            else:
                cursor = conn.execute('''
                    SELECT a.*, h.name as host_name 
                    FROM agents a
                    LEFT JOIN hosts h ON a.host_id = h.id
                    WHERE a.agent_version IS NULL
                    ORDER BY a.hostname
                ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_agent_version_summary(self):
        """Get summary of agent versions"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT 
                    agent_version,
                    build_date,
                    COUNT(*) as count,
                    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_count
                FROM agents 
                GROUP BY agent_version, build_date
                ORDER BY agent_version DESC, build_date DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_latest_agent_scan_results(self, agent_id):
        """Get the latest scan results for an agent"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM agent_scan_results 
                WHERE agent_id = ?
                ORDER BY scan_timestamp DESC
                LIMIT 1
            ''', (agent_id,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                try:
                    result['scan_data'] = json.loads(result['scan_data'])
                except json.JSONDecodeError:
                    result['scan_data'] = {}
                return result
            return None
    
    def get_agent_scan_results(self, agent_id, limit=10):
        """Get scan results for an agent with optional limit"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM agent_scan_results 
                WHERE agent_id = ?
                ORDER BY scan_timestamp DESC
                LIMIT ?
            ''', (agent_id, limit))
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['scan_data'] = json.loads(result['scan_data'])
                except json.JSONDecodeError:
                    result['scan_data'] = {}
                results.append(result)
            return results
    
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
    
    # Advanced statistics methods for the statistics dashboard
    def get_network_overview_stats(self):
        """Get comprehensive network overview statistics"""
        with self.get_connection() as conn:
            stats = {}
            
            # Host statistics
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_hosts,
                    COUNT(CASE WHEN status = 'online' THEN 1 END) as online_hosts,
                    COUNT(CASE WHEN status = 'offline' THEN 1 END) as offline_hosts,
                    COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as active_last_hour,
                    COUNT(CASE WHEN last_seen > datetime('now', '-24 hour') THEN 1 END) as active_last_day
                FROM hosts
            ''')
            stats['hosts'] = dict(cursor.fetchone())
            
            # Connection statistics
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(DISTINCT source_host_id) as hosts_with_connections,
                    SUM(connection_count) as total_connection_count,
                    SUM(bytes_sent) as total_bytes_sent,
                    SUM(bytes_received) as total_bytes_received,
                    COUNT(CASE WHEN last_seen > datetime('now', '-1 hour') THEN 1 END) as active_last_hour
                FROM network_connections
            ''')
            stats['connections'] = dict(cursor.fetchone())
            
            # Convert None values to 0
            for key in stats['connections']:
                if stats['connections'][key] is None:
                    stats['connections'][key] = 0
            
            # Port statistics
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_open_ports,
                    COUNT(DISTINCT host_id) as hosts_with_open_ports,
                    COUNT(DISTINCT port) as unique_ports
                FROM port_scans
                WHERE state = 'open'
            ''')
            stats['ports'] = dict(cursor.fetchone())
            
            # Agent statistics
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_agents,
                    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_agents,
                    COUNT(CASE WHEN last_heartbeat > datetime('now', '-10 minute') THEN 1 END) as recently_active,
                    COUNT(DISTINCT hostname) as unique_hosts
                FROM agents
            ''')
            stats['agents'] = dict(cursor.fetchone())
            
            # Recent scan statistics
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as total_scans,
                    COUNT(DISTINCT agent_id) as unique_agents,
                    COUNT(CASE WHEN scan_timestamp > datetime('now', '-24 hour') THEN 1 END) as scans_last_day,
                    COUNT(CASE WHEN scan_timestamp > datetime('now', '-1 hour') THEN 1 END) as scans_last_hour
                FROM agent_scan_results
            ''')
            stats['scans'] = dict(cursor.fetchone())
            
            return stats
    
    def get_lan_vs_external_stats(self, local_subnets=None):
        """Get statistics comparing LAN vs external network connections
        
        Args:
            local_subnets: List of local subnet CIDR patterns (e.g. ['192.168.%', '10.%'])
                           If None, will use common private IP patterns
        """
        if local_subnets is None:
            # Default local subnet patterns
            local_subnets = ['192.168.%', '10.%', '172.1_.%', '172.2_.%', '172.3_.%', '127.%']
        
        with self.get_connection() as conn:
            results = {
                'lan': {},
                'external': {},
                'total': {},
                'ratios': {}
            }
            
            # Build the SQL WHERE clause for local subnets
            local_conditions = []
            for subnet in local_subnets:
                local_conditions.append(f"dest_ip LIKE '{subnet}'")
            local_where = " OR ".join(local_conditions)
            
            # LAN connections
            cursor = conn.execute(f'''
                SELECT 
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT source_host_id) as source_hosts,
                    COUNT(DISTINCT dest_ip) as destination_ips,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received,
                    COUNT(DISTINCT dest_port) as unique_ports
                FROM network_connections
                WHERE {local_where}
            ''')
            results['lan'] = dict(cursor.fetchone())
            
            # External connections (not matching local subnets)
            cursor = conn.execute(f'''
                SELECT 
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT source_host_id) as source_hosts,
                    COUNT(DISTINCT dest_ip) as destination_ips,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received,
                    COUNT(DISTINCT dest_port) as unique_ports
                FROM network_connections
                WHERE NOT ({local_where})
            ''')
            results['external'] = dict(cursor.fetchone())
            
            # Total connections
            cursor = conn.execute('''
                SELECT 
                    COUNT(*) as connection_count,
                    COUNT(DISTINCT source_host_id) as source_hosts,
                    COUNT(DISTINCT dest_ip) as destination_ips,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received,
                    COUNT(DISTINCT dest_port) as unique_ports
                FROM network_connections
            ''')
            results['total'] = dict(cursor.fetchone())
            
            # Convert None values to 0
            for category in ['lan', 'external', 'total']:
                for key in results[category]:
                    if results[category][key] is None:
                        results[category][key] = 0
            
            # Calculate ratios
            if results['total']['connection_count'] > 0:
                results['ratios']['lan_pct'] = round(results['lan']['connection_count'] / results['total']['connection_count'] * 100, 1)
                results['ratios']['external_pct'] = round(results['external']['connection_count'] / results['total']['connection_count'] * 100, 1)
            else:
                results['ratios']['lan_pct'] = 0
                results['ratios']['external_pct'] = 0
                
            if results['total']['bytes_sent'] > 0:
                results['ratios']['lan_bytes_pct'] = round((results['lan']['bytes_sent'] + results['lan']['bytes_received']) / 
                                                   (results['total']['bytes_sent'] + results['total']['bytes_received']) * 100, 1)
                results['ratios']['external_bytes_pct'] = round((results['external']['bytes_sent'] + results['external']['bytes_received']) / 
                                                      (results['total']['bytes_sent'] + results['total']['bytes_received']) * 100, 1)
            else:
                results['ratios']['lan_bytes_pct'] = 0
                results['ratios']['external_bytes_pct'] = 0
            
            return results
    
    def get_historical_connection_stats(self, time_periods=None):
        """Get historical connection statistics over different time periods
        
        Args:
            time_periods: List of time periods in hours to analyze.
                         If None, will use [1, 6, 24, 72, 168] (1 hour, 6 hours, 1 day, 3 days, 1 week)
        """
        if time_periods is None:
            time_periods = [1, 6, 24, 72, 168]  # hours
        
        results = {}
        
        with self.get_connection() as conn:
            for hours in time_periods:
                period_name = f"{hours}h"
                if hours == 24:
                    period_name = "1d"  # 1 day
                elif hours == 168:
                    period_name = "1w"  # 1 week
                elif hours == 72:
                    period_name = "3d"  # 3 days
                
                cutoff = datetime.now() - timedelta(hours=hours)
                
                cursor = conn.execute('''
                    SELECT 
                        COUNT(*) as connections,
                        COUNT(DISTINCT source_host_id) as active_hosts,
                        COUNT(DISTINCT dest_ip) as dest_ips,
                        SUM(connection_count) as total_connects,
                        SUM(bytes_sent) as bytes_sent,
                        SUM(bytes_received) as bytes_received
                    FROM network_connections
                    WHERE last_seen > ?
                ''', (cutoff,))
                
                period_stats = dict(cursor.fetchone())
                
                # Convert None values to 0
                for key in period_stats:
                    if period_stats[key] is None:
                        period_stats[key] = 0
                
                # Add human-readable traffic volume
                period_stats['total_traffic_bytes'] = period_stats['bytes_sent'] + period_stats['bytes_received']
                period_stats['total_traffic'] = self._format_bytes(period_stats['total_traffic_bytes'])
                
                results[period_name] = period_stats
            
            return results
    
    def get_top_hosts_by_connections(self, limit=10):
        """Get top hosts by connection count"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT 
                    h.id as host_id,
                    h.name as host_name,
                    h.ip_address,
                    COUNT(nc.id) as connection_count,
                    SUM(nc.bytes_sent) as bytes_sent,
                    SUM(nc.bytes_received) as bytes_received,
                    COUNT(DISTINCT nc.dest_ip) as unique_destinations,
                    MAX(nc.last_seen) as last_activity
                FROM hosts h
                JOIN network_connections nc ON h.id = nc.source_host_id
                GROUP BY h.id
                ORDER BY connection_count DESC
                LIMIT ?
            ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                host_data = dict(row)
                host_data['total_traffic_bytes'] = host_data['bytes_sent'] + host_data['bytes_received']
                host_data['total_traffic'] = self._format_bytes(host_data['total_traffic_bytes'])
                results.append(host_data)
            
            return results
    
    def get_top_external_destinations(self, limit=10, local_subnets=None):
        """Get top external destinations by connection count
        
        Args:
            limit: Number of top destinations to return
            local_subnets: List of local subnet CIDR patterns (e.g. ['192.168.%', '10.%'])
                           If None, will use common private IP patterns
        """
        if local_subnets is None:
            # Default local subnet patterns
            local_subnets = ['192.168.%', '10.%', '172.1_.%', '172.2_.%', '172.3_.%', '127.%']
        
        # Build the SQL WHERE clause for non-local subnets
        local_conditions = []
        for subnet in local_subnets:
            local_conditions.append(f"dest_ip NOT LIKE '{subnet}'")
        external_where = " AND ".join(local_conditions)
        
        with self.get_connection() as conn:
            cursor = conn.execute(f'''
                SELECT 
                    dest_ip,
                    COUNT(*) as connection_count,
                    SUM(connection_count) as total_connections,
                    COUNT(DISTINCT source_host_id) as source_hosts,
                    COUNT(DISTINCT dest_port) as dest_ports,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received,
                    MAX(last_seen) as last_seen
                FROM network_connections
                WHERE {external_where}
                GROUP BY dest_ip
                ORDER BY connection_count DESC
                LIMIT ?
            ''', (limit,))
            
            results = []
            for row in cursor.fetchall():
                dest_data = dict(row)
                dest_data['total_traffic_bytes'] = dest_data['bytes_sent'] + dest_data['bytes_received']
                dest_data['total_traffic'] = self._format_bytes(dest_data['total_traffic_bytes'])
                results.append(dest_data)
            
            return results
    
    def get_connection_history_by_hour(self, hours=24):
        """Get connection history aggregated by hour for the last N hours"""
        with self.get_connection() as conn:
            results = []
            
            # Get hour boundaries from most recent connection down to X hours ago
            cutoff = datetime.now() - timedelta(hours=hours)
            
            # Query hourly connection stats
            cursor = conn.execute('''
                SELECT 
                    strftime('%Y-%m-%d %H:00:00', last_seen) as hour,
                    COUNT(*) as connections,
                    COUNT(DISTINCT source_host_id) as unique_hosts,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received
                FROM network_connections
                WHERE last_seen > ?
                GROUP BY strftime('%Y-%m-%d %H', last_seen)
                ORDER BY hour ASC
            ''', (cutoff,))
            
            for row in cursor.fetchall():
                hour_data = dict(row)
                hour_data['total_traffic_bytes'] = hour_data.get('bytes_sent', 0) + hour_data.get('bytes_received', 0)
                hour_data['total_traffic'] = self._format_bytes(hour_data['total_traffic_bytes'])
                results.append(hour_data)
            
            return results
    
    def get_host_activity_timeline(self, host_id, days=7):
        """Get timeline of host activity over the specified number of days"""
        with self.get_connection() as conn:
            cutoff = datetime.now() - timedelta(days=days)
            
            # Get daily connection stats for this host
            cursor = conn.execute('''
                SELECT 
                    strftime('%Y-%m-%d', last_seen) as date,
                    COUNT(*) as connections,
                    COUNT(DISTINCT dest_ip) as unique_destinations,
                    SUM(connection_count) as total_connections,
                    SUM(bytes_sent) as bytes_sent,
                    SUM(bytes_received) as bytes_received
                FROM network_connections
                WHERE source_host_id = ? AND last_seen > ?
                GROUP BY strftime('%Y-%m-%d', last_seen)
                ORDER BY date ASC
            ''', (host_id, cutoff))
            
            daily_stats = []
            for row in cursor.fetchall():
                day_data = dict(row)
                day_data['total_traffic_bytes'] = day_data.get('bytes_sent', 0) + day_data.get('bytes_received', 0)
                day_data['total_traffic'] = self._format_bytes(day_data['total_traffic_bytes'])
                daily_stats.append(day_data)
            
            # Get port scan history
            cursor = conn.execute('''
                SELECT 
                    strftime('%Y-%m-%d', scan_time) as date,
                    COUNT(*) as open_ports,
                    GROUP_CONCAT(DISTINCT port) as port_list
                FROM port_scans
                WHERE host_id = ? AND scan_time > ?
                GROUP BY strftime('%Y-%m-%d', scan_time)
                ORDER BY date ASC
            ''', (host_id, cutoff))
            
            port_history = [dict(row) for row in cursor.fetchall()]
            
            # Get agent scan history if this host has agents
            cursor = conn.execute('''
                SELECT agent_id FROM agents WHERE host_id = ?
            ''', (host_id,))
            
            agent_history = []
            for agent_row in cursor.fetchall():
                agent_id = agent_row[0]
                cursor = conn.execute('''
                    SELECT 
                        strftime('%Y-%m-%d', scan_timestamp) as date,
                        COUNT(*) as scan_count,
                        MAX(scan_timestamp) as last_scan
                    FROM agent_scan_results
                    WHERE agent_id = ? AND scan_timestamp > ?
                    GROUP BY strftime('%Y-%m-%d', scan_timestamp)
                    ORDER BY date ASC
                ''', (agent_id, cutoff))
                
                for row in cursor.fetchall():
                    agent_history.append(dict(row))
            
            return {
                'daily_connections': daily_stats,
                'port_history': port_history,
                'agent_scans': agent_history
            }
    
    # AI API settings management
    def save_ai_api_settings(self, provider, api_key=None, model_name=None, api_endpoint=None, 
                            temperature=0.7, max_tokens=1000, timeout=30, enabled=False, additional_config=None):
        """Save AI API settings for a provider"""
        with self.get_connection() as conn:
            # Check if settings exist for this provider
            cursor = conn.execute('SELECT id FROM ai_api_settings WHERE provider = ?', (provider,))
            existing = cursor.fetchone()
            
            # Convert additional_config to JSON if provided
            config_json = json.dumps(additional_config) if additional_config is not None else None
            
            if existing:
                # Update existing settings
                conn.execute('''
                    UPDATE ai_api_settings 
                    SET api_key = ?, model_name = ?, api_endpoint = ?, temperature = ?,
                        max_tokens = ?, timeout = ?, enabled = ?, additional_config = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE provider = ?
                ''', (api_key, model_name, api_endpoint, temperature, max_tokens, 
                     timeout, enabled, config_json, provider))
            else:
                # Insert new settings
                conn.execute('''
                    INSERT INTO ai_api_settings 
                    (provider, api_key, model_name, api_endpoint, temperature, max_tokens, 
                     timeout, enabled, additional_config)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (provider, api_key, model_name, api_endpoint, temperature, max_tokens,
                     timeout, enabled, config_json))
            
            conn.commit()
    
    def get_ai_api_settings(self, provider):
        """Get AI API settings for a specific provider"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings WHERE provider = ?', (provider,))
            row = cursor.fetchone()
            if row:
                settings = dict(row)
                # Parse additional_config JSON if present
                if settings.get('additional_config'):
                    try:
                        settings['additional_config'] = json.loads(settings['additional_config'])
                    except json.JSONDecodeError:
                        settings['additional_config'] = {}
                return settings
            return None
    
    def get_all_ai_api_settings(self):
        """Get all AI API settings"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings ORDER BY provider')
            settings_list = []
            for row in cursor.fetchall():
                settings = dict(row)
                # Parse additional_config JSON if present
                if settings.get('additional_config'):
                    try:
                        settings['additional_config'] = json.loads(settings['additional_config'])
                    except json.JSONDecodeError:
                        settings['additional_config'] = {}
                else:
                    settings['additional_config'] = {}
                settings_list.append(settings)
            return settings_list
    
    def delete_ai_api_settings(self, provider):
        """Delete AI API settings for a provider"""
        with self.get_connection() as conn:
            cursor = conn.execute('DELETE FROM ai_api_settings WHERE provider = ?', (provider,))
            conn.commit()
            return cursor.rowcount > 0
    
    def enable_ai_api(self, provider, enabled=True):
        """Enable or disable AI API for a provider"""
        with self.get_connection() as conn:
            conn.execute('''
                UPDATE ai_api_settings 
                SET enabled = ?, updated_at = CURRENT_TIMESTAMP
                WHERE provider = ?
            ''', (enabled, provider))
            conn.commit()
    
    def get_enabled_ai_apis(self):
        """Get all enabled AI API providers"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM ai_api_settings WHERE enabled = 1 ORDER BY provider')
            settings_list = []
            for row in cursor.fetchall():
                settings = dict(row)
                # Parse additional_config JSON if present  
                if settings.get('additional_config'):
                    try:
                        settings['additional_config'] = json.loads(settings['additional_config'])
                    except json.JSONDecodeError:
                        settings['additional_config'] = {}
                else:
                    settings['additional_config'] = {}
                settings_list.append(settings)
            return settings_list
    
    # Chatbot database methods
    def save_chatbot_conversation(self, conversation):
        """Save or update chatbot conversation"""
        with self.get_connection() as conn:
            metadata = json.dumps(conversation) if isinstance(conversation, dict) else '{}'
            
            # Check if conversation exists
            cursor = conn.execute('SELECT id FROM chatbot_conversations WHERE id = ?', (conversation['id'],))
            if cursor.fetchone():
                # Update existing conversation
                conn.execute('''
                    UPDATE chatbot_conversations 
                    SET state = ?, updated_at = ?, metadata = ?
                    WHERE id = ?
                ''', (
                    conversation.get('state', 'initial'),
                    conversation.get('updated_at', datetime.now().isoformat()),
                    metadata,
                    conversation['id']
                ))
            else:
                # Insert new conversation
                conn.execute('''
                    INSERT INTO chatbot_conversations (id, user_id, state, created_at, updated_at, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    conversation['id'],
                    conversation.get('user_id'),
                    conversation.get('state', 'initial'),
                    conversation.get('created_at', datetime.now().isoformat()),
                    conversation.get('updated_at', datetime.now().isoformat()),
                    metadata
                ))
            
            # Save messages
            for message in conversation.get('messages', []):
                self.save_chatbot_message(message, conversation['id'])
            
            conn.commit()
    
    def save_chatbot_message(self, message, conversation_id):
        """Save a chatbot message"""
        with self.get_connection() as conn:
            metadata = json.dumps(message.get('metadata', {}))
            
            # Check if message exists
            cursor = conn.execute('SELECT id FROM chatbot_messages WHERE id = ?', (message['id'],))
            if cursor.fetchone():
                # Update existing message
                conn.execute('''
                    UPDATE chatbot_messages 
                    SET content = ?, metadata = ?
                    WHERE id = ?
                ''', (
                    message.get('content', ''),
                    metadata,
                    message['id']
                ))
            else:
                # Insert new message
                conn.execute('''
                    INSERT INTO chatbot_messages (id, conversation_id, message_type, content, timestamp, metadata)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    message['id'],
                    conversation_id,
                    message.get('type', 'bot'),
                    message.get('content', ''),
                    message.get('timestamp', datetime.now().isoformat()),
                    metadata
                ))
            
            conn.commit()
    
    def get_chatbot_conversation(self, conversation_id):
        """Get a chatbot conversation by ID"""
        with self.get_connection() as conn:
            # Get conversation
            cursor = conn.execute('SELECT * FROM chatbot_conversations WHERE id = ?', (conversation_id,))
            conversation_row = cursor.fetchone()
            
            if not conversation_row:
                return None
            
            # Get messages
            cursor = conn.execute('''
                SELECT * FROM chatbot_messages 
                WHERE conversation_id = ? 
                ORDER BY timestamp
            ''', (conversation_id,))
            message_rows = cursor.fetchall()
            
            # Convert to dict
            conversation = dict(conversation_row)
            
            # Parse metadata
            try:
                metadata = json.loads(conversation.get('metadata', '{}'))
                conversation.update(metadata)
            except:
                conversation['metadata'] = {}
            
            # Add messages
            conversation['messages'] = []
            for message_row in message_rows:
                message = dict(message_row)
                
                # Parse metadata
                try:
                    message_metadata = json.loads(message.get('metadata', '{}'))
                    message['metadata'] = message_metadata
                except:
                    message['metadata'] = {}
                
                conversation['messages'].append(message)
            
            return conversation
    
    # Helper methods
    def _format_bytes(self, bytes_value):
        """Format bytes into human-readable format"""
        if bytes_value is None:
            return "0 B"
            
        bytes_value = int(bytes_value)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024 or unit == 'TB':
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024

    # Application settings management
    def save_application_setting(self, setting_key, setting_value, setting_type='string', description=None):
        """Save or update an application setting"""
        with self.get_connection() as conn:
            # Convert value to string for storage
            value_str = str(setting_value) if setting_value is not None else None
            
            # Check if setting exists
            cursor = conn.execute('SELECT id FROM application_settings WHERE setting_key = ?', (setting_key,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing setting
                conn.execute('''
                    UPDATE application_settings 
                    SET setting_value = ?, setting_type = ?, description = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE setting_key = ?
                ''', (value_str, setting_type, description, setting_key))
            else:
                # Insert new setting
                conn.execute('''
                    INSERT INTO application_settings 
                    (setting_key, setting_value, setting_type, description)
                    VALUES (?, ?, ?, ?)
                ''', (setting_key, value_str, setting_type, description))
            
            conn.commit()
    
    def get_application_setting(self, setting_key, default_value=None):
        """Get an application setting by key"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM application_settings WHERE setting_key = ?', (setting_key,))
            row = cursor.fetchone()
            
            if row:
                setting = dict(row)
                # Convert value based on type
                value_str = setting.get('setting_value')
                setting_type = setting.get('setting_type', 'string')
                
                if value_str is None:
                    return default_value
                
                # Type conversion
                if setting_type == 'boolean':
                    return value_str.lower() in ('true', '1', 'yes', 'on')
                elif setting_type == 'integer':
                    try:
                        return int(value_str)
                    except ValueError:
                        return default_value
                elif setting_type == 'float':
                    try:
                        return float(value_str)
                    except ValueError:
                        return default_value
                elif setting_type == 'json':
                    try:
                        return json.loads(value_str)
                    except json.JSONDecodeError:
                        return default_value
                else:  # string
                    return value_str
            
            return default_value
    
    def get_all_application_settings(self):
        """Get all application settings"""
        with self.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM application_settings ORDER BY setting_key')
            settings = {}
            
            for row in cursor.fetchall():
                setting = dict(row)
                key = setting['setting_key']
                value_str = setting.get('setting_value')
                setting_type = setting.get('setting_type', 'string')
                
                # Type conversion
                if value_str is None:
                    value = None
                elif setting_type == 'boolean':
                    value = value_str.lower() in ('true', '1', 'yes', 'on')
                elif setting_type == 'integer':
                    try:
                        value = int(value_str)
                    except ValueError:
                        value = value_str
                elif setting_type == 'float':
                    try:
                        value = float(value_str)
                    except ValueError:
                        value = value_str
                elif setting_type == 'json':
                    try:
                        value = json.loads(value_str)
                    except json.JSONDecodeError:
                        value = value_str
                else:  # string
                    value = value_str
                
                settings[key] = {
                    'value': value,
                    'type': setting_type,
                    'description': setting.get('description'),
                    'created_at': setting.get('created_at'),
                    'updated_at': setting.get('updated_at')
                }
            
            return settings
    
    def delete_application_setting(self, setting_key):
        """Delete an application setting"""
        with self.get_connection() as conn:
            cursor = conn.execute('DELETE FROM application_settings WHERE setting_key = ?', (setting_key,))
            conn.commit()
            return cursor.rowcount > 0
    
    def initialize_default_settings(self):
        """Initialize default application settings if they don't exist"""
        defaults = {
            'chatbot.minimum_agent_version': {
                'value': '1.6.0',
                'type': 'string',
                'description': 'Minimum agent version required for AI chatbot script execution'
            },
            'chatbot.require_version_check': {
                'value': True,
                'type': 'boolean',
                'description': 'Whether to enforce minimum agent version checking for chatbot scripts'
            },
            'chatbot.script_timeout': {
                'value': 300,
                'type': 'integer',
                'description': 'Default timeout for chatbot script execution (seconds)'
            },
            'chatbot.max_concurrent_executions': {
                'value': 5,
                'type': 'integer',
                'description': 'Maximum number of concurrent script executions allowed'
            }
        }
        
        for key, config in defaults.items():
            # Only set if not already exists
            existing = self.get_application_setting(key)
            if existing is None:
                self.save_application_setting(
                    key, 
                    config['value'], 
                    config['type'], 
                    config['description']
                )
