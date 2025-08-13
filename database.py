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
            return [dict(row) for row in cursor.fetchall()]
    
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
