#!/usr/bin/env python3
"""
Database module for Network Map application
Handles PostgreSQL storage of hosts, connections, and statistics
"""

import psycopg2
import psycopg2.extras
import os
from datetime import datetime, timedelta
from contextlib import contextmanager
import json
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Database:
    def __init__(self, db_config=None):
        """Initialize with PostgreSQL configuration"""
        if db_config is None:
            self.db_config = {
                'host': 'localhost',
                'database': 'networkmap',
                'user': 'networkmap',
                'password': 'networkmap123',
                'port': 5432
            }
        else:
            self.db_config = db_config
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = None
        try:
            conn = psycopg2.connect(**self.db_config)
            conn.autocommit = True  # Enable autocommit for PostgreSQL
            yield conn
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()
    
    def init_db(self):
        """Initialize database tables"""
        logger.info("Initializing PostgreSQL database")
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Hosts table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS hosts (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    username VARCHAR(255) DEFAULT 'root',
                    ssh_port INTEGER DEFAULT 22,
                    description TEXT,
                    status VARCHAR(50) DEFAULT 'unknown',
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Network connections table
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_connections (
                    id SERIAL PRIMARY KEY,
                    source_host_id INTEGER REFERENCES hosts(id),
                    dest_host_id INTEGER REFERENCES hosts(id),
                    dest_ip VARCHAR(45),
                    dest_port INTEGER,
                    protocol VARCHAR(10),
                    connection_count INTEGER DEFAULT 1,
                    bytes_sent BIGINT DEFAULT 0,
                    bytes_received BIGINT DEFAULT 0,
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Port scan results
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS port_scans (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    port INTEGER,
                    service VARCHAR(255),
                    state VARCHAR(50),
                    version TEXT,
                    scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Network traffic statistics
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    bytes_in BIGINT DEFAULT 0,
                    bytes_out BIGINT DEFAULT 0,
                    packets_in INTEGER DEFAULT 0,
                    packets_out INTEGER DEFAULT 0,
                    connections_active INTEGER DEFAULT 0
                )
                ''')
                
                # System information
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS host_info (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER UNIQUE REFERENCES hosts(id),
                    hostname VARCHAR(255),
                    os_info TEXT,
                    kernel_version VARCHAR(255),
                    cpu_info TEXT,
                    memory_total BIGINT,
                    disk_info TEXT,
                    network_interfaces TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Network discovery data
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_discovery (
                    id SERIAL PRIMARY KEY,
                    host_id INTEGER REFERENCES hosts(id),
                    discovery_type VARCHAR(100),
                    discovery_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Topology analysis results
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS topology_analysis (
                    id SERIAL PRIMARY KEY,
                    analysis_type VARCHAR(100),
                    analysis_data TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Network diagram layouts
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS diagram_layouts (
                    id SERIAL PRIMARY KEY,
                    layout_name VARCHAR(255) DEFAULT 'default',
                    layout_data TEXT,
                    created_by VARCHAR(255) DEFAULT 'system',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Agent management
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS agents (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255) UNIQUE NOT NULL,
                    host_id INTEGER REFERENCES hosts(id),
                    hostname VARCHAR(255) NOT NULL,
                    ip_address VARCHAR(45) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    agent_version VARCHAR(50),
                    status VARCHAR(50) DEFAULT 'inactive',
                    last_heartbeat TIMESTAMP,
                    last_scan TIMESTAMP,
                    config_hash VARCHAR(255),
                    error_message TEXT,
                    build_date VARCHAR(50),
                    last_update_date TIMESTAMP,
                    platform VARCHAR(50),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Agent configuration
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_configs (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id),
                    server_url TEXT NOT NULL,
                    scan_interval INTEGER DEFAULT 300,
                    heartbeat_interval INTEGER DEFAULT 60,
                    log_collection_enabled BOOLEAN DEFAULT TRUE,
                    log_paths TEXT DEFAULT '/var/log',
                    scan_enabled BOOLEAN DEFAULT TRUE,
                    test_configuration TEXT,
                    config_version INTEGER DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Agent logs collection
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_logs (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id),
                    log_source VARCHAR(255) NOT NULL,
                    log_level VARCHAR(50),
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP,
                    collected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Agent scan results
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS agent_scan_results (
                    id SERIAL PRIMARY KEY,
                    agent_id VARCHAR(255) NOT NULL REFERENCES agents(agent_id),
                    scan_type VARCHAR(100) NOT NULL,
                    scan_data TEXT NOT NULL,
                    scan_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    processed BOOLEAN DEFAULT FALSE
                )
                ''')
                
                # AI API settings
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS ai_api_settings (
                    id SERIAL PRIMARY KEY,
                    provider VARCHAR(100) UNIQUE NOT NULL,
                    api_key TEXT,
                    model_name VARCHAR(255),
                    api_endpoint TEXT,
                    temperature REAL DEFAULT 0.7,
                    max_tokens INTEGER DEFAULT 1000,
                    timeout INTEGER DEFAULT 30,
                    enabled BOOLEAN DEFAULT FALSE,
                    additional_config TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Application settings
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS application_settings (
                    id SERIAL PRIMARY KEY,
                    setting_key VARCHAR(255) UNIQUE NOT NULL,
                    setting_value TEXT,
                    setting_type VARCHAR(50) DEFAULT 'string',
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Chatbot conversations
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS chatbot_conversations (
                    id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255),
                    state VARCHAR(50) DEFAULT 'initial',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
                ''')
                
                # Chatbot messages
                cursor.execute('''
                CREATE TABLE IF NOT EXISTS chatbot_messages (
                    id VARCHAR(255) PRIMARY KEY,
                    conversation_id VARCHAR(255) NOT NULL REFERENCES chatbot_conversations(id),
                    message_type VARCHAR(50) DEFAULT 'bot',
                    content TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    metadata TEXT
                )
                ''')
                
                # Create indexes for performance
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip_address)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_hostname ON agents(hostname)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_agents_version ON agents(agent_version)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_network_connections_source ON network_connections(source_host_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_chatbot_messages_conversation ON chatbot_messages(conversation_id)')
                
                # Initialize default application settings
                try:
                    self.initialize_default_settings()
                    logger.info("Default application settings initialized")
                except Exception as e:
                    logger.warning(f"Could not initialize default settings: {e}")
                
                logger.info("Database initialization completed successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    def initialize_default_settings(self):
        """Initialize default application settings"""
        default_settings = [
            ('chatbot_min_agent_version', '1.6.0', 'string', 'Minimum required agent version for chatbot script execution'),
            ('chatbot_version_check_enabled', 'true', 'boolean', 'Enable agent version checking before script execution'),
            ('chatbot_script_timeout', '300', 'integer', 'Script execution timeout in seconds'),
            ('chatbot_max_concurrent_executions', '5', 'integer', 'Maximum concurrent script executions'),
            ('chatbot_system_prompt', 'You are a helpful AI assistant for network administration and troubleshooting.', 'string', 'System prompt for chatbot AI responses')
        ]
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for key, value, type_, desc in default_settings:
                cursor.execute('''
                    INSERT INTO application_settings (setting_key, setting_value, setting_type, description)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (setting_key) DO NOTHING
                ''', (key, value, type_, desc))
    
    # Host management
    def add_host(self, name, ip_address, username='root', ssh_port=22, description=''):
        """Add a new host"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO hosts (name, ip_address, username, ssh_port, description)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id
            ''', (name, ip_address, username, ssh_port, description))
            return cursor.fetchone()[0]
    
    def get_host(self, host_id):
        """Get a specific host"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM hosts WHERE id = %s', (host_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_all_hosts(self):
        """Get all hosts"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM hosts ORDER BY name')
            hosts = []
            for row in cursor.fetchall():
                host = dict(row)
                hosts.append(host)
            return hosts
    
    def update_host_status(self, host_id, status, last_seen=None):
        """Update host status and last seen time"""
        if last_seen is None:
            last_seen = datetime.now()
        
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE hosts 
                SET status = %s, last_seen = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
            ''', (status, last_seen, host_id))
    
    def remove_host(self, host_id):
        """Remove a host and all related data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM traffic_stats WHERE host_id = %s', (host_id,))
            cursor.execute('DELETE FROM port_scans WHERE host_id = %s', (host_id,))
            cursor.execute('DELETE FROM host_info WHERE host_id = %s', (host_id,))
            cursor.execute('DELETE FROM network_connections WHERE source_host_id = %s OR dest_host_id = %s', 
                        (host_id, host_id))
            cursor.execute('DELETE FROM hosts WHERE id = %s', (host_id,))
    
    # Agent management methods
    def register_agent(self, agent_id, hostname, ip_address, username, agent_version=None):
        """Register or update an agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO agents (agent_id, hostname, ip_address, username, agent_version, status, last_heartbeat)
                VALUES (%s, %s, %s, %s, %s, 'active', CURRENT_TIMESTAMP)
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    ip_address = EXCLUDED.ip_address,
                    username = EXCLUDED.username,
                    agent_version = EXCLUDED.agent_version,
                    status = 'active',
                    last_heartbeat = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                RETURNING id
            ''', (agent_id, hostname, ip_address, username, agent_version))
            return cursor.fetchone()[0]
    
    def get_all_agents(self):
        """Get all agents"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM agents ORDER BY hostname')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_agent_by_id(self, agent_id):
        """Get agent by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM agents WHERE agent_id = %s', (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_agent_heartbeat(self, agent_id):
        """Update agent heartbeat"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE agents 
                SET last_heartbeat = CURRENT_TIMESTAMP, status = 'active'
                WHERE agent_id = %s
            ''', (agent_id,))
    
    def get_application_setting(self, key):
        """Get application setting value"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT setting_value FROM application_settings WHERE setting_key = %s', (key,))
            row = cursor.fetchone()
            return row[0] if row else None
    
    def save_application_setting(self, key, value, setting_type='string', description=None):
        """Save application setting"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO application_settings (setting_key, setting_value, setting_type, description)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (setting_key) DO UPDATE SET
                    setting_value = EXCLUDED.setting_value,
                    setting_type = EXCLUDED.setting_type,
                    description = COALESCE(EXCLUDED.description, application_settings.description),
                    updated_at = CURRENT_TIMESTAMP
            ''', (key, value, setting_type, description))
    
    def save_chatbot_conversation(self, conversation_id, user_id=None, state='initial', metadata=None):
        """Save or update chatbot conversation"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO chatbot_conversations (id, user_id, state, metadata)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    state = EXCLUDED.state,
                    metadata = EXCLUDED.metadata,
                    updated_at = CURRENT_TIMESTAMP
            ''', (conversation_id, user_id, state, json.dumps(metadata) if metadata else None))
    
    def get_chatbot_conversation(self, conversation_id):
        """Get chatbot conversation"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM chatbot_conversations WHERE id = %s', (conversation_id,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                if result.get('metadata'):
                    result['metadata'] = json.loads(result['metadata'])
                return result
            return None
    
    def save_chatbot_message(self, message_id, conversation_id, message_type, content, metadata=None):
        """Save chatbot message"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO chatbot_messages (id, conversation_id, message_type, content, metadata)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    content = EXCLUDED.content,
                    metadata = EXCLUDED.metadata
            ''', (message_id, conversation_id, message_type, content, json.dumps(metadata) if metadata else None))
    
    def get_chatbot_messages(self, conversation_id, limit=50):
        """Get chatbot messages for a conversation"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT * FROM chatbot_messages 
                WHERE conversation_id = %s 
                ORDER BY timestamp DESC 
                LIMIT %s
            ''', (conversation_id, limit))
            messages = []
            for row in cursor.fetchall():
                message = dict(row)
                if message.get('metadata'):
                    message['metadata'] = json.loads(message['metadata'])
                messages.append(message)
            return list(reversed(messages))  # Return in chronological order
    
    # Network connections
    def add_connection(self, source_host_id, dest_ip, dest_port, protocol, dest_host_id=None, 
                      bytes_sent=0, bytes_received=0):
        """Add or update a network connection"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Check if connection already exists
            cursor.execute('''
                SELECT id, connection_count FROM network_connections 
                WHERE source_host_id = %s AND dest_ip = %s AND dest_port = %s AND protocol = %s
            ''', (source_host_id, dest_ip, dest_port, protocol))
            
            existing = cursor.fetchone()
            if existing:
                # Update existing connection
                cursor.execute('''
                    UPDATE network_connections 
                    SET connection_count = connection_count + 1,
                        bytes_sent = bytes_sent + %s,
                        bytes_received = bytes_received + %s,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE id = %s
                ''', (bytes_sent, bytes_received, existing[0]))
                return existing[0]
            else:
                # Insert new connection
                cursor.execute('''
                    INSERT INTO network_connections 
                    (source_host_id, dest_host_id, dest_ip, dest_port, protocol, 
                     bytes_sent, bytes_received, connection_count)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                    RETURNING id
                ''', (source_host_id, dest_host_id, dest_ip, dest_port, protocol, bytes_sent, bytes_received))
                return cursor.fetchone()[0]
    
    def get_recent_connections(self, hours=24):
        """Get recent network connections"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT nc.*, h1.name as source_hostname, h2.name as dest_hostname
                FROM network_connections nc
                LEFT JOIN hosts h1 ON nc.source_host_id = h1.id
                LEFT JOIN hosts h2 ON nc.dest_host_id = h2.id
                WHERE nc.last_seen > CURRENT_TIMESTAMP - INTERVAL '%s hours'
                ORDER BY nc.last_seen DESC
            ''', (hours,))
            return [dict(row) for row in cursor.fetchall()]
    
    def save_port_scan(self, host_id, ports):
        """Save port scan results"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Clear previous scan results for this host
            cursor.execute('DELETE FROM port_scans WHERE host_id = %s', (host_id,))
            
            # Insert new scan results
            for port_info in ports:
                cursor.execute('''
                    INSERT INTO port_scans (host_id, port, service, state, version)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (host_id, port_info.get('port'), port_info.get('service'),
                     port_info.get('state'), port_info.get('version')))
    
    def get_host_ports(self, host_id):
        """Get port scan results for a host"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM port_scans WHERE host_id = %s ORDER BY port', (host_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def add_traffic_stats(self, host_id, bytes_in=0, bytes_out=0, packets_in=0, 
                         packets_out=0, connections_active=0):
        """Add traffic statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO traffic_stats 
                (host_id, bytes_in, bytes_out, packets_in, packets_out, connections_active)
                VALUES (%s, %s, %s, %s, %s, %s)
            ''', (host_id, bytes_in, bytes_out, packets_in, packets_out, connections_active))
    
    def get_traffic_stats(self, hours=24):
        """Get traffic statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('''
                SELECT ts.*, h.name as hostname
                FROM traffic_stats ts
                JOIN hosts h ON ts.host_id = h.id
                WHERE ts.timestamp > CURRENT_TIMESTAMP - INTERVAL '%s hours'
                ORDER BY ts.timestamp DESC
            ''', (hours,))
            return [dict(row) for row in cursor.fetchall()]
    
    def save_host_info(self, host_id, hostname, os_info, kernel_version, cpu_info, 
                      memory_total=0, disk_info='', network_interfaces=''):
        """Save host system information"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO host_info 
                (host_id, hostname, os_info, kernel_version, cpu_info, 
                 memory_total, disk_info, network_interfaces, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                ON CONFLICT (host_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    os_info = EXCLUDED.os_info,
                    kernel_version = EXCLUDED.kernel_version,
                    cpu_info = EXCLUDED.cpu_info,
                    memory_total = EXCLUDED.memory_total,
                    disk_info = EXCLUDED.disk_info,
                    network_interfaces = EXCLUDED.network_interfaces,
                    updated_at = CURRENT_TIMESTAMP
            ''', (host_id, hostname, os_info, kernel_version, cpu_info, 
                 memory_total, disk_info, network_interfaces))
    
    def get_host_info(self, host_id):
        """Get host system information"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM host_info WHERE host_id = %s', (host_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def get_network_stats(self):
        """Get overall network statistics"""
        try:
            cursor = self.conn.cursor()
            
            # Host counts
            cursor.execute('SELECT COUNT(*) as total_hosts FROM hosts')
            result = cursor.fetchone()
            total_hosts = result[0] if result else 0
            
            cursor.execute("SELECT COUNT(*) as online_hosts FROM hosts WHERE status = %s", ('online',))
            result = cursor.fetchone()
            online_hosts = result[0] if result else 0
            
            # Connection counts
            cursor.execute('SELECT COUNT(*) as total_connections FROM network_connections')
            result = cursor.fetchone()
            total_connections = result[0] if result else 0
            
            # Recent activity (last 24 hours)
            cursor.execute("""
                SELECT COUNT(*) as recent_connections 
                FROM network_connections WHERE last_seen > NOW() - INTERVAL '24 hour'
            """)
            result = cursor.fetchone()
            recent_connections = result[0] if result else 0
            
            return {
                'total_hosts': total_hosts,
                'online_hosts': online_hosts,
                'total_connections': total_connections,
                'recent_connections': recent_connections
            }
        except Exception as e:
            logger.error(f"Error getting network stats: {e}")
            return {
                'total_hosts': 0,
                'online_hosts': 0,
                'total_connections': 0,
                'recent_connections': 0
            }

    def get_host_stats(self, host_id):
        """Get statistics for a specific host"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Host basic info
            cursor.execute('SELECT * FROM hosts WHERE id = %s', (host_id,))
            host_info = cursor.fetchone()
            
            # Connection stats
            cursor.execute('''
                SELECT COUNT(*) as outbound_connections,
                       SUM(bytes_sent) as bytes_sent,
                       SUM(bytes_received) as bytes_received
                FROM network_connections WHERE source_host_id = %s
            ''', (host_id,))
            conn_stats = cursor.fetchone()
            
            # Port scan results
            cursor.execute('SELECT COUNT(*) as open_ports FROM port_scans WHERE host_id = %s AND state = %s', 
                          (host_id, 'open'))
            port_stats = cursor.fetchone()
            
            return {
                'host': dict(host_info) if host_info else {},
                'connections': dict(conn_stats) if conn_stats else {},
                'ports': dict(port_stats) if port_stats else {}
            }
    
    # Network discovery methods
    def save_network_discovery(self, host_id, discovery_type, discovery_data):
        """Save network discovery data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO network_discovery (host_id, discovery_type, discovery_data)
                VALUES (%s, %s, %s)
            ''', (host_id, discovery_type, json.dumps(discovery_data) if isinstance(discovery_data, dict) else discovery_data))
    
    def get_network_discovery(self, host_id=None, discovery_type=None, hours=24):
        """Get network discovery data"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            query = '''
                SELECT nd.*, h.name as hostname
                FROM network_discovery nd
                LEFT JOIN hosts h ON nd.host_id = h.id
                WHERE nd.timestamp > CURRENT_TIMESTAMP - INTERVAL '%s hours'
            ''' % hours
            
            params = []
            if host_id:
                query += ' AND nd.host_id = %s'
                params.append(host_id)
            if discovery_type:
                query += ' AND nd.discovery_type = %s'
                params.append(discovery_type)
            
            query += ' ORDER BY nd.timestamp DESC'
            
            cursor.execute(query, params)
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['discovery_data'] = json.loads(result['discovery_data'])
                except (json.JSONDecodeError, TypeError):
                    pass
                results.append(result)
            return results
    
    # Topology analysis methods
    def save_topology_analysis(self, analysis_type, analysis_data):
        """Save topology analysis data"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO topology_analysis (analysis_type, analysis_data)
                VALUES (%s, %s)
            ''', (analysis_type, json.dumps(analysis_data) if isinstance(analysis_data, dict) else analysis_data))
    
    def get_topology_analysis(self, analysis_type=None):
        """Get topology analysis data"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            if analysis_type:
                cursor.execute('''
                    SELECT * FROM topology_analysis 
                    WHERE analysis_type = %s 
                    ORDER BY timestamp DESC LIMIT 1
                ''', (analysis_type,))
            else:
                cursor.execute('SELECT * FROM topology_analysis ORDER BY timestamp DESC')
            
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['analysis_data'] = json.loads(result['analysis_data'])
                except (json.JSONDecodeError, TypeError):
                    pass
                results.append(result)
            return results
    
    # Diagram layout methods
    def save_diagram_layout(self, layout_name='default', layout_data=None, created_by='system'):
        """Save diagram layout"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO diagram_layouts (layout_name, layout_data, created_by)
                VALUES (%s, %s, %s)
                ON CONFLICT (layout_name) DO UPDATE SET
                    layout_data = EXCLUDED.layout_data,
                    created_by = EXCLUDED.created_by,
                    updated_at = CURRENT_TIMESTAMP
            ''', (layout_name, json.dumps(layout_data) if isinstance(layout_data, dict) else layout_data, created_by))
    
    def get_diagram_layout(self, layout_name='default'):
        """Get diagram layout"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM diagram_layouts WHERE layout_name = %s', (layout_name,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                try:
                    result['layout_data'] = json.loads(result['layout_data'])
                except (json.JSONDecodeError, TypeError):
                    pass
                return result
            return None
    
    def get_all_diagram_layouts(self):
        """Get all diagram layouts"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM diagram_layouts ORDER BY created_at DESC')
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['layout_data'] = json.loads(result['layout_data'])
                except (json.JSONDecodeError, TypeError):
                    pass
                results.append(result)
            return results
    
    def delete_diagram_layout(self, layout_name):
        """Delete diagram layout"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM diagram_layouts WHERE layout_name = %s', (layout_name,))
    
    # Additional agent management methods
    def deactivate_agent(self, agent_id):
        """Deactivate an agent"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE agents SET status = 'inactive', updated_at = CURRENT_TIMESTAMP
                WHERE agent_id = %s
            ''', (agent_id,))
    
    def remove_agent(self, agent_id):
        """Remove an agent completely"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM agent_scan_results WHERE agent_id = %s', (agent_id,))
            cursor.execute('DELETE FROM agent_logs WHERE agent_id = %s', (agent_id,))
            cursor.execute('DELETE FROM agent_configs WHERE agent_id = %s', (agent_id,))
            cursor.execute('DELETE FROM agents WHERE agent_id = %s', (agent_id,))
    
    def save_agent_config(self, agent_id, server_url, scan_interval=300, heartbeat_interval=60,
                         log_collection_enabled=True, log_paths='/var/log', scan_enabled=True,
                         test_configuration=None):
        """Save agent configuration"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO agent_configs 
                (agent_id, server_url, scan_interval, heartbeat_interval, 
                 log_collection_enabled, log_paths, scan_enabled, test_configuration)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (agent_id) DO UPDATE SET
                    server_url = EXCLUDED.server_url,
                    scan_interval = EXCLUDED.scan_interval,
                    heartbeat_interval = EXCLUDED.heartbeat_interval,
                    log_collection_enabled = EXCLUDED.log_collection_enabled,
                    log_paths = EXCLUDED.log_paths,
                    scan_enabled = EXCLUDED.scan_enabled,
                    test_configuration = EXCLUDED.test_configuration,
                    config_version = config_version + 1,
                    updated_at = CURRENT_TIMESTAMP
            ''', (agent_id, server_url, scan_interval, heartbeat_interval,
                 log_collection_enabled, log_paths, scan_enabled, test_configuration))
    
    def get_agent_config(self, agent_id):
        """Get agent configuration"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM agent_configs WHERE agent_id = %s', (agent_id,))
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def save_agent_logs(self, agent_id, logs):
        """Save agent logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for log_entry in logs:
                cursor.execute('''
                    INSERT INTO agent_logs 
                    (agent_id, log_source, log_level, message, timestamp)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (agent_id, log_entry.get('source', 'unknown'),
                     log_entry.get('level', 'INFO'), log_entry.get('message', ''),
                     log_entry.get('timestamp', datetime.now())))
    
    def get_agent_logs(self, agent_id=None, hours=24, limit=1000):
        """Get agent logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            query = '''
                SELECT al.*, a.hostname
                FROM agent_logs al
                JOIN agents a ON al.agent_id = a.agent_id
                WHERE al.collected_at > CURRENT_TIMESTAMP - INTERVAL '%s hours'
            ''' % hours
            
            params = []
            if agent_id:
                query += ' AND al.agent_id = %s'
                params.append(agent_id)
            
            query += ' ORDER BY al.collected_at DESC LIMIT %s'
            params.append(limit)
            
            cursor.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
    
    def save_agent_scan_result(self, agent_id, scan_type, scan_data):
        """Save agent scan result"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO agent_scan_results (agent_id, scan_type, scan_data)
                VALUES (%s, %s, %s)
            ''', (agent_id, scan_type, json.dumps(scan_data) if isinstance(scan_data, dict) else scan_data))
    
    def get_unprocessed_agent_scans(self):
        """Get unprocessed agent scan results"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM agent_scan_results WHERE processed = FALSE ORDER BY scan_timestamp ASC')
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                try:
                    result['scan_data'] = json.loads(result['scan_data'])
                except (json.JSONDecodeError, TypeError):
                    pass
                results.append(result)
            return results
    
    def mark_agent_scan_processed(self, scan_id):
        """Mark agent scan as processed"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE agent_scan_results SET processed = TRUE WHERE id = %s', (scan_id,))
    
    def get_agent_stats(self):
        """Get agent statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            
            # Basic stats
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_agents,
                    COUNT(CASE WHEN status = 'active' THEN 1 END) as active_agents,
                    COUNT(CASE WHEN last_heartbeat > CURRENT_TIMESTAMP - INTERVAL '5 minutes' THEN 1 END) as recent_heartbeats
                FROM agents
            ''')
            basic_stats = cursor.fetchone()
            
            # Version distribution
            cursor.execute('''
                SELECT agent_version, COUNT(*) as count
                FROM agents
                WHERE agent_version IS NOT NULL
                GROUP BY agent_version
                ORDER BY count DESC
            ''')
            version_stats = cursor.fetchall()
            
            return {
                'basic': dict(basic_stats) if basic_stats else {},
                'versions': [dict(row) for row in version_stats] if version_stats else []
            }
    
    # AI API settings methods
    def save_ai_api_settings(self, provider, api_key=None, model_name=None, api_endpoint=None, 
                            temperature=0.7, max_tokens=1000, timeout=30, enabled=False, additional_config=None):
        """Save AI API settings"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ai_api_settings 
                (provider, api_key, model_name, api_endpoint, temperature, max_tokens, timeout, enabled, additional_config)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (provider) DO UPDATE SET
                    api_key = EXCLUDED.api_key,
                    model_name = EXCLUDED.model_name,
                    api_endpoint = EXCLUDED.api_endpoint,
                    temperature = EXCLUDED.temperature,
                    max_tokens = EXCLUDED.max_tokens,
                    timeout = EXCLUDED.timeout,
                    enabled = EXCLUDED.enabled,
                    additional_config = EXCLUDED.additional_config,
                    updated_at = CURRENT_TIMESTAMP
            ''', (provider, api_key, model_name, api_endpoint, temperature, max_tokens, timeout, enabled,
                 json.dumps(additional_config) if additional_config else None))
    
    def get_ai_api_settings(self, provider):
        """Get AI API settings for a provider"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM ai_api_settings WHERE provider = %s', (provider,))
            row = cursor.fetchone()
            if row:
                result = dict(row)
                if result.get('additional_config'):
                    try:
                        result['additional_config'] = json.loads(result['additional_config'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                return result
            return None
    
    def get_all_ai_api_settings(self):
        """Get all AI API settings"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM ai_api_settings ORDER BY provider')
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                if result.get('additional_config'):
                    try:
                        result['additional_config'] = json.loads(result['additional_config'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                results.append(result)
            return results
    
    def get_enabled_ai_apis(self):
        """Get enabled AI API providers"""
        with self.get_connection() as conn:
            cursor = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cursor.execute('SELECT * FROM ai_api_settings WHERE enabled = TRUE')
            results = []
            for row in cursor.fetchall():
                result = dict(row)
                if result.get('additional_config'):
                    try:
                        result['additional_config'] = json.loads(result['additional_config'])
                    except (json.JSONDecodeError, TypeError):
                        pass
                results.append(result)
            return results
    

    def get_network_overview_stats(self):
        """Get comprehensive network overview statistics"""
        try:
            cursor = self.conn.cursor()
            stats = {}
            
            # Host statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_hosts,
                    COUNT(CASE WHEN status = %s THEN 1 END) as online_hosts,
                    COUNT(CASE WHEN status = %s THEN 1 END) as offline_hosts,
                    COUNT(CASE WHEN last_seen > NOW() - INTERVAL %s THEN 1 END) as active_last_hour,
                    COUNT(CASE WHEN last_seen > NOW() - INTERVAL %s THEN 1 END) as active_last_day
                FROM hosts
            """, ("online", "offline", "1 hour", "24 hour"))
            result = cursor.fetchone()
            if result:
                # Add to flat stats structure (not nested)
                stats.update({
                    "total_hosts": result[0] or 0,
                    "online_hosts": result[1] or 0,
                    "offline_hosts": result[2] or 0,
                    "hosts_active_last_hour": result[3] or 0,
                    "hosts_active_last_day": result[4] or 0
                })
            else:
                stats.update({"total_hosts": 0, "online_hosts": 0, "offline_hosts": 0, "hosts_active_last_hour": 0, "hosts_active_last_day": 0})
            
            # Connection statistics  
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(DISTINCT source_host_id) as hosts_with_connections,
                    COALESCE(SUM(connection_count), 0) as total_connection_count,
                    COALESCE(SUM(bytes_sent), 0) as total_bytes_sent,
                    COALESCE(SUM(bytes_received), 0) as total_bytes_received,
                    COUNT(CASE WHEN last_seen > NOW() - INTERVAL %s THEN 1 END) as active_last_hour
                FROM network_connections
            """, ("1 hour",))
            result = cursor.fetchone()
            if result:
                stats.update({
                    "total_connections": result[0] or 0,
                    "hosts_with_connections": result[1] or 0,
                    "total_connection_count": result[2] or 0,
                    "total_bytes_sent": result[3] or 0,
                    "total_bytes_received": result[4] or 0,
                    "connections_active_last_hour": result[5] or 0
                })
            else:
                stats.update({"total_connections": 0, "hosts_with_connections": 0, "total_connection_count": 0, "total_bytes_sent": 0, "total_bytes_received": 0, "connections_active_last_hour": 0})
            
            # Port statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_open_ports,
                    COUNT(DISTINCT host_id) as hosts_with_open_ports,
                    COUNT(DISTINCT port) as unique_ports
                FROM port_scans
                WHERE state = %s
            """, ("open",))
            result = cursor.fetchone()
            if result:
                stats.update({
                    "total_open_ports": result[0] or 0,
                    "hosts_with_open_ports": result[1] or 0,
                    "unique_ports": result[2] or 0
                })
            else:
                stats.update({"total_open_ports": 0, "hosts_with_open_ports": 0, "unique_ports": 0})
            
            # Agent statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_agents,
                    COUNT(CASE WHEN status = %s THEN 1 END) as active_agents,
                    COUNT(CASE WHEN last_heartbeat > NOW() - INTERVAL %s THEN 1 END) as recently_active,
                    COUNT(DISTINCT hostname) as unique_hosts
                FROM agents
            """, ("active", "10 minute"))
            result = cursor.fetchone()
            if result:
                stats.update({
                    "total_agents": result[0] or 0,
                    "active_agents": result[1] or 0,
                    "recently_active": result[2] or 0,
                    "agents_unique_hosts": result[3] or 0
                })
            else:
                stats.update({"total_agents": 0, "active_agents": 0, "recently_active": 0, "agents_unique_hosts": 0})
            
            # Recent scan statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_scans,
                    COUNT(DISTINCT agent_id) as unique_agents,
                    COUNT(CASE WHEN scan_timestamp > NOW() - INTERVAL %s THEN 1 END) as scans_last_day,
                    COUNT(CASE WHEN scan_timestamp > NOW() - INTERVAL %s THEN 1 END) as scans_last_hour
                FROM agent_scan_results
            """, ("24 hour", "1 hour"))
            result = cursor.fetchone()
            if result:
                stats.update({
                    "total_scans": result[0] or 0,
                    "unique_agents": result[1] or 0,
                    "scans_last_day": result[2] or 0,
                    "scans_last_hour": result[3] or 0
                })
            else:
                stats.update({"total_scans": 0, "unique_agents": 0, "scans_last_day": 0, "scans_last_hour": 0})
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting network overview stats: {e}")
            # Return empty flat stats structure to prevent template errors
            return {
                "total_hosts": 0, "online_hosts": 0, "offline_hosts": 0, "hosts_active_last_hour": 0, "hosts_active_last_day": 0,
                "total_connections": 0, "hosts_with_connections": 0, "total_connection_count": 0, "total_bytes_sent": 0, "total_bytes_received": 0, "connections_active_last_hour": 0,
                "total_open_ports": 0, "hosts_with_open_ports": 0, "unique_ports": 0,
                "total_agents": 0, "active_agents": 0, "recently_active": 0, "agents_unique_hosts": 0,
                "total_scans": 0, "unique_agents": 0, "scans_last_day": 0, "scans_last_hour": 0
            }


    def get_unified_dashboard_stats(self):
        """Get comprehensive dashboard statistics for all pages"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                stats = {}
                
                # Host statistics
                cursor.execute('SELECT COUNT(*) FROM hosts')
                result = cursor.fetchone()
                stats['total_hosts'] = result[0] if result else 0
                
                cursor.execute("SELECT COUNT(*) FROM hosts WHERE status = %s", ('online',))
                result = cursor.fetchone()
                stats['online_hosts'] = result[0] if result else 0
                
                # Agent statistics
                cursor.execute('SELECT COUNT(*) FROM agents')
                result = cursor.fetchone()
                stats['agents_deployed'] = result[0] if result else 0
                
                cursor.execute("SELECT COUNT(*) FROM agents WHERE status = %s", ('active',))
                result = cursor.fetchone()
                stats['active_agents'] = result[0] if result else 0
                
                # Get most common deployed agent version
                cursor.execute("SELECT agent_version, COUNT(*) FROM agents WHERE agent_version IS NOT NULL GROUP BY agent_version ORDER BY COUNT(*) DESC LIMIT 1")
                result = cursor.fetchone()
                stats['current_deployed'] = result[0] if result else 'Unknown'
                
                # Get latest available version from settings or use default
                cursor.execute("SELECT setting_value FROM application_settings WHERE setting_key = %s", ('latest_agent_version',))
                result = cursor.fetchone()
                stats['latest_available'] = result[0] if result else '1.7.0'
                
                # Recent scans (last 24 hours)
                cursor.execute("""
                    SELECT COUNT(*) FROM agent_scan_results 
                    WHERE scan_timestamp > NOW() - INTERVAL '24 hour'
                """)
                result = cursor.fetchone()
                stats['recent_scans'] = result[0] if result else 0
                
                # Add total_connections for backward compatibility
                cursor.execute("SELECT COUNT(*) FROM network_connections")
                result = cursor.fetchone()
                stats["total_connections"] = result[0] if result else 0
                
            return stats
            
        except Exception as e:
            logger.error(f"Error getting unified dashboard stats: {e}")
            return {
                'total_hosts': 0,
                'online_hosts': 0,
                'active_agents': 0,
                'agents_deployed': 0,
                'current_deployed': 'Unknown',
                'latest_available': '1.6.0',
                'recent_scans': 0
            }


    # Utility method
    def _format_bytes(self, bytes_value):
        """Format bytes to human readable format"""
        if bytes_value is None:
            return "0 B"
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    def get_network_statistics(self):
        """Get comprehensive network connection statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                stats = {}
                
                # Protocol breakdown
                cursor.execute("""
                    SELECT protocol, 
                           COUNT(*) as connection_count,
                           SUM(connection_count) as total_connections,
                           COUNT(DISTINCT source_host_id) as unique_hosts,
                           COUNT(DISTINCT dest_ip) as unique_destinations
                    FROM network_connections 
                    GROUP BY protocol 
                    ORDER BY COUNT(*) DESC
                """)
                stats['protocol_breakdown'] = [
                    {
                        'protocol': row[0],
                        'connection_count': row[1],
                        'total_connections': row[2],
                        'unique_hosts': row[3],
                        'unique_destinations': row[4]
                    } for row in cursor.fetchall()
                ]
                
                # Top destination IPs
                cursor.execute("""
                    SELECT dest_ip,
                           COUNT(*) as connection_count,
                           SUM(connection_count) as total_connections,
                           COUNT(DISTINCT source_host_id) as source_hosts,
                           COUNT(DISTINCT dest_port) as dest_ports,
                           SUM(bytes_sent + bytes_received) as total_bytes
                    FROM network_connections 
                    GROUP BY dest_ip 
                    ORDER BY COUNT(*) DESC 
                    LIMIT 10
                """)
                stats['top_destinations'] = [
                    {
                        'dest_ip': row[0],
                        'connection_count': row[1],
                        'total_connections': row[2],
                        'source_hosts': row[3],
                        'dest_ports': row[4],
                        'total_bytes': row[5] or 0
                    } for row in cursor.fetchall()
                ]
                
                # Top source hosts by connections
                cursor.execute("""
                    SELECT h.name, h.ip_address, h.status,
                           COUNT(nc.id) as connection_count,
                           SUM(nc.connection_count) as total_connections,
                           COUNT(DISTINCT nc.dest_ip) as unique_destinations,
                           SUM(nc.bytes_sent + nc.bytes_received) as total_bytes,
                           MAX(nc.last_seen) as last_activity
                    FROM hosts h
                    LEFT JOIN network_connections nc ON h.id = nc.source_host_id
                    GROUP BY h.id, h.name, h.ip_address, h.status
                    ORDER BY connection_count DESC
                    LIMIT 10
                """)
                stats['top_hosts'] = [
                    {
                        'host_name': row[0],
                        'ip_address': row[1],
                        'status': row[2],
                        'connection_count': row[3],
                        'total_connections': row[4] or 0,
                        'unique_destinations': row[5] or 0,
                        'total_bytes': row[6] or 0,
                        'last_activity': row[7]
                    } for row in cursor.fetchall()
                ]
                
                # LAN vs External analysis
                cursor.execute("""
                    SELECT 
                        CASE 
                            WHEN dest_ip LIKE '192.168.%' OR 
                                 dest_ip LIKE '10.%' OR 
                                 dest_ip LIKE '172.16.%' OR
                                 dest_ip LIKE '172.17.%' OR
                                 dest_ip LIKE '172.18.%' OR
                                 dest_ip LIKE '172.19.%' OR
                                 dest_ip LIKE '172.20.%' OR
                                 dest_ip LIKE '172.21.%' OR
                                 dest_ip LIKE '172.22.%' OR
                                 dest_ip LIKE '172.23.%' OR
                                 dest_ip LIKE '172.24.%' OR
                                 dest_ip LIKE '172.25.%' OR
                                 dest_ip LIKE '172.26.%' OR
                                 dest_ip LIKE '172.27.%' OR
                                 dest_ip LIKE '172.28.%' OR
                                 dest_ip LIKE '172.29.%' OR
                                 dest_ip LIKE '172.30.%' OR
                                 dest_ip LIKE '172.31.%'
                            THEN 'LAN' 
                            ELSE 'External' 
                        END as connection_type,
                        COUNT(*) as connection_count,
                        SUM(connection_count) as total_connections,
                        COUNT(DISTINCT source_host_id) as unique_hosts,
                        SUM(bytes_sent + bytes_received) as total_bytes
                    FROM network_connections 
                    GROUP BY connection_type
                """)
                lan_external = {row[0]: {
                    'connection_count': row[1],
                    'total_connections': row[2] or 0,
                    'unique_hosts': row[3],
                    'total_bytes': row[4] or 0
                } for row in cursor.fetchall()}
                
                total_conns = sum(data['connection_count'] for data in lan_external.values())
                for conn_type in lan_external:
                    lan_external[conn_type]['percentage'] = round(
                        (lan_external[conn_type]['connection_count'] / total_conns * 100) if total_conns > 0 else 0, 1
                    )
                
                stats['lan_vs_external'] = lan_external
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting network statistics: {e}")
            return {
                'protocol_breakdown': [],
                'top_destinations': [],
                'top_hosts': [],
                'lan_vs_external': {}
            }

    def get_agent_statistics(self):
        """Get comprehensive agent activity statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                stats = {}
                
                # Agent activity overview
                cursor.execute("""
                    SELECT 
                        COUNT(*) as total_agents,
                        COUNT(CASE WHEN status = 'active' THEN 1 END) as active_agents,
                        COUNT(CASE WHEN last_heartbeat > NOW() - INTERVAL '5 minutes' THEN 1 END) as recent_heartbeats,
                        COUNT(CASE WHEN last_scan > NOW() - INTERVAL '1 hour' THEN 1 END) as recent_scans
                    FROM agents
                """)
                row = cursor.fetchone()
                stats['overview'] = {
                    'total_agents': row[0],
                    'active_agents': row[1],
                    'recent_heartbeats': row[2],
                    'recent_scans': row[3]
                }
                
                # Recent scan activity by type
                cursor.execute("""
                    SELECT scan_type, 
                           COUNT(*) as scan_count,
                           COUNT(DISTINCT agent_id) as unique_agents
                    FROM agent_scan_results 
                    WHERE scan_timestamp > NOW() - INTERVAL '24 hours'
                    GROUP BY scan_type
                    ORDER BY scan_count DESC
                """)
                stats['scan_activity'] = [
                    {
                        'scan_type': row[0],
                        'scan_count': row[1],
                        'unique_agents': row[2]
                    } for row in cursor.fetchall()
                ]
                
                # Agent versions
                cursor.execute("""
                    SELECT agent_version, 
                           COUNT(*) as agent_count,
                           COUNT(CASE WHEN status = 'active' THEN 1 END) as active_count
                    FROM agents 
                    WHERE agent_version IS NOT NULL
                    GROUP BY agent_version
                    ORDER BY agent_count DESC
                """)
                stats['version_breakdown'] = [
                    {
                        'version': row[0],
                        'agent_count': row[1],
                        'active_count': row[2]
                    } for row in cursor.fetchall()
                ]
                
                # Platform breakdown
                cursor.execute("""
                    SELECT platform, 
                           COUNT(*) as agent_count,
                           COUNT(CASE WHEN status = 'active' THEN 1 END) as active_count
                    FROM agents 
                    WHERE platform IS NOT NULL
                    GROUP BY platform
                    ORDER BY agent_count DESC
                """)
                stats['platform_breakdown'] = [
                    {
                        'platform': row[0],
                        'agent_count': row[1],
                        'active_count': row[2]
                    } for row in cursor.fetchall()
                ]
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting agent statistics: {e}")
            return {
                'overview': {'total_agents': 0, 'active_agents': 0, 'recent_heartbeats': 0, 'recent_scans': 0},
                'scan_activity': [],
                'version_breakdown': [],
                'platform_breakdown': []
            }

    def get_historical_statistics(self, hours=24):
        """Get historical statistics for the specified time period"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                stats = {}
                
                # Hourly connection activity
                cursor.execute("""
                    SELECT 
                        to_char(date_trunc('hour', last_seen), 'YYYY-MM-DD HH24:00:00') as hour,
                        COUNT(*) as connections,
                        COUNT(DISTINCT source_host_id) as unique_hosts,
                        COUNT(DISTINCT dest_ip) as unique_destinations
                    FROM network_connections 
                    WHERE last_seen > NOW() - INTERVAL %s
                    GROUP BY date_trunc('hour', last_seen)
                    ORDER BY hour
                """, (f'{hours} hours',))
                
                stats['hourly_activity'] = [
                    {
                        'hour': row[0],
                        'connections': row[1],
                        'unique_hosts': row[2],
                        'unique_destinations': row[3]
                    } for row in cursor.fetchall()
                ]
                
                # Daily agent scan activity
                cursor.execute("""
                    SELECT 
                        to_char(date_trunc('day', scan_timestamp), 'YYYY-MM-DD') as day,
                        scan_type,
                        COUNT(*) as scan_count,
                        COUNT(DISTINCT agent_id) as unique_agents
                    FROM agent_scan_results 
                    WHERE scan_timestamp > NOW() - INTERVAL %s
                    GROUP BY date_trunc('day', scan_timestamp), scan_type
                    ORDER BY day, scan_count DESC
                """, (f'{hours} hours',))
                
                daily_scans = {}
                for row in cursor.fetchall():
                    day = row[0]
                    if day not in daily_scans:
                        daily_scans[day] = []
                    daily_scans[day].append({
                        'scan_type': row[1],
                        'scan_count': row[2],
                        'unique_agents': row[3]
                    })
                
                stats['daily_scan_activity'] = daily_scans
                
                return stats
                
        except Exception as e:
            logger.error(f"Error getting historical statistics: {e}")
            return {
                'hourly_activity': [],
                'daily_scan_activity': {}
            }
