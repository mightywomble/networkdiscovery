#!/usr/bin/env python3
"""
AI Data Collector for NetworkMap
Collects and prepares network data for AI analysis
"""

import json
import sqlite3
from datetime import datetime, timedelta
from collections import defaultdict
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIDataCollector:
    """Collects and prepares network data for AI analysis"""
    
    def __init__(self, database, host_manager):
        """
        Initialize the AI Data Collector
        
        Args:
            database: Database instance
            host_manager: HostManager instance
        """
        self.db = database
        self.host_manager = host_manager
    
    def get_data_statistics(self):
        """
        Get statistics about available data for AI analysis
        
        Returns:
            dict: Data statistics including counts and time ranges
        """
        try:
            stats = {
                'hosts': {},
                'connections': {},
                'agents': {},
                'logs': {},
                'scan_data': {},
                'last_updated': datetime.now().isoformat()
            }
            
            with self.db.get_connection() as conn:
                # Host statistics
                cursor = conn.execute('SELECT COUNT(*) as total FROM hosts')
                stats['hosts']['total'] = cursor.fetchone()['total']
                
                cursor = conn.execute("SELECT COUNT(*) as online FROM hosts WHERE status = 'online'")
                result = cursor.fetchone()
                stats['hosts']['online'] = result['online'] if result else 0
                
                # Connection statistics
                cursor = conn.execute('SELECT COUNT(*) as total FROM network_connections')
                stats['connections']['total'] = cursor.fetchone()['total']
                
                # Recent connections (last 24 hours)
                cursor = conn.execute("""
                    SELECT COUNT(*) as recent 
                    FROM network_connections 
                    WHERE last_seen > datetime('now', '-24 hours')
                """)
                result = cursor.fetchone()
                stats['connections']['last_24h'] = result['recent'] if result else 0
                
                # Get time range of connection data
                cursor = conn.execute("""
                    SELECT 
                        MIN(first_seen) as earliest,
                        MAX(last_seen) as latest
                    FROM network_connections
                """)
                result = cursor.fetchone()
                if result and result['earliest']:
                    stats['connections']['time_range'] = {
                        'earliest': result['earliest'],
                        'latest': result['latest']
                    }
                
                # Agent statistics
                cursor = conn.execute('SELECT COUNT(*) as total FROM agents')
                result = cursor.fetchone()
                stats['agents']['total'] = result['total'] if result else 0
                
                cursor = conn.execute("SELECT COUNT(*) as active FROM agents WHERE status = 'active'")
                result = cursor.fetchone()
                stats['agents']['active'] = result['active'] if result else 0
                
                # Agent scan results
                cursor = conn.execute('SELECT COUNT(*) as total FROM agent_scan_results')
                result = cursor.fetchone()
                stats['scan_data']['agent_scans'] = result['total'] if result else 0
                
                # Recent agent scans (last 24 hours)
                cursor = conn.execute("""
                    SELECT COUNT(*) as recent 
                    FROM agent_scan_results 
                    WHERE scan_timestamp > datetime('now', '-24 hours')
                """)
                result = cursor.fetchone()
                stats['scan_data']['recent_scans'] = result['recent'] if result else 0
                
                # Agent logs
                cursor = conn.execute('SELECT COUNT(*) as total FROM agent_logs')
                result = cursor.fetchone()
                stats['logs']['total'] = result['total'] if result else 0
                
                # Recent logs (last 24 hours)
                cursor = conn.execute("""
                    SELECT COUNT(*) as recent 
                    FROM agent_logs 
                    WHERE timestamp > datetime('now', '-24 hours')
                """)
                result = cursor.fetchone()
                stats['logs']['recent'] = result['recent'] if result else 0
                
            return stats
            
        except Exception as e:
            logger.error(f"Error getting data statistics: {e}")
            return {
                'error': str(e),
                'hosts': {'total': 0, 'online': 0},
                'connections': {'total': 0, 'last_24h': 0},
                'agents': {'total': 0, 'active': 0},
                'scan_data': {'agent_scans': 0, 'recent_scans': 0},
                'logs': {'total': 0, 'recent': 0},
                'last_updated': datetime.now().isoformat()
            }
    
    def collect_all_data(self):
        """
        Collect all available network data for AI analysis
        
        Returns:
            dict: Complete network dataset
        """
        try:
            logger.info("Collecting all network data for AI analysis")
            
            data = {
                'collection_timestamp': datetime.now().isoformat(),
                'data_type': 'complete_dataset',
                'hosts': self._collect_host_data(),
                'network_connections': self._collect_connection_data(),
                'agents': self._collect_agent_data(),
                'scan_results': self._collect_scan_data(),
                'network_topology': self._collect_topology_data(),
                'system_logs': self._collect_log_data(),
                'metadata': {
                    'collection_method': 'complete',
                    'data_sources': ['hosts', 'connections', 'agents', 'scans', 'logs'],
                    'time_range': 'all_available'
                }
            }
            
            logger.info("Complete data collection finished")
            return data
            
        except Exception as e:
            logger.error(f"Error collecting all data: {e}")
            raise
    
    def collect_latest_capture(self):
        """
        Collect the latest network data capture (last 24 hours)
        
        Returns:
            dict: Recent network dataset
        """
        try:
            logger.info("Collecting latest network data capture")
            
            cutoff_time = datetime.now() - timedelta(hours=24)
            
            data = {
                'collection_timestamp': datetime.now().isoformat(),
                'data_type': 'latest_capture',
                'time_range': '24_hours',
                'cutoff_time': cutoff_time.isoformat(),
                'hosts': self._collect_host_data(),
                'network_connections': self._collect_connection_data(since=cutoff_time),
                'agents': self._collect_agent_data(),
                'scan_results': self._collect_scan_data(since=cutoff_time),
                'recent_activity': self._collect_recent_activity(),
                'metadata': {
                    'collection_method': 'recent_capture',
                    'data_sources': ['recent_connections', 'recent_scans', 'current_hosts'],
                    'time_range': 'last_24_hours'
                }
            }
            
            logger.info("Latest capture collection finished")
            return data
            
        except Exception as e:
            logger.error(f"Error collecting latest capture: {e}")
            raise
    
    def collect_latest_logs(self):
        """
        Collect the latest log files and system data
        
        Returns:
            dict: Latest log dataset
        """
        try:
            logger.info("Collecting latest log data")
            
            cutoff_time = datetime.now() - timedelta(hours=12)
            
            data = {
                'collection_timestamp': datetime.now().isoformat(),
                'data_type': 'latest_logs',
                'time_range': '12_hours',
                'cutoff_time': cutoff_time.isoformat(),
                'system_logs': self._collect_log_data(since=cutoff_time),
                'agent_logs': self._collect_agent_logs(since=cutoff_time),
                'recent_errors': self._collect_error_logs(since=cutoff_time),
                'system_events': self._collect_system_events(since=cutoff_time),
                'metadata': {
                    'collection_method': 'logs_only',
                    'data_sources': ['system_logs', 'agent_logs', 'error_logs'],
                    'time_range': 'last_12_hours'
                }
            }
            
            logger.info("Latest logs collection finished")
            return data
            
        except Exception as e:
            logger.error(f"Error collecting latest logs: {e}")
            raise
    
    def _collect_host_data(self):
        """Collect host configuration and status data"""
        try:
            hosts = self.host_manager.get_all_hosts()
            
            host_data = []
            for host in hosts:
                host_info = {
                    'id': host.get('id'),
                    'name': host.get('name'),
                    'ip_address': host.get('ip_address'),
                    'username': host.get('username'),
                    'ssh_port': host.get('ssh_port'),
                    'description': host.get('description'),
                    'status': host.get('status'),
                    'last_seen': host.get('last_seen'),
                    'created_at': host.get('created_at'),
                    'updated_at': host.get('updated_at')
                }
                host_data.append(host_info)
            
            return host_data
            
        except Exception as e:
            logger.error(f"Error collecting host data: {e}")
            return []
    
    def _collect_connection_data(self, since=None):
        """Collect network connection data"""
        try:
            with self.db.get_connection() as conn:
                if since:
                    cursor = conn.execute("""
                        SELECT * FROM network_connections 
                        WHERE last_seen > ? 
                        ORDER BY last_seen DESC
                    """, (since,))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM network_connections 
                        ORDER BY last_seen DESC 
                        LIMIT 10000
                    """)
                
                connections = []
                for row in cursor.fetchall():
                    connection = dict(row)
                    connections.append(connection)
                
                return connections
                
        except Exception as e:
            logger.error(f"Error collecting connection data: {e}")
            return []
    
    def _collect_agent_data(self):
        """Collect agent information"""
        try:
            agents = self.db.get_all_agents()
            return agents
            
        except Exception as e:
            logger.error(f"Error collecting agent data: {e}")
            return []
    
    def _collect_scan_data(self, since=None):
        """Collect scan results from agents"""
        try:
            with self.db.get_connection() as conn:
                if since:
                    cursor = conn.execute("""
                        SELECT * FROM agent_scan_results 
                        WHERE scan_timestamp > ? 
                        ORDER BY scan_timestamp DESC
                    """, (since,))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM agent_scan_results 
                        ORDER BY scan_timestamp DESC 
                        LIMIT 1000
                    """)
                
                scans = []
                for row in cursor.fetchall():
                    scan = dict(row)
                    # Parse scan_data JSON if it exists
                    if scan.get('scan_data'):
                        try:
                            scan['scan_data'] = json.loads(scan['scan_data'])
                        except json.JSONDecodeError:
                            pass
                    scans.append(scan)
                
                return scans
                
        except Exception as e:
            logger.error(f"Error collecting scan data: {e}")
            return []
    
    def _collect_topology_data(self):
        """Collect network topology analysis data"""
        try:
            with self.db.get_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM topology_analysis 
                    ORDER BY analysis_timestamp DESC 
                    LIMIT 10
                """)
                
                topology_data = []
                for row in cursor.fetchall():
                    analysis = dict(row)
                    # Parse analysis_data JSON if it exists
                    if analysis.get('analysis_data'):
                        try:
                            analysis['analysis_data'] = json.loads(analysis['analysis_data'])
                        except json.JSONDecodeError:
                            pass
                    topology_data.append(analysis)
                
                return topology_data
                
        except Exception as e:
            logger.error(f"Error collecting topology data: {e}")
            return []
    
    def _collect_log_data(self, since=None):
        """Collect general log data"""
        try:
            # This would collect system logs if available
            # For now, return placeholder structure
            log_data = {
                'system_logs': [],
                'application_logs': [],
                'security_logs': [],
                'note': 'Log collection not yet implemented'
            }
            
            return log_data
            
        except Exception as e:
            logger.error(f"Error collecting log data: {e}")
            return {}
    
    def _collect_agent_logs(self, since=None):
        """Collect logs from agents"""
        try:
            with self.db.get_connection() as conn:
                if since:
                    cursor = conn.execute("""
                        SELECT * FROM agent_logs 
                        WHERE timestamp > ? 
                        ORDER BY timestamp DESC 
                        LIMIT 1000
                    """, (since,))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM agent_logs 
                        ORDER BY timestamp DESC 
                        LIMIT 1000
                    """)
                
                logs = []
                for row in cursor.fetchall():
                    log_entry = dict(row)
                    logs.append(log_entry)
                
                return logs
                
        except Exception as e:
            logger.error(f"Error collecting agent logs: {e}")
            return []
    
    def _collect_error_logs(self, since=None):
        """Collect error and warning logs"""
        try:
            with self.db.get_connection() as conn:
                if since:
                    cursor = conn.execute("""
                        SELECT * FROM agent_logs 
                        WHERE timestamp > ? AND (level = 'error' OR level = 'warning')
                        ORDER BY timestamp DESC 
                        LIMIT 500
                    """, (since,))
                else:
                    cursor = conn.execute("""
                        SELECT * FROM agent_logs 
                        WHERE level = 'error' OR level = 'warning'
                        ORDER BY timestamp DESC 
                        LIMIT 500
                    """)
                
                error_logs = []
                for row in cursor.fetchall():
                    log_entry = dict(row)
                    error_logs.append(log_entry)
                
                return error_logs
                
        except Exception as e:
            logger.error(f"Error collecting error logs: {e}")
            return []
    
    def _collect_system_events(self, since=None):
        """Collect system events and status changes"""
        try:
            # This could collect system events from various sources
            # For now, collect agent heartbeat events and status changes
            events = []
            
            with self.db.get_connection() as conn:
                if since:
                    cursor = conn.execute("""
                        SELECT agent_id, hostname, status, last_heartbeat, error_message
                        FROM agents 
                        WHERE last_heartbeat > ? 
                        ORDER BY last_heartbeat DESC
                    """, (since,))
                else:
                    cursor = conn.execute("""
                        SELECT agent_id, hostname, status, last_heartbeat, error_message
                        FROM agents 
                        ORDER BY last_heartbeat DESC 
                        LIMIT 100
                    """)
                
                for row in cursor.fetchall():
                    event = dict(row)
                    event['event_type'] = 'agent_heartbeat'
                    events.append(event)
            
            return events
            
        except Exception as e:
            logger.error(f"Error collecting system events: {e}")
            return []
    
    def _collect_recent_activity(self):
        """Collect recent network activity summary"""
        try:
            activity = {}
            
            with self.db.get_connection() as conn:
                # Recent connection summary
                cursor = conn.execute("""
                    SELECT 
                        COUNT(*) as connection_count,
                        COUNT(DISTINCT source_host_id) as unique_sources,
                        COUNT(DISTINCT dest_ip) as unique_destinations
                    FROM network_connections 
                    WHERE last_seen > datetime('now', '-1 hour')
                """)
                result = cursor.fetchone()
                activity['last_hour'] = dict(result) if result else {}
                
                # Top active hosts
                cursor = conn.execute("""
                    SELECT 
                        h.name,
                        h.ip_address,
                        COUNT(*) as connection_count
                    FROM network_connections nc
                    JOIN hosts h ON nc.source_host_id = h.id
                    WHERE nc.last_seen > datetime('now', '-24 hours')
                    GROUP BY h.id, h.name, h.ip_address
                    ORDER BY connection_count DESC
                    LIMIT 10
                """)
                activity['top_active_hosts'] = [dict(row) for row in cursor.fetchall()]
                
                # Top destination ports
                cursor = conn.execute("""
                    SELECT 
                        dest_port,
                        COUNT(*) as connection_count,
                        COUNT(DISTINCT source_host_id) as unique_sources
                    FROM network_connections 
                    WHERE last_seen > datetime('now', '-24 hours')
                    GROUP BY dest_port
                    ORDER BY connection_count DESC
                    LIMIT 10
                """)
                activity['top_ports'] = [dict(row) for row in cursor.fetchall()]
            
            return activity
            
        except Exception as e:
            logger.error(f"Error collecting recent activity: {e}")
            return {}
    
    def format_data_for_ai(self, data, max_size_mb=25):
        """
        Format and potentially truncate data for AI analysis with improved sampling
        
        Args:
            data: Raw data dictionary
            max_size_mb: Maximum size in MB for the formatted data
            
        Returns:
            dict: Formatted data suitable for AI analysis
        """
        try:
            # Calculate approximate size and use intelligent truncation if necessary
            data_str = json.dumps(data, default=str)
            size_mb = len(data_str.encode('utf-8')) / (1024 * 1024)
            
            if size_mb > max_size_mb:
                logger.warning(f"Data size ({size_mb:.2f}MB) exceeds limit ({max_size_mb}MB), applying intelligent sampling")
                
                # Intelligent truncation with representative sampling
                if 'network_connections' in data and len(data['network_connections']) > 1000:
                    # Keep most recent connections, some random samples, and any with errors
                    connections = data['network_connections']
                    recent = connections[-500:]  # Most recent 500
                    errors = [c for c in connections if 'error' in str(c).lower()][:100]  # Up to 100 error connections
                    # Random sample from the rest
                    import random
                    remaining = [c for c in connections[:-500] if c not in errors]
                    sample_size = min(400, len(remaining))
                    random_sample = random.sample(remaining, sample_size) if remaining else []
                    
                    data['network_connections'] = recent + errors + random_sample
                    data['_connections_truncated'] = {
                        'original_count': len(connections),
                        'kept_recent': len(recent),
                        'kept_errors': len(errors),
                        'kept_sample': len(random_sample)
                    }
                
                # Apply same intelligent sampling to system logs
                if 'system_logs' in data and isinstance(data['system_logs'], list) and len(data['system_logs']) > 1000:
                    logs = data['system_logs']
                    # Keep recent logs, error logs, and warning logs
                    recent = logs[-300:]
                    errors = [l for l in logs if any(level in str(l).lower() for level in ['error', 'critical', 'fail'])][:200]
                    warnings = [l for l in logs if 'warn' in str(l).lower()][:200]
                    
                    # Combine and deduplicate
                    important_logs = list({str(l): l for l in (recent + errors + warnings)}.values())
                    data['system_logs'] = important_logs[:800]  # Max 800 logs
                    data['_logs_truncated'] = {
                        'original_count': len(logs),
                        'kept_important': len(important_logs)
                    }
                
                # Apply same to agent logs
                if 'agent_logs' in data and len(data['agent_logs']) > 500:
                    logs = data['agent_logs']
                    # Keep most recent and error logs
                    recent = logs[-200:]
                    errors = [l for l in logs if any(level in str(l).lower() for level in ['error', 'critical', 'fail', 'warn'])][:300]
                    combined = list({str(l): l for l in (recent + errors)}.values())
                    
                    data['agent_logs'] = combined[:400]
                    data['_agent_logs_truncated'] = {
                        'original_count': len(logs),
                        'kept_important': len(combined)
                    }
                
                # Check size again after intelligent truncation and force further reduction if needed
                data_str = json.dumps(data, default=str)
                new_size_mb = len(data_str.encode('utf-8')) / (1024 * 1024)
                
                # If still too large, do more aggressive truncation
                if new_size_mb > max_size_mb:
                    logger.warning(f"Still too large ({new_size_mb:.2f}MB), applying aggressive truncation")
                    
                    # More aggressive truncation - keep only essential data
                    for key in ['network_connections', 'system_logs', 'agent_logs', 'hosts', 'scan_results']:
                        if key in data and isinstance(data[key], list):
                            original_length = len(data[key])
                            if original_length > 0:
                                # Keep only 5% of the data, max 50 items for large collections
                                keep_count = min(50, max(5, original_length // 20))
                                data[key] = data[key][-keep_count:]  # Keep most recent
                                logger.info(f"Reduced {key} from {original_length} to {keep_count} items")
                    
                    # Remove large text fields from remaining items
                    if 'hosts' in data:
                        for host in data['hosts']:
                            if isinstance(host, dict):
                                # Remove potentially large fields
                                for field in ['logs', 'full_scan_results', 'detailed_info']:
                                    host.pop(field, None)
                    
                    # Recalculate size
                    data_str = json.dumps(data, default=str)
                    new_size_mb = len(data_str.encode('utf-8')) / (1024 * 1024)
                    logger.info(f"After aggressive truncation: {new_size_mb:.2f}MB")
                
                logger.info(f"After intelligent sampling: {new_size_mb:.2f}MB (reduced from {size_mb:.2f}MB)")
                
                data['_truncated'] = True
                data['_size_reduction'] = {
                    'original_size_mb': round(size_mb, 2),
                    'final_size_mb': round(new_size_mb, 2),
                    'reduction_percent': round((1 - new_size_mb/size_mb) * 100, 1)
                }
            
            # Add comprehensive summary statistics
            data['data_summary'] = {
                'hosts_count': len(data.get('hosts', [])),
                'connections_count': len(data.get('network_connections', [])),
                'agents_count': len(data.get('agents', [])),
                'scans_count': len(data.get('scan_results', [])),
                'logs_count': len(data.get('agent_logs', [])),
                'system_logs_count': len(data.get('system_logs', [])),
                'data_size_mb': round(len(json.dumps(data, default=str).encode('utf-8')) / (1024 * 1024), 2),
                'truncated': data.get('_truncated', False),
                'collection_time': datetime.now().isoformat()
            }
            
            return data
            
        except Exception as e:
            logger.error(f"Error formatting data for AI: {e}")
            raise
if __name__ == "__main__":
    # Basic test
    print("AI Data Collector module loaded successfully")
