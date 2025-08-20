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
                stats['latest_available'] = result[0] if result else '1.6.0'
                
                # Recent scans (last 24 hours)
                cursor.execute("""
                    SELECT COUNT(*) FROM agent_scan_results 
                    WHERE scan_timestamp > NOW() - INTERVAL '24 hour'
                """)
                result = cursor.fetchone()
                stats['recent_scans'] = result[0] if result else 0
                
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
