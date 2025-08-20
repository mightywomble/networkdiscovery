
    def _get_chatbot_settings(self):
        """Get current chatbot settings"""
        try:
            from database import get_chatbot_settings
            return get_chatbot_settings()
        except Exception as e:
            logger.error(f"Error getting chatbot settings: {e}")
            return {
                'minimum_agent_version': '1.6.0',
                'require_version_check': True,
                'script_timeout': 300,
                'max_concurrent_executions': 5
            }
    
    def _check_agent_version(self, host_id: str) -> str:
        """Check the agent version on a specific host"""
        try:
            from database import execute_script_on_host
            
            # Execute version check command
            version_script = """
            # Try multiple methods to get agent version
            if [ -f '/opt/networkmap-agent/version.txt' ]; then
                cat /opt/networkmap-agent/version.txt
            elif command -v networkmap-agent >/dev/null 2>&1; then
                networkmap-agent --version 2>/dev/null || echo "unknown"
            elif [ -f '/usr/local/bin/networkmap-agent' ]; then
                /usr/local/bin/networkmap-agent --version 2>/dev/null || echo "unknown"
            else
                echo "unknown"
            fi
            """
            
            result = execute_script_on_host(host_id, version_script.strip())
            if result and result.get('success') and result.get('stdout'):
                version = result.get('stdout', '').strip()
                return version if version else 'unknown'
            else:
                return 'unknown'
                
        except Exception as e:
            logger.error(f"Error checking agent version for host {host_id}: {e}")
            return 'unknown'
    
    def _is_version_compatible(self, version: str, min_version: str) -> bool:
        """Check if version meets minimum requirement"""
        try:
            if version == 'unknown':
                return False
            
            # Simple version comparison (assumes semantic versioning)
            def version_tuple(v):
                return tuple(map(int, (v.split("."))))
            
            return version_tuple(version) >= version_tuple(min_version)
        except Exception as e:
            logger.error(f"Error comparing versions {version} vs {min_version}: {e}")
            return False
    
    def _execute_script_on_single_host(self, host_id: str, script: str) -> dict:
        """Execute script on a single host and return detailed results"""
        try:
            from database import execute_script_on_host
            import time
            
            start_time = time.time()
            result = execute_script_on_host(host_id, script)
            end_time = time.time()
            
            if result:
                result['execution_time'] = end_time - start_time
                return result
            else:
                return {
                    'success': False,
                    'error': 'No result returned from host',
                    'execution_time': end_time - start_time
                }
                
        except Exception as e:
            logger.error(f"Error executing script on host {host_id}: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_time': 0
            }
