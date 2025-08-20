
    def _execute_with_version_check_and_analysis(self, conversation_id: str, execution_id: str, script: str, selected_hosts: List[Dict], min_version: str, version_check_enabled: bool):
        """Execute script with version checking and AI analysis"""
        try:
            conversation = self.active_conversations.get(conversation_id)
            if not conversation:
                return
            
            logger.info(f"Starting enhanced execution {execution_id} on {len(selected_hosts)} hosts")
            
            execution_results = {
                'execution_id': execution_id,
                'started_at': datetime.now().isoformat(),
                'completed_at': None,
                'status': 'running',
                'version_checks': {},
                'results': {},
                'ai_analysis': None,
                'summary': {
                    'total_hosts': len(selected_hosts),
                    'version_compatible': 0,
                    'version_incompatible': 0,
                    'successful': 0,
                    'failed': 0,
                    'errors': []
                }
            }
            
            # Step 1: Check agent versions
            compatible_hosts = []
            incompatible_hosts = []
            
            for host in selected_hosts:
                host_id = host.get('id')
                host_name = host.get('name', 'Unknown')
                
                if version_check_enabled:
                    # Check agent version
                    version = self._check_agent_version(host_id)
                    execution_results['version_checks'][host_name] = {
                        'version': version,
                        'compatible': self._is_version_compatible(version, min_version)
                    }
                    
                    if self._is_version_compatible(version, min_version):
                        compatible_hosts.append(host)
                        execution_results['summary']['version_compatible'] += 1
                    else:
                        incompatible_hosts.append(host)
                        execution_results['summary']['version_incompatible'] += 1
                        logger.warning(f"Host {host_name} has incompatible version {version}, minimum required: {min_version}")
                else:
                    # Skip version checking
                    compatible_hosts.append(host)
                    execution_results['version_checks'][host_name] = {
                        'version': 'Not checked',
                        'compatible': True
                    }
                    execution_results['summary']['version_compatible'] += 1
            
            # Step 2: Execute script on compatible hosts
            script_outputs = {}
            
            for host in compatible_hosts:
                try:
                    host_id = host.get('id')
                    host_name = host.get('name', 'Unknown')
                    
                    logger.info(f"Executing script on host {host_name}")
                    
                    # Execute the script (this should use your existing script execution logic)
                    result = self._execute_script_on_single_host(host_id, script)
                    
                    if result.get('success'):
                        execution_results['results'][host_name] = {
                            'status': 'success',
                            'stdout': result.get('stdout', ''),
                            'stderr': result.get('stderr', ''),
                            'exit_code': result.get('exit_code', 0),
                            'execution_time': result.get('execution_time', 0)
                        }
                        script_outputs[host_name] = result.get('stdout', '')
                        execution_results['summary']['successful'] += 1
                    else:
                        execution_results['results'][host_name] = {
                            'status': 'failed',
                            'error': result.get('error', 'Unknown error'),
                            'stderr': result.get('stderr', ''),
                            'exit_code': result.get('exit_code', 1)
                        }
                        execution_results['summary']['failed'] += 1
                        execution_results['summary']['errors'].append(f"{host_name}: {result.get('error', 'Unknown error')}")
                        
                except Exception as e:
                    logger.error(f"Error executing on host {host_name}: {e}")
                    execution_results['results'][host_name] = {
                        'status': 'failed',
                        'error': str(e),
                        'exit_code': 1
                    }
                    execution_results['summary']['failed'] += 1
                    execution_results['summary']['errors'].append(f"{host_name}: {str(e)}")
            
            # Step 3: AI Analysis of results
            if script_outputs:
                try:
                    ai_analysis = self._analyze_script_output_with_ai(script_outputs, script)
                    execution_results['ai_analysis'] = ai_analysis
                except Exception as e:
                    logger.error(f"Error in AI analysis: {e}")
                    execution_results['ai_analysis'] = {
                        'error': f"AI analysis failed: {str(e)}"
                    }
            
            # Complete execution
            execution_results['completed_at'] = datetime.now().isoformat()
            execution_results['status'] = 'completed'
            
            # Store results
            conversation['execution_results'] = execution_results
            conversation['state'] = self.CONVERSATION_STATES['completed']
            
            # Send completion message with AI analysis
            self._send_execution_completion_message(conversation_id, execution_results)
            
            logger.info(f"Enhanced execution {execution_id} completed")
            
        except Exception as e:
            logger.error(f"Error in enhanced execution: {e}")
            # Send error message
            if conversation_id in self.active_conversations:
                conversation = self.active_conversations[conversation_id]
                conversation['state'] = self.CONVERSATION_STATES['error']
