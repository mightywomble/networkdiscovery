    def _execute_script(self, conversation: Dict) -> Dict[str, Any]:
        """Execute the script with version checking and AI analysis"""
        try:
            script_data = conversation.get('current_script')
            validation_data = conversation.get('validation_result')
            selected_hosts = conversation.get('selected_hosts', [])
            
            if not script_data or not validation_data:
                return {
                    'success': False,
                    'error': 'No script or validation data available'
                }
            
            if not selected_hosts:
                return {
                    'success': False,
                    'error': 'No hosts selected for execution'
                }
            
            # Get chatbot settings for version checking
            settings = self._get_chatbot_settings()
            min_version = settings.get('minimum_agent_version', '1.6.0')
            version_check_enabled = settings.get('require_version_check', True)
            
            conversation['state'] = self.CONVERSATION_STATES['executing']
            
            # Start execution with version checking and AI analysis
            execution_id = str(uuid.uuid4())
            execution_thread = threading.Thread(
                target=self._execute_with_version_check_and_analysis,
                args=(conversation['id'], execution_id, script_data['script'], selected_hosts, min_version, version_check_enabled)
            )
            execution_thread.daemon = True
            execution_thread.start()
            
            bot_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': f"🚀 **Executing script with version checking...**

" +
                          f"**Step 1:** Checking agent versions (minimum required: {min_version})
" +
                          f"**Step 2:** Executing script on compatible hosts
" +
                          f"**Step 3:** Analyzing results with AI

" +
                          f"This process may take a few moments...",
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'conversation_state': 'executing',
                    'execution_id': execution_id,
                    'available_actions': []
                }
            }
            
            return {
                'success': True,
                'message': bot_message,
                'conversation_state': conversation['state'],
                'execution_id': execution_id
            }
            
        except Exception as e:
            logger.error(f"Error executing script: {e}")
            return {
                'success': False,
                'error': str(e)
            }
