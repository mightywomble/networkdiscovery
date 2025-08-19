#!/usr/bin/env python3
"""
Chatbot Controller for NetworkMap
Orchestrates the conversation flow, command generation, validation, and execution
"""

import json
import uuid
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ChatbotController:
    """Main controller for the NetworkMap AI Chatbot"""
    
    def __init__(self, database, host_manager):
        """
        Initialize the Chatbot Controller
        
        Args:
            database: Database instance
            host_manager: HostManager instance for remote execution
        """
        self.db = database
        self.host_manager = host_manager
        
        # Initialize components
        from ai_command_generator import AICommandGenerator
        from command_validator import CommandValidator
        
        self.command_generator = AICommandGenerator(database)
        self.command_validator = CommandValidator()
        
        # Active conversations and executions
        self.active_conversations = {}
        self.active_executions = {}
        
        # Conversation states
        self.CONVERSATION_STATES = {
            'initial': 'initial',
            'awaiting_request': 'awaiting_request',
            'script_generated': 'script_generated',
            'script_validated': 'script_validated',
            'awaiting_approval': 'awaiting_approval',
            'executing': 'executing',
            'completed': 'completed',
            'error': 'error'
        }
    
    def start_conversation(self, user_id: str = None) -> Dict[str, Any]:
        """
        Start a new chatbot conversation
        
        Args:
            user_id: Optional user identifier
            
        Returns:
            dict: Conversation initialization response
        """
        try:
            conversation_id = str(uuid.uuid4())
            
            conversation = {
                'id': conversation_id,
                'user_id': user_id,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat(),
                'state': self.CONVERSATION_STATES['initial'],
                'messages': [],
                'current_script': None,
                'validation_result': None,
                'selected_hosts': [],
                'execution_results': None
            }
            
            self.active_conversations[conversation_id] = conversation
            
            # Save to database
            self._save_conversation(conversation)
            
            # Add welcome message
            welcome_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': self._get_welcome_message(),
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'conversation_state': 'initial',
                    'available_actions': ['request_command']
                }
            }
            
            conversation['messages'].append(welcome_message)
            conversation['state'] = self.CONVERSATION_STATES['awaiting_request']
            conversation['updated_at'] = datetime.now().isoformat()
            
            # Save conversation with welcome message
            self._save_conversation(conversation)
            
            logger.info(f"Started new conversation: {conversation_id}")
            
            return {
                'success': True,
                'conversation_id': conversation_id,
                'message': welcome_message,
                'conversation_state': conversation['state']
            }
            
        except Exception as e:
            logger.error(f"Error starting conversation: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def process_user_message(self, conversation_id: str, user_message: str, selected_hosts: List[Dict] = None) -> Dict[str, Any]:
        """
        Process a user message and generate appropriate response
        
        Args:
            conversation_id: ID of the conversation
            user_message: User's message/request
            selected_hosts: List of selected host dictionaries
            
        Returns:
            dict: Bot response with actions
        """
        try:
            conversation = self.active_conversations.get(conversation_id)
            if not conversation:
                # Try to load from database
                conversation = self.db.get_chatbot_conversation(conversation_id)
                if conversation:
                    self.active_conversations[conversation_id] = conversation
                else:
                    return {
                        'success': False,
                        'error': 'Conversation not found'
                    }
            
            # Add user message to conversation
            user_msg = {
                'id': str(uuid.uuid4()),
                'type': 'user',
                'content': user_message,
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'selected_hosts': selected_hosts or []
                }
            }
            
            conversation['messages'].append(user_msg)
            if selected_hosts:
                conversation['selected_hosts'] = selected_hosts
            
            # Process based on current conversation state
            response = self._process_message_by_state(conversation, user_message)
            
            # Add bot response to conversation
            if response.get('success'):
                conversation['messages'].append(response['message'])
                conversation['updated_at'] = datetime.now().isoformat()
                
                # Save updated conversation
                self._save_conversation(conversation)
            
            logger.info(f"Processed message in conversation {conversation_id}")
            return response
            
        except Exception as e:
            logger.error(f"Error processing user message: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _process_message_by_state(self, conversation: Dict, user_message: str) -> Dict[str, Any]:
        """Process message based on current conversation state"""
        
        current_state = conversation['state']
        
        if current_state == self.CONVERSATION_STATES['awaiting_request']:
            return self._handle_command_request(conversation, user_message)
        
        elif current_state == self.CONVERSATION_STATES['initial']:
            # Handle initial state as a command request - user is ready to give commands
            conversation['state'] = self.CONVERSATION_STATES['awaiting_request']
            return self._handle_command_request(conversation, user_message)
        
        elif current_state == self.CONVERSATION_STATES['script_validated']:
            return self._handle_validation_response(conversation, user_message)
        
        elif current_state == self.CONVERSATION_STATES['awaiting_approval']:
            return self._handle_approval_response(conversation, user_message)
        
        else:
            return self._handle_general_message(conversation, user_message)
    
    def _handle_command_request(self, conversation: Dict, user_message: str) -> Dict[str, Any]:
        """Handle initial command request from user"""
        try:
            logger.info(f"Generating script for request: {user_message}")
            
            # Generate script using AI
            generation_result = self.command_generator.generate_script_from_request(
                user_message, 
                conversation.get('selected_hosts', [])
            )
            
            if not generation_result.get('success'):
                return {
                    'success': False,
                    'error': f"Failed to generate script: {generation_result.get('error', 'Unknown error')}"
                }
            
            # Validate the generated script
            validation_result = self.command_validator.validate_script(
                generation_result['script']
            )
            
            # Store results in conversation
            conversation['current_script'] = generation_result
            conversation['validation_result'] = validation_result
            conversation['state'] = self.CONVERSATION_STATES['script_validated']
            
            # Create response message
            response_content = self._create_script_validation_response(
                generation_result, validation_result
            )
            
            bot_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': response_content['text'],
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'conversation_state': 'script_validated',
                    'script_data': generation_result,
                    'validation_data': validation_result,
                    'available_actions': response_content['actions']
                }
            }
            
            return {
                'success': True,
                'message': bot_message,
                'conversation_state': conversation['state'],
                'script_data': generation_result,
                'validation_data': validation_result
            }
            
        except Exception as e:
            logger.error(f"Error handling command request: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _handle_validation_response(self, conversation: Dict, user_message: str) -> Dict[str, Any]:
        """Handle user response to script validation"""
        
        user_choice = user_message.lower().strip()
        
        if user_choice in ['run', 'execute', 'yes', 'proceed']:
            return self._execute_script(conversation)
        
        elif user_choice in ['edit', 'modify', 'change']:
            return self._handle_edit_request(conversation)
        
        elif user_choice in ['try again', 'regenerate', 'new', 'different']:
            return self._handle_regenerate_request(conversation)
        
        else:
            # Provide guidance on available options
            bot_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': "I didn't understand your choice. Please choose one of the following options:\n\n" +
                          "• **Run** - Execute the script on selected hosts\n" +
                          "• **Edit** - Modify the script manually\n" +
                          "• **Try Again** - Generate a new script\n\n" +
                          "Just type your choice or click one of the buttons.",
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'conversation_state': 'script_validated',
                    'available_actions': ['run', 'edit', 'try_again']
                }
            }
            
            return {
                'success': True,
                'message': bot_message,
                'conversation_state': conversation['state']
            }
    
    def _execute_script(self, conversation: Dict) -> Dict[str, Any]:
        """Execute the validated script on selected hosts"""
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
            
            # Check if execution is approved
            if not validation_data.get('is_approved'):
                conversation['state'] = self.CONVERSATION_STATES['awaiting_approval']
                
                bot_message = {
                    'id': str(uuid.uuid4()),
                    'type': 'bot',
                    'content': f"⚠️ **Manual Approval Required**\n\n" +
                              f"This script has been flagged as **{validation_data['overall_risk'].upper()}** risk " +
                              f"and requires manual approval before execution.\n\n" +
                              f"**Risks identified:**\n" +
                              '\n'.join([f"• {risk['description']}" for risk in validation_data.get('risks', [])]) +
                              f"\n\nDo you want to proceed anyway? Type 'yes' to confirm or 'no' to cancel.",
                    'timestamp': datetime.now().isoformat(),
                    'metadata': {
                        'conversation_state': 'awaiting_approval',
                        'available_actions': ['approve', 'deny']
                    }
                }
                
                return {
                    'success': True,
                    'message': bot_message,
                    'conversation_state': conversation['state']
                }
            
            # Execute script
            execution_id = str(uuid.uuid4())
            conversation['state'] = self.CONVERSATION_STATES['executing']
            
            # Start execution in background thread
            execution_thread = threading.Thread(
                target=self._execute_script_on_hosts,
                args=(conversation['id'], execution_id, script_data['script'], selected_hosts)
            )
            execution_thread.daemon = True
            execution_thread.start()
            
            bot_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': f"🚀 **Executing script on {len(selected_hosts)} host(s)...**\n\n" +
                          f"Script is now running on the selected hosts. This may take a few moments.\n\n" +
                          f"**Execution ID:** `{execution_id}`\n" +
                          f"**Estimated runtime:** {script_data.get('estimated_runtime', 'Unknown')}\n\n" +
                          f"I'll show you the results as soon as they're available.",
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
    
    def _execute_script_on_hosts(self, conversation_id: str, execution_id: str, script: str, selected_hosts: List[Dict]):
        """Execute script on selected hosts (runs in background thread)"""
        try:
            conversation = self.active_conversations.get(conversation_id)
            if not conversation:
                return
            
            logger.info(f"Starting script execution {execution_id} on {len(selected_hosts)} hosts")
            
            execution_results = {
                'execution_id': execution_id,
                'started_at': datetime.now().isoformat(),
                'completed_at': None,
                'status': 'running',
                'results': {},
                'summary': {
                    'total_hosts': len(selected_hosts),
                    'successful': 0,
                    'failed': 0,
                    'errors': []
                }
            }
            
            # Execute on each host
            for host in selected_hosts:
                try:
                    host_id = host.get('id')
                    host_name = host.get('name', 'Unknown')
                    
                    logger.info(f"Executing script on host {host_name}")
                    
                    # Execute command via host manager
                    result, error = self.host_manager.execute_command(host, script, timeout=300)
                    
                    if result and result.get('success'):
                        execution_results['results'][host_id] = {
                            'host_name': host_name,
                            'host_ip': host.get('ip_address', 'Unknown'),
                            'status': 'success',
                            'stdout': result.get('stdout', ''),
                            'stderr': result.get('stderr', ''),
                            'exit_code': result.get('exit_code', 0),
                            'execution_time': result.get('execution_time', 'Unknown')
                        }
                        execution_results['summary']['successful'] += 1
                    else:
                        error_msg = result.get('stderr', error) if result else str(error)
                        execution_results['results'][host_id] = {
                            'host_name': host_name,
                            'host_ip': host.get('ip_address', 'Unknown'),
                            'status': 'failed',
                            'error': error_msg,
                            'stdout': result.get('stdout', '') if result else '',
                            'stderr': result.get('stderr', '') if result else ''
                        }
                        execution_results['summary']['failed'] += 1
                        execution_results['summary']['errors'].append(f"{host_name}: {error_msg}")
                        
                except Exception as e:
                    logger.error(f"Error executing on host {host.get('name', 'Unknown')}: {e}")
                    execution_results['results'][host.get('id', 'unknown')] = {
                        'host_name': host.get('name', 'Unknown'),
                        'host_ip': host.get('ip_address', 'Unknown'),
                        'status': 'error',
                        'error': str(e)
                    }
                    execution_results['summary']['failed'] += 1
                    execution_results['summary']['errors'].append(f"{host.get('name', 'Unknown')}: {str(e)}")
            
            # Mark execution as completed
            execution_results['completed_at'] = datetime.now().isoformat()
            execution_results['status'] = 'completed'
            
            # Store results in conversation
            conversation['execution_results'] = execution_results
            conversation['state'] = self.CONVERSATION_STATES['completed']
            conversation['updated_at'] = datetime.now().isoformat()
            
            # Create completion message
            completion_message = self._create_execution_completion_message(execution_results)
            conversation['messages'].append(completion_message)
            
            # Save conversation
            self._save_conversation(conversation)
            
            logger.info(f"Script execution {execution_id} completed")
            
        except Exception as e:
            logger.error(f"Error in background execution: {e}")
            # Handle execution failure
            if conversation:
                conversation['state'] = self.CONVERSATION_STATES['error']
                error_message = {
                    'id': str(uuid.uuid4()),
                    'type': 'bot',
                    'content': f"❌ **Execution Failed**\n\nAn error occurred during script execution: {str(e)}",
                    'timestamp': datetime.now().isoformat(),
                    'metadata': {
                        'conversation_state': 'error',
                        'error': str(e)
                    }
                }
                conversation['messages'].append(error_message)
                self._save_conversation(conversation)
    
    def _create_execution_completion_message(self, execution_results: Dict) -> Dict[str, Any]:
        """Create message for execution completion"""
        
        summary = execution_results['summary']
        success_rate = (summary['successful'] / summary['total_hosts']) * 100 if summary['total_hosts'] > 0 else 0
        
        # Determine overall status icon and color
        if summary['successful'] == summary['total_hosts']:
            status_icon = "✅"
            status_text = "**All executions completed successfully!**"
        elif summary['successful'] > 0:
            status_icon = "⚠️"
            status_text = f"**Partial success** - {summary['successful']}/{summary['total_hosts']} hosts succeeded"
        else:
            status_icon = "❌"
            status_text = "**All executions failed**"
        
        content = f"{status_icon} {status_text}\n\n"
        content += f"**Execution Summary:**\n"
        content += f"• Total hosts: {summary['total_hosts']}\n"
        content += f"• Successful: {summary['successful']}\n"
        content += f"• Failed: {summary['failed']}\n"
        content += f"• Success rate: {success_rate:.1f}%\n\n"
        
        if summary['successful'] > 0:
            content += "**Successful Results:**\n"
            for host_id, result in execution_results['results'].items():
                if result['status'] == 'success':
                    content += f"• **{result['host_name']}** ({result['host_ip']}): ✓ Success\n"
        
        if summary['errors']:
            content += "\n**Errors:**\n"
            for error in summary['errors'][:3]:  # Show first 3 errors
                content += f"• {error}\n"
            if len(summary['errors']) > 3:
                content += f"• ... and {len(summary['errors']) - 3} more errors\n"
        
        content += f"\n*Execution completed at {execution_results['completed_at']}*"
        
        return {
            'id': str(uuid.uuid4()),
            'type': 'bot',
            'content': content,
            'timestamp': datetime.now().isoformat(),
            'metadata': {
                'conversation_state': 'completed',
                'execution_results': execution_results,
                'available_actions': ['new_request', 'view_details']
            }
        }
    
    def get_execution_results(self, conversation_id: str, execution_id: str) -> Dict[str, Any]:
        """Get detailed execution results"""
        try:
            conversation = self.active_conversations.get(conversation_id)
            if not conversation:
                return {'success': False, 'error': 'Conversation not found'}
            
            execution_results = conversation.get('execution_results')
            if not execution_results or execution_results.get('execution_id') != execution_id:
                return {'success': False, 'error': 'Execution results not found'}
            
            return {
                'success': True,
                'execution_results': execution_results
            }
            
        except Exception as e:
            logger.error(f"Error getting execution results: {e}")
            return {'success': False, 'error': str(e)}
    
    def _create_script_validation_response(self, script_data: Dict, validation_data: Dict) -> Dict[str, Any]:
        """Create response showing script and validation results"""
        
        safety_info = self.command_validator.get_safety_explanation(validation_data['overall_risk'])
        
        content = f"I've generated a script for your request: **{script_data['user_request']}**\n\n"
        
        # Show script preview
        content += "**Generated Script:**\n```bash\n"
        content += script_data['script'][:500]
        if len(script_data['script']) > 500:
            content += "\n... (script truncated for display)\n"
        content += "```\n\n"
        
        # Show explanation
        content += "**What this script does:**\n"
        content += script_data['explanation'] + "\n\n"
        
        # Show safety assessment
        content += f"**Safety Assessment:** {safety_info['icon']} {safety_info['title']}\n"
        content += safety_info['description'] + "\n\n"
        
        if validation_data.get('warnings'):
            content += "**Warnings:**\n"
            for warning in validation_data['warnings'][:3]:
                content += f"• {warning['description']}\n"
            content += "\n"
        
        if validation_data.get('risks'):
            content += "**⚠️ Risks Identified:**\n"
            for risk in validation_data['risks']:
                content += f"• {risk['description']}\n"
            content += "\n"
        
        # Show estimated runtime
        content += f"**Estimated runtime:** {script_data.get('estimated_runtime', 'Unknown')}\n\n"
        
        # Show available actions
        content += "**What would you like to do?**\n\n"
        
        available_actions = []
        
        if validation_data.get('is_approved'):
            content += "• **Run** - Execute the script on selected hosts\n"
            available_actions.append('run')
        else:
            content += "• **Review & Approve** - This script requires approval before execution\n"
            available_actions.append('review')
        
        content += "• **Edit** - Modify the script manually\n"
        content += "• **Try Again** - Generate a different script\n"
        available_actions.extend(['edit', 'try_again'])
        
        return {
            'text': content,
            'actions': available_actions
        }
    
    def _get_welcome_message(self) -> str:
        """Get the welcome message for new conversations"""
        return """👋 **Welcome to the NetworkMap AI Assistant!**

I can help you run commands on your remote hosts by generating and executing bash scripts. Just describe what you'd like to do, and I'll:

1. **Generate** a safe bash script based on your request
2. **Validate** the script for security and safety  
3. **Show you** exactly what will be executed
4. **Run it** on your selected hosts with your approval

**Example requests:**
• "Check disk space on all servers"
• "Show me the memory usage"
• "List running processes"
• "Get network interface information"

**To get started:**
1. Select the hosts you want to work with (if any)
2. Type your request below

What would you like me to help you with today?"""
    
    def _handle_edit_request(self, conversation: Dict) -> Dict[str, Any]:
        """Handle request to edit the generated script"""
        # This would integrate with the script editor functionality
        bot_message = {
            'id': str(uuid.uuid4()),
            'type': 'bot',
            'content': "**Script Editor**\n\nI'll open the script editor where you can modify the generated script. " +
                      "The editor will show the current script and allow you to make changes, " +
                      "then re-validate it for safety.\n\n" +
                      "*[Script editor interface would appear here]*",
            'timestamp': datetime.now().isoformat(),
            'metadata': {
                'conversation_state': 'editing',
                'available_actions': ['save_edit', 'cancel_edit']
            }
        }
        
        return {
            'success': True,
            'message': bot_message,
            'conversation_state': 'editing'
        }
    
    def _handle_regenerate_request(self, conversation: Dict) -> Dict[str, Any]:
        """Handle request to generate a new script"""
        conversation['state'] = self.CONVERSATION_STATES['awaiting_request']
        
        bot_message = {
            'id': str(uuid.uuid4()),
            'type': 'bot',
            'content': "I'll generate a new script for you. Please describe what you'd like to do, " +
                      "and I can try a different approach or focus on specific aspects of your request.\n\n" +
                      "What would you like the new script to do?",
            'timestamp': datetime.now().isoformat(),
            'metadata': {
                'conversation_state': 'awaiting_request',
                'available_actions': ['new_request']
            }
        }
        
        return {
            'success': True,
            'message': bot_message,
            'conversation_state': conversation['state']
        }
    
    def _handle_approval_response(self, conversation: Dict, user_message: str) -> Dict[str, Any]:
        """Handle user response to approval request"""
        user_choice = user_message.lower().strip()
        
        if user_choice in ['yes', 'approve', 'proceed', 'confirm']:
            # Override approval and execute
            if conversation.get('validation_result'):
                conversation['validation_result']['is_approved'] = True
            return self._execute_script(conversation)
        
        else:
            # User declined - go back to validation state
            conversation['state'] = self.CONVERSATION_STATES['script_validated']
            
            bot_message = {
                'id': str(uuid.uuid4()),
                'type': 'bot',
                'content': "Execution cancelled. You can still:\n\n" +
                          "• **Edit** - Modify the script to make it safer\n" +
                          "• **Try Again** - Generate a completely new script\n\n" +
                          "What would you like to do?",
                'timestamp': datetime.now().isoformat(),
                'metadata': {
                    'conversation_state': 'script_validated',
                    'available_actions': ['edit', 'try_again']
                }
            }
            
            return {
                'success': True,
                'message': bot_message,
                'conversation_state': conversation['state']
            }
    
    def _handle_general_message(self, conversation: Dict, user_message: str) -> Dict[str, Any]:
        """Handle general messages not tied to specific states"""
        
        bot_message = {
            'id': str(uuid.uuid4()),
            'type': 'bot',
            'content': "I'm here to help you run commands on your remote hosts. " +
                      "Please describe what you'd like me to do, and I'll generate a script for you.\n\n" +
                      "For example:\n" +
                      "• \"Check disk usage on all servers\"\n" +
                      "• \"Show me running processes\"\n" +
                      "• \"Get system information\"",
            'timestamp': datetime.now().isoformat(),
            'metadata': {
                'conversation_state': conversation['state'],
                'available_actions': ['new_request']
            }
        }
        
        return {
            'success': True,
            'message': bot_message,
            'conversation_state': conversation['state']
        }
    
    def _save_conversation(self, conversation: Dict):
        """Save conversation to database"""
        try:
            self.db.save_chatbot_conversation(conversation)
            logger.info(f"Saved conversation {conversation['id']} to database")
            
        except Exception as e:
            logger.error(f"Error saving conversation: {e}")
    
    def get_conversation(self, conversation_id: str) -> Optional[Dict[str, Any]]:
        """Get conversation by ID"""
        return self.active_conversations.get(conversation_id)
    
    def get_conversation_history(self, conversation_id: str) -> Dict[str, Any]:
        """Get conversation message history"""
        try:
            conversation = self.active_conversations.get(conversation_id)
            if not conversation:
                return {'success': False, 'error': 'Conversation not found'}
            
            return {
                'success': True,
                'conversation_id': conversation_id,
                'messages': conversation['messages'],
                'state': conversation['state'],
                'updated_at': conversation['updated_at']
            }
            
        except Exception as e:
            logger.error(f"Error getting conversation history: {e}")
            return {'success': False, 'error': str(e)}

if __name__ == "__main__":
    # Basic test
    print("Chatbot Controller module loaded successfully")
