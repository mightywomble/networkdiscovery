#!/usr/bin/env python3
"""
AI Command Generator for NetworkMap Chatbot
Converts natural language requests into bash scripts using AI models
"""

import json
import requests
import time
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AICommandGenerator:
    """Generates bash scripts from natural language requests using AI models"""
    
    def __init__(self, database):
        """
        Initialize the AI Command Generator
        
        Args:
            database: Database instance
        """
        self.db = database
        
        # Common command templates for safety and consistency
        self.command_templates = {
            'disk_space': {
                'pattern': r'disk\s+space|storage|free\s+space|df',
                'template': 'df -h',
                'description': 'Check disk space usage',
                'safety_level': 'safe'
            },
            'memory_usage': {
                'pattern': r'memory|ram|mem\s+usage',
                'template': 'free -h',
                'description': 'Check memory usage',
                'safety_level': 'safe'
            },
            'cpu_usage': {
                'pattern': r'cpu|processor|load|performance',
                'template': 'top -bn1 | head -20',
                'description': 'Check CPU usage and load',
                'safety_level': 'safe'
            },
            'network_info': {
                'pattern': r'network|ip\s+address|interface',
                'template': 'ip addr show',
                'description': 'Show network interfaces',
                'safety_level': 'safe'
            },
            'running_processes': {
                'pattern': r'process|running|ps',
                'template': 'ps aux | head -20',
                'description': 'Show running processes',
                'safety_level': 'safe'
            },
            'uptime': {
                'pattern': r'uptime|how\s+long',
                'template': 'uptime',
                'description': 'Show system uptime',
                'safety_level': 'safe'
            }
        }
    
    def generate_script_from_request(self, user_request: str, selected_hosts: List[Dict] = None) -> Dict[str, Any]:
        """
        Generate a bash script from a natural language request
        
        Args:
            user_request: Natural language request from user
            selected_hosts: List of selected host dictionaries
            
        Returns:
            dict: Generated script information including command, explanation, and metadata
        """
        try:
            logger.info(f"Generating script for request: {user_request}")
            
            # First, try to match against known templates for common requests
            template_match = self._match_command_template(user_request)
            if template_match:
                logger.info(f"Using template match: {template_match['description']}")
                return self._create_script_from_template(template_match, user_request, selected_hosts)
            
            # If no template match, use AI to generate custom script
            return self._generate_custom_script_with_ai(user_request, selected_hosts)
            
        except Exception as e:
            logger.error(f"Error generating script: {e}")
            return {
                'success': False,
                'error': str(e),
                'script': '# Error generating script\necho "Failed to generate command"',
                'explanation': f'Error occurred while generating script: {str(e)}',
                'safety_level': 'error'
            }
    
    def _match_command_template(self, user_request: str) -> Optional[Dict]:
        """Match user request against known command templates"""
        request_lower = user_request.lower()
        
        for template_name, template_data in self.command_templates.items():
            if re.search(template_data['pattern'], request_lower, re.IGNORECASE):
                return {
                    'name': template_name,
                    **template_data
                }
        
        return None
    
    def _create_script_from_template(self, template: Dict, user_request: str, selected_hosts: List[Dict]) -> Dict[str, Any]:
        """Create script response from a matched template"""
        script_lines = [
            "#!/bin/bash",
            "# Generated script for: " + user_request,
            f"# Template: {template['description']}",
            f"# Generated at: {datetime.now().isoformat()}",
            "",
            "# Confirm hostname at start of execution",
            "hostname",
            "",
            "echo '=== " + template['description'] + " ==='",
            "echo 'Hostname:' $(hostname)",
            "echo 'Timestamp:' $(date)",
            "echo ''",
            "",
            template['template'],
            "",
            "echo ''",
            "echo '=== Command completed successfully ==='"
        ]
        
        script = '\n'.join(script_lines)
        
        return {
            'success': True,
            'script': script,
            'explanation': self._create_template_explanation(template, user_request),
            'safety_level': template['safety_level'],
            'template_used': template['name'],
            'estimated_runtime': self._estimate_runtime(template['template']),
            'host_compatibility': self._check_host_compatibility(template['template'], selected_hosts),
            'generated_at': datetime.now().isoformat(),
            'user_request': user_request
        }
    
    def _generate_custom_script_with_ai(self, user_request: str, selected_hosts: List[Dict]) -> Dict[str, Any]:
        """Generate a custom script using AI when no template matches"""
        
        # Get AI configuration
        ai_models = self.db.get_enabled_ai_apis()
        if not ai_models:
            return self._create_fallback_script(user_request)
        
        # Use the first available AI model
        ai_model = ai_models[0]
        ai_config = self.db.get_ai_api_settings(ai_model['provider'])
        
        if not ai_config:
            return self._create_fallback_script(user_request)
        
        try:
            # Create AI prompt for script generation
            prompt = self._create_script_generation_prompt(user_request, selected_hosts)
            
            # Call AI model
            ai_response = self._call_ai_model(ai_model['provider'], ai_config, prompt)
            
            if ai_response.get('success'):
                return self._parse_ai_script_response(ai_response['content'], user_request)
            else:
                return self._create_fallback_script(user_request)
                
        except Exception as e:
            logger.error(f"Error generating custom script with AI: {e}")
            return self._create_fallback_script(user_request)
    
    def _create_script_generation_prompt(self, user_request: str, selected_hosts: List[Dict]) -> str:
        """Create AI prompt for bash script generation"""
        
        host_info = ""
        if selected_hosts:
            host_info = f"\nTarget hosts ({len(selected_hosts)}):\n"
            for host in selected_hosts[:5]:  # Limit to first 5 for prompt brevity
                host_info += f"- {host.get('name', 'Unknown')} ({host.get('ip_address', 'N/A')}): {host.get('description', 'No description')}\n"
        
        prompt = f"""
You are a system administrator assistant. Generate a safe bash script to fulfill this request: "{user_request}"

{host_info}

Requirements:
1. Create a bash script that safely accomplishes the user's request
2. Include proper error handling and safety checks
3. Add informative echo statements for clarity
4. Use only READ-ONLY commands unless explicitly requested otherwise
5. Include comments explaining what each part does
6. Format output clearly with headers and separators

IMPORTANT SAFETY RULES:
- NO destructive commands (rm, rmdir, dd, mkfs, etc.)
- NO system modification commands unless explicitly requested
- NO network attacks or scanning external systems
- Use standard Linux commands that are widely available
- Include error checking where appropriate

Respond with ONLY the bash script, no additional text or explanation. Start with #!/bin/bash and include helpful comments.
"""
        return prompt
    
    def _call_ai_model(self, ai_model: str, ai_config: Dict, prompt: str) -> Dict[str, Any]:
        """Call the specified AI model with the given prompt"""
        try:
            if ai_model == 'gemini':
                return self._call_gemini(ai_config, prompt)
            elif ai_model == 'chatgpt':
                return self._call_chatgpt(ai_config, prompt)
            else:
                raise ValueError(f"Unsupported AI model: {ai_model}")
                
        except Exception as e:
            logger.error(f"Error calling AI model {ai_model}: {e}")
            return {
                'content': f'Error calling AI model: {str(e)}',
                'error': str(e),
                'success': False
            }
    
    def _call_gemini(self, config: Dict, prompt: str) -> Dict[str, Any]:
        """Call Google Gemini API"""
        try:
            api_key = config.get('api_key')
            model_name = config.get('model_name', 'gemini-pro')
            api_endpoint = config.get('api_endpoint', 'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent')
            timeout = config.get('timeout', 30)
            
            if not api_key:
                raise ValueError("Gemini API key not configured")
            
            # Format endpoint URL
            endpoint_url = api_endpoint.format(model=model_name)
            if '?' in endpoint_url:
                endpoint_url += f'&key={api_key}'
            else:
                endpoint_url += f'?key={api_key}'
            
            # Prepare request data
            request_data = {
                'contents': [{
                    'parts': [{
                        'text': prompt
                    }]
                }],
                'generationConfig': {
                    'temperature': 0.3,  # Lower temperature for more consistent code generation
                    'maxOutputTokens': config.get('max_tokens', 2000)
                }
            }
            
            # Make API call
            response = requests.post(
                endpoint_url,
                json=request_data,
                timeout=timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
                return {'content': content, 'success': True}
            else:
                error_msg = f"Gemini API error: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return {'content': error_msg, 'error': error_msg, 'success': False}
                
        except Exception as e:
            error_msg = f"Error calling Gemini API: {str(e)}"
            logger.error(error_msg)
            return {'content': error_msg, 'error': error_msg, 'success': False}
    
    def _call_chatgpt(self, config: Dict, prompt: str) -> Dict[str, Any]:
        """Call OpenAI ChatGPT API"""
        try:
            api_key = config.get('api_key')
            model_name = config.get('model_name', 'gpt-3.5-turbo')
            api_endpoint = config.get('api_endpoint', 'https://api.openai.com/v1/chat/completions')
            timeout = config.get('timeout', 30)
            
            if not api_key:
                raise ValueError("ChatGPT API key not configured")
            
            # Prepare request data
            request_data = {
                'model': model_name,
                'messages': [{
                    'role': 'user',
                    'content': prompt
                }],
                'temperature': 0.3,  # Lower temperature for more consistent code generation
                'max_tokens': config.get('max_tokens', 2000)
            }
            
            # Make API call
            headers = {
                'Authorization': f'Bearer {api_key}',
                'Content-Type': 'application/json'
            }
            
            response = requests.post(
                api_endpoint,
                json=request_data,
                headers=headers,
                timeout=timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                content = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                return {'content': content, 'success': True}
            else:
                error_msg = f"ChatGPT API error: {response.status_code} - {response.text}"
                logger.error(error_msg)
                return {'content': error_msg, 'error': error_msg, 'success': False}
                
        except Exception as e:
            error_msg = f"Error calling ChatGPT API: {str(e)}"
            logger.error(error_msg)
            return {'content': error_msg, 'error': error_msg, 'success': False}
    
    def _parse_ai_script_response(self, ai_content: str, user_request: str) -> Dict[str, Any]:
        """Parse AI response and extract bash script"""
        try:
            # Clean up the AI response to extract just the bash script
            script_content = ai_content.strip()
            
            # Remove markdown code blocks if present
            if script_content.startswith('```bash'):
                script_content = script_content[7:]
            elif script_content.startswith('```'):
                script_content = script_content[3:]
            
            if script_content.endswith('```'):
                script_content = script_content[:-3]
            
            script_content = script_content.strip()
            
            # Ensure script starts with shebang
            if not script_content.startswith('#!/bin/bash'):
                script_content = '#!/bin/bash\n' + script_content
            
            # Ensure hostname command is at the beginning (after shebang and initial comments)
            script_lines = script_content.split('\n')
            hostname_added = False
            insert_position = 1  # After shebang
            
            # Find where to insert hostname command (skip initial comments)
            for i, line in enumerate(script_lines):
                line_stripped = line.strip()
                if line_stripped and not line_stripped.startswith('#') and line_stripped != '#!/bin/bash':
                    insert_position = i
                    break
                if line_stripped.startswith('hostname'):
                    hostname_added = True
                    break
            
            # Add hostname command if not already present
            if not hostname_added:
                script_lines.insert(insert_position, '')
                script_lines.insert(insert_position + 1, '# Confirm hostname at start of execution')
                script_lines.insert(insert_position + 2, 'hostname')
                script_lines.insert(insert_position + 3, '')
                script_content = '\n'.join(script_lines)
            
            return {
                'success': True,
                'script': script_content,
                'explanation': self._create_ai_script_explanation(script_content, user_request),
                'safety_level': self._assess_script_safety(script_content),
                'template_used': 'ai_generated',
                'estimated_runtime': self._estimate_runtime(script_content),
                'generated_at': datetime.now().isoformat(),
                'user_request': user_request
            }
            
        except Exception as e:
            logger.error(f"Error parsing AI script response: {e}")
            return self._create_fallback_script(user_request)
    
    def _create_fallback_script(self, user_request: str) -> Dict[str, Any]:
        """Create a safe fallback script when AI generation fails"""
        fallback_script = f"""#!/bin/bash
# Fallback script for request: {user_request}
# Generated at: {datetime.now().isoformat()}

# Confirm hostname at start of execution
hostname

echo "=== System Information Request ==="
echo "Request: {user_request}"
echo "Hostname: $(hostname)"
echo "Date: $(date)"
echo ""
echo "Basic system information:"
echo "- Uptime: $(uptime)"
echo "- Disk usage: $(df -h / | tail -1)"
echo "- Memory usage: $(free -h | head -2 | tail -1)"
echo ""
echo "Note: This is a fallback response. For more specific information,"
echo "please try rephrasing your request or contact your administrator."
"""
        
        return {
            'success': True,
            'script': fallback_script,
            'explanation': f"Generated a safe fallback script for your request: '{user_request}'. This script provides basic system information since a more specific script could not be generated automatically.",
            'safety_level': 'safe',
            'template_used': 'fallback',
            'estimated_runtime': '< 5 seconds',
            'generated_at': datetime.now().isoformat(),
            'user_request': user_request
        }
    
    def _create_template_explanation(self, template: Dict, user_request: str) -> str:
        """Create human-readable explanation for template-based scripts"""
        explanation = f"""This script was generated to handle your request: "{user_request}"

Script breakdown:
• Uses the '{template['description']}' template
• Main command: {template['template']}
• Safety level: {template['safety_level']}

The script will:
1. Display a header with the operation being performed
2. Show the hostname and current timestamp
3. Execute: {template['template']}
4. Display a completion message

This is a read-only operation that safely retrieves system information without making any changes."""
        
        return explanation
    
    def _create_ai_script_explanation(self, script: str, user_request: str) -> str:
        """Create explanation for AI-generated scripts"""
        # Extract main commands from script (simplified analysis)
        lines = script.split('\n')
        commands = []
        
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and not line.startswith('echo') and line != '#!/bin/bash':
                if not any(keyword in line for keyword in ['if', 'then', 'fi', 'do', 'done', 'while', 'for']):
                    commands.append(line)
        
        explanation = f"""This script was generated by AI to handle your request: "{user_request}"

Main commands that will be executed:"""
        
        for i, cmd in enumerate(commands[:5], 1):  # Limit to first 5 commands
            explanation += f"\n{i}. {cmd}"
        
        if len(commands) > 5:
            explanation += f"\n... and {len(commands) - 5} more commands"
        
        explanation += f"""

The script includes proper error handling and informative output to show what's happening at each step. All commands are designed to be safe and read-only unless you specifically requested system modifications."""
        
        return explanation
    
    def _assess_script_safety(self, script: str) -> str:
        """Assess the safety level of a generated script"""
        dangerous_commands = [
            'rm ', 'rmdir', 'dd ', 'mkfs', 'fdisk', 'parted', 'wipefs',
            'reboot', 'shutdown', 'halt', 'init 0', 'init 6',
            'passwd', 'userdel', 'groupdel', 'chpasswd',
            'iptables -F', 'ufw --force', 'systemctl stop', 'service stop'
        ]
        
        risky_commands = [
            'curl', 'wget', 'nc ', 'netcat', 'nmap', 'chmod 777', 'chown'
        ]
        
        script_lower = script.lower()
        
        for cmd in dangerous_commands:
            if cmd in script_lower:
                return 'dangerous'
        
        for cmd in risky_commands:
            if cmd in script_lower:
                return 'risky'
        
        return 'safe'
    
    def _estimate_runtime(self, script_or_command: str) -> str:
        """Estimate how long the script might take to run"""
        if any(cmd in script_or_command.lower() for cmd in ['find /', 'du -', 'locate']):
            return '30-60 seconds'
        elif any(cmd in script_or_command.lower() for cmd in ['ps aux', 'netstat', 'ss ']):
            return '5-15 seconds'
        else:
            return '< 5 seconds'
    
    def _check_host_compatibility(self, script: str, selected_hosts: List[Dict]) -> Dict[str, Any]:
        """Check if script is compatible with selected hosts"""
        if not selected_hosts:
            return {'compatible': True, 'notes': 'No specific hosts selected'}
        
        # Basic compatibility check - could be enhanced
        linux_commands = ['ps aux', 'df -h', 'free -h', 'ip addr']
        uses_linux_commands = any(cmd in script for cmd in linux_commands)
        
        return {
            'compatible': True,  # Assume compatible unless we detect issues
            'notes': f'Script appears compatible with Linux systems ({len(selected_hosts)} hosts selected)',
            'linux_optimized': uses_linux_commands
        }

if __name__ == "__main__":
    # Basic test
    print("AI Command Generator module loaded successfully")
