#!/usr/bin/env python3
"""
AI Report Generator for NetworkMap
Generates comprehensive network analysis reports using AI models
"""

import json
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIReportGenerator:
    """Generates AI-powered network analysis reports"""
    
    def __init__(self, database, host_manager):
        """
        Initialize the AI Report Generator
        
        Args:
            database: Database instance
            host_manager: HostManager instance
        """
        self.db = database
        self.host_manager = host_manager
        
        # Import the data collector
        from ai_data_collector import AIDataCollector
        self.data_collector = AIDataCollector(database, host_manager)
    
    def generate_report(self, ai_model: str, data_type: str) -> Dict[str, Any]:
        """
        Generate a comprehensive network analysis report using AI
        
        Args:
            ai_model: AI model to use ('gemini' or 'chatgpt')
            data_type: Type of data to analyze ('all_data', 'latest_capture', 'latest_logs')
            
        Returns:
            dict: Generated report with analysis sections
        """
        try:
            logger.info(f"Starting AI report generation: {ai_model} on {data_type}")
            
            # Step 1: Collect data based on type
            raw_data = self._collect_data_by_type(data_type)
            
            # Step 2: Format data for AI analysis
            formatted_data = self.data_collector.format_data_for_ai(raw_data)
            
            # Step 3: Get AI configuration
            ai_config = self._get_ai_configuration(ai_model)
            if not ai_config:
                raise ValueError(f"AI configuration not found or not enabled for {ai_model}")
            
            # Step 4: Generate report sections using AI
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'ai_model': ai_model,
                    'data_type': data_type,
                    'data_summary': formatted_data.get('data_summary', {}),
                    'generation_time': None
                },
                'executive_summary': {},
                'network_overview': {},
                'security_analysis': {},
                'performance_insights': {},
                'infrastructure_analysis': {},
                'recommendations': {},
                'detailed_findings': {}
            }
            
            start_time = time.time()
            
            # Generate each section
            report['executive_summary'] = self._generate_executive_summary(ai_model, ai_config, formatted_data)
            report['network_overview'] = self._generate_network_overview(ai_model, ai_config, formatted_data)
            report['security_analysis'] = self._generate_security_analysis(ai_model, ai_config, formatted_data)
            report['performance_insights'] = self._generate_performance_insights(ai_model, ai_config, formatted_data)
            report['infrastructure_analysis'] = self._generate_infrastructure_analysis(ai_model, ai_config, formatted_data)
            report['recommendations'] = self._generate_recommendations(ai_model, ai_config, formatted_data)
            report['detailed_findings'] = self._generate_detailed_findings(ai_model, ai_config, formatted_data)
            
            # Add generation time
            generation_time = time.time() - start_time
            report['metadata']['generation_time'] = f"{generation_time:.2f} seconds"
            
            logger.info(f"AI report generation completed in {generation_time:.2f} seconds")
            return report
            
        except Exception as e:
            logger.error(f"Error generating AI report: {e}")
            # Return error report
            return {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'ai_model': ai_model,
                    'data_type': data_type,
                    'error': str(e),
                    'status': 'failed'
                },
                'executive_summary': {
                    'title': 'Report Generation Failed',
                    'summary': f'Unable to generate AI report: {str(e)}',
                    'key_points': [
                        'Report generation encountered an error',
                        'Please check AI configuration and try again',
                        'Contact administrator if problem persists'
                    ]
                },
                'error_details': str(e)
            }
    
    def _collect_data_by_type(self, data_type: str) -> Dict[str, Any]:
        """Collect data based on the specified type"""
        if data_type == 'all_data':
            return self.data_collector.collect_all_data()
        elif data_type == 'latest_capture':
            return self.data_collector.collect_latest_capture()
        elif data_type == 'latest_logs':
            return self.data_collector.collect_latest_logs()
        else:
            raise ValueError(f"Unknown data type: {data_type}")
    
    def _get_ai_configuration(self, ai_model: str) -> Optional[Dict[str, Any]]:
        """Get AI configuration for the specified model"""
        try:
            config = self.db.get_ai_api_settings(ai_model)
            if config and config.get('enabled', False):
                return config
            return None
        except Exception as e:
            logger.error(f"Error getting AI configuration: {e}")
            return None
    
    def _generate_executive_summary(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate executive summary section"""
        try:
            prompt = self._create_executive_summary_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Executive Summary',
                'summary': response.get('content', 'Unable to generate executive summary'),
                'key_points': self._extract_key_points(response.get('content', '')),
                'risk_level': self._assess_risk_level(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {e}")
            return {
                'title': 'Executive Summary',
                'summary': f'Error generating summary: {str(e)}',
                'key_points': ['Report generation encountered an error'],
                'error': str(e)
            }
    
    def _generate_network_overview(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate network overview section"""
        try:
            prompt = self._create_network_overview_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Network Overview',
                'analysis': response.get('content', 'Unable to generate network overview'),
                'topology_insights': self._analyze_topology(data),
                'connection_patterns': self._analyze_connections(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating network overview: {e}")
            return {
                'title': 'Network Overview',
                'analysis': f'Error generating overview: {str(e)}',
                'error': str(e)
            }
    
    def _generate_security_analysis(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate security analysis section"""
        try:
            prompt = self._create_security_analysis_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Security Analysis',
                'analysis': response.get('content', 'Unable to generate security analysis'),
                'threats_identified': self._identify_security_threats(data),
                'recommendations': self._generate_security_recommendations(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating security analysis: {e}")
            return {
                'title': 'Security Analysis',
                'analysis': f'Error generating analysis: {str(e)}',
                'error': str(e)
            }
    
    def _generate_performance_insights(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate performance insights section"""
        try:
            prompt = self._create_performance_insights_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Performance Insights',
                'analysis': response.get('content', 'Unable to generate performance insights'),
                'metrics': self._analyze_performance_metrics(data),
                'bottlenecks': self._identify_bottlenecks(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating performance insights: {e}")
            return {
                'title': 'Performance Insights',
                'analysis': f'Error generating insights: {str(e)}',
                'error': str(e)
            }
    
    def _generate_infrastructure_analysis(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate infrastructure analysis section"""
        try:
            prompt = self._create_infrastructure_analysis_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Infrastructure Analysis',
                'analysis': response.get('content', 'Unable to generate infrastructure analysis'),
                'asset_inventory': self._create_asset_inventory(data),
                'configuration_insights': self._analyze_configurations(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating infrastructure analysis: {e}")
            return {
                'title': 'Infrastructure Analysis',
                'analysis': f'Error generating analysis: {str(e)}',
                'error': str(e)
            }
    
    def _generate_recommendations(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate recommendations section"""
        try:
            prompt = self._create_recommendations_prompt(data)
            response = self._call_ai_model(ai_model, ai_config, prompt)
            
            return {
                'title': 'Recommendations',
                'analysis': response.get('content', 'Unable to generate recommendations'),
                'priority_actions': self._prioritize_actions(data),
                'implementation_guide': self._create_implementation_guide(data),
                'generated_at': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return {
                'title': 'Recommendations',
                'analysis': f'Error generating recommendations: {str(e)}',
                'error': str(e)
            }
    
    def _generate_detailed_findings(self, ai_model: str, ai_config: Dict, data: Dict) -> Dict[str, Any]:
        """Generate detailed findings section"""
        try:
            # Compile detailed technical findings
            findings = {
                'title': 'Detailed Technical Findings',
                'network_statistics': self._compile_network_statistics(data),
                'host_analysis': self._analyze_individual_hosts(data),
                'traffic_analysis': self._analyze_traffic_patterns(data),
                'error_analysis': self._analyze_errors(data),
                'generated_at': datetime.now().isoformat()
            }
            
            return findings
            
        except Exception as e:
            logger.error(f"Error generating detailed findings: {e}")
            return {
                'title': 'Detailed Technical Findings',
                'analysis': f'Error generating findings: {str(e)}',
                'error': str(e)
            }
    
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
                'error': str(e)
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
                    'temperature': config.get('temperature', 0.7),
                    'maxOutputTokens': config.get('max_tokens', 1000)
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
                'temperature': config.get('temperature', 0.7),
                'max_tokens': config.get('max_tokens', 1000)
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
    
    # Prompt creation methods
    def _create_executive_summary_prompt(self, data: Dict) -> str:
        """Create prompt for executive summary"""
        summary = data.get('data_summary', {})
        
        prompt = f"""
Please analyze this network monitoring data and provide an executive summary suitable for IT management.

Data Overview:
- Hosts monitored: {summary.get('hosts_count', 0)}
- Network connections analyzed: {summary.get('connections_count', 0)}
- Active monitoring agents: {summary.get('agents_count', 0)}
- Scan results available: {summary.get('scans_count', 0)}
- Data collection period: {data.get('metadata', {}).get('time_range', 'Unknown')}

Network Data Sample: {json.dumps(data, default=str)[:2000]}...

Please provide:
1. A concise executive summary (2-3 paragraphs)
2. Key findings and insights
3. Critical issues that require attention
4. Overall network health assessment

Format your response as a clear, professional summary suitable for executives.
"""
        return prompt
    
    def _create_network_overview_prompt(self, data: Dict) -> str:
        """Create prompt for network overview"""
        connections = data.get('network_connections', [])[:50]  # Sample of connections
        hosts = data.get('hosts', [])
        
        prompt = f"""
Analyze this network infrastructure and provide a comprehensive overview.

Hosts in Network: {len(hosts)}
Recent Connections: {len(connections)}

Host Details:
{json.dumps(hosts, default=str, indent=2)[:1500]}

Connection Patterns:
{json.dumps(connections, default=str, indent=2)[:1500]}

Please analyze and provide:
1. Network topology insights
2. Communication patterns between hosts
3. Most active network segments
4. Unusual or concerning traffic patterns
5. Network architecture observations

Focus on providing actionable insights about the network structure and behavior.
"""
        return prompt
    
    def _create_security_analysis_prompt(self, data: Dict) -> str:
        """Create prompt for security analysis"""
        connections = data.get('network_connections', [])[:30]
        agents = data.get('agents', [])
        
        prompt = f"""
Perform a security analysis of this network monitoring data.

Active Monitoring Agents: {len(agents)}
Network Connections Sample:
{json.dumps(connections, default=str, indent=2)[:1500]}

Agent Status:
{json.dumps(agents, default=str, indent=2)[:1000]}

Please identify and analyze:
1. Potential security vulnerabilities
2. Unusual connection patterns that could indicate threats
3. Exposed services and ports
4. Agent security status and coverage gaps
5. Recommendations for improving security posture

Focus on practical security insights and actionable recommendations.
"""
        return prompt
    
    def _create_performance_insights_prompt(self, data: Dict) -> str:
        """Create prompt for performance insights"""
        recent_activity = data.get('recent_activity', {})
        
        prompt = f"""
Analyze network performance based on this monitoring data.

Recent Network Activity:
{json.dumps(recent_activity, default=str, indent=2)}

Connection Statistics:
{json.dumps(data.get('data_summary', {}), default=str, indent=2)}

Please provide insights on:
1. Network performance indicators
2. Connection volume trends
3. Potential bottlenecks or performance issues
4. Resource utilization patterns
5. Performance optimization recommendations

Focus on metrics that indicate network health and efficiency.
"""
        return prompt
    
    def _create_infrastructure_analysis_prompt(self, data: Dict) -> str:
        """Create prompt for infrastructure analysis"""
        hosts = data.get('hosts', [])
        scan_results = data.get('scan_results', [])[:10]
        
        prompt = f"""
Analyze the IT infrastructure based on this monitoring data.

Infrastructure Components:
- Monitored Hosts: {len(hosts)}
- Recent Scans: {len(scan_results)}

Host Configuration:
{json.dumps(hosts, default=str, indent=2)[:1500]}

Scan Results Sample:
{json.dumps(scan_results, default=str, indent=2)[:1000]}

Please provide analysis on:
1. Infrastructure composition and diversity
2. System configurations and standards
3. Monitoring coverage and gaps
4. Asset management insights
5. Infrastructure optimization opportunities

Focus on providing strategic insights about the IT environment.
"""
        return prompt
    
    def _create_recommendations_prompt(self, data: Dict) -> str:
        """Create prompt for recommendations"""
        prompt = f"""
Based on the comprehensive network analysis, provide strategic recommendations.

Data Analysis Summary:
{json.dumps(data.get('data_summary', {}), default=str, indent=2)}

Network Overview:
{json.dumps(data.get('metadata', {}), default=str, indent=2)}

Please provide:
1. Top 5 priority recommendations
2. Implementation roadmap
3. Risk mitigation strategies
4. Monitoring improvements
5. Long-term strategic suggestions

Format recommendations with clear action items and expected benefits.
"""
        return prompt
    
    # Analysis helper methods
    def _extract_key_points(self, content: str) -> List[str]:
        """Extract key points from AI-generated content"""
        # Simple extraction - could be enhanced with NLP
        lines = content.split('\n')
        key_points = []
        for line in lines:
            line = line.strip()
            if line and (line.startswith('•') or line.startswith('-') or line.startswith('*')):
                key_points.append(line[1:].strip())
            elif line and len(line) < 100 and ('critical' in line.lower() or 'important' in line.lower()):
                key_points.append(line)
        
        return key_points[:10]  # Limit to top 10
    
    def _assess_risk_level(self, data: Dict) -> str:
        """Assess overall risk level based on data"""
        agents = data.get('agents', [])
        active_agents = len([a for a in agents if a.get('status') == 'active'])
        total_agents = len(agents)
        
        if total_agents == 0:
            return 'HIGH - No monitoring agents active'
        elif active_agents / total_agents < 0.5:
            return 'MEDIUM - Limited monitoring coverage'
        else:
            return 'LOW - Good monitoring coverage'
    
    def _analyze_topology(self, data: Dict) -> Dict[str, Any]:
        """Analyze network topology"""
        hosts = data.get('hosts', [])
        connections = data.get('network_connections', [])
        
        return {
            'total_hosts': len(hosts),
            'total_connections': len(connections),
            'unique_destinations': len(set(c.get('dest_ip', '') for c in connections if c.get('dest_ip'))),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _analyze_connections(self, data: Dict) -> Dict[str, Any]:
        """Analyze connection patterns"""
        connections = data.get('network_connections', [])
        
        # Basic pattern analysis
        protocols = {}
        ports = {}
        
        for conn in connections:
            protocol = conn.get('protocol', 'unknown')
            port = conn.get('dest_port', 'unknown')
            
            protocols[protocol] = protocols.get(protocol, 0) + 1
            ports[str(port)] = ports.get(str(port), 0) + 1
        
        return {
            'top_protocols': dict(sorted(protocols.items(), key=lambda x: x[1], reverse=True)[:5]),
            'top_ports': dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'total_analyzed': len(connections)
        }
    
    def _identify_security_threats(self, data: Dict) -> List[str]:
        """Identify potential security threats"""
        threats = []
        
        # Check for inactive agents
        agents = data.get('agents', [])
        inactive_agents = [a for a in agents if a.get('status') != 'active']
        if inactive_agents:
            threats.append(f"{len(inactive_agents)} monitoring agents are inactive")
        
        # Check for unusual ports
        connections = data.get('network_connections', [])
        unusual_ports = []
        for conn in connections:
            port = conn.get('dest_port')
            if port and int(port) > 10000:  # High ports might be unusual
                unusual_ports.append(port)
        
        if unusual_ports:
            threats.append(f"Connections to unusual high ports detected: {set(unusual_ports)}")
        
        return threats[:5]  # Limit to top 5
    
    def _generate_security_recommendations(self, data: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        agents = data.get('agents', [])
        if len(agents) == 0:
            recommendations.append("Deploy monitoring agents to improve network visibility")
        
        hosts = data.get('hosts', [])
        offline_hosts = [h for h in hosts if h.get('status') != 'online']
        if offline_hosts:
            recommendations.append(f"Investigate {len(offline_hosts)} offline hosts for security implications")
        
        return recommendations
    
    def _analyze_performance_metrics(self, data: Dict) -> Dict[str, Any]:
        """Analyze performance metrics"""
        connections = data.get('network_connections', [])
        
        return {
            'total_connections': len(connections),
            'active_in_last_hour': len([c for c in connections if self._is_recent(c.get('last_seen'), hours=1)]),
            'connection_rate': len(connections) / max(1, len(data.get('hosts', []))),
            'analysis_timestamp': datetime.now().isoformat()
        }
    
    def _identify_bottlenecks(self, data: Dict) -> List[str]:
        """Identify potential bottlenecks"""
        bottlenecks = []
        
        # Check for overloaded hosts
        recent_activity = data.get('recent_activity', {})
        top_hosts = recent_activity.get('top_active_hosts', [])
        
        if top_hosts:
            most_active = top_hosts[0]
            if most_active.get('connection_count', 0) > 100:
                bottlenecks.append(f"Host {most_active.get('name')} has high connection volume")
        
        return bottlenecks
    
    def _create_asset_inventory(self, data: Dict) -> Dict[str, Any]:
        """Create asset inventory"""
        hosts = data.get('hosts', [])
        agents = data.get('agents', [])
        
        return {
            'total_assets': len(hosts),
            'monitored_assets': len([h for h in hosts if h.get('status') == 'online']),
            'agent_coverage': len(agents),
            'asset_types': self._categorize_assets(hosts),
            'last_updated': datetime.now().isoformat()
        }
    
    def _categorize_assets(self, hosts: List[Dict]) -> Dict[str, int]:
        """Categorize assets by type"""
        categories = {}
        for host in hosts:
            # Simple categorization based on naming patterns or other attributes
            name = host.get('name', '').lower()
            if 'server' in name or 'srv' in name:
                categories['servers'] = categories.get('servers', 0) + 1
            elif 'db' in name or 'database' in name:
                categories['databases'] = categories.get('databases', 0) + 1
            else:
                categories['workstations'] = categories.get('workstations', 0) + 1
        
        return categories
    
    def _analyze_configurations(self, data: Dict) -> Dict[str, Any]:
        """Analyze system configurations"""
        hosts = data.get('hosts', [])
        
        ssh_ports = {}
        for host in hosts:
            port = host.get('ssh_port', 22)
            ssh_ports[str(port)] = ssh_ports.get(str(port), 0) + 1
        
        return {
            'ssh_port_distribution': ssh_ports,
            'total_hosts_analyzed': len(hosts),
            'configuration_diversity': len(ssh_ports)
        }
    
    def _prioritize_actions(self, data: Dict) -> List[Dict[str, Any]]:
        """Prioritize recommended actions"""
        actions = []
        
        # Check agent coverage
        agents = data.get('agents', [])
        hosts = data.get('hosts', [])
        
        if len(agents) < len(hosts):
            actions.append({
                'priority': 'HIGH',
                'action': 'Deploy additional monitoring agents',
                'description': f'Only {len(agents)} agents for {len(hosts)} hosts',
                'effort': 'Medium'
            })
        
        # Check for offline hosts
        offline_hosts = [h for h in hosts if h.get('status') != 'online']
        if offline_hosts:
            actions.append({
                'priority': 'MEDIUM',
                'action': 'Investigate offline hosts',
                'description': f'{len(offline_hosts)} hosts are not responding',
                'effort': 'Low'
            })
        
        return actions[:5]  # Top 5 priorities
    
    def _create_implementation_guide(self, data: Dict) -> Dict[str, Any]:
        """Create implementation guide for recommendations"""
        return {
            'immediate_actions': [
                'Review agent status and restart failed agents',
                'Verify network connectivity to offline hosts',
                'Update monitoring configurations'
            ],
            'short_term_goals': [
                'Implement comprehensive monitoring coverage',
                'Establish baseline performance metrics',
                'Create incident response procedures'
            ],
            'long_term_strategy': [
                'Implement automated threat detection',
                'Develop capacity planning processes',
                'Establish security monitoring protocols'
            ]
        }
    
    def _compile_network_statistics(self, data: Dict) -> Dict[str, Any]:
        """Compile detailed network statistics"""
        connections = data.get('network_connections', [])
        hosts = data.get('hosts', [])
        
        return {
            'total_hosts': len(hosts),
            'online_hosts': len([h for h in hosts if h.get('status') == 'online']),
            'total_connections': len(connections),
            'unique_source_hosts': len(set(c.get('source_host_id') for c in connections if c.get('source_host_id'))),
            'unique_destinations': len(set(c.get('dest_ip') for c in connections if c.get('dest_ip'))),
            'data_collection_period': data.get('metadata', {}).get('time_range', 'Unknown')
        }
    
    def _analyze_individual_hosts(self, data: Dict) -> List[Dict[str, Any]]:
        """Analyze individual hosts"""
        hosts = data.get('hosts', [])
        connections = data.get('network_connections', [])
        
        host_analysis = []
        for host in hosts[:10]:  # Limit to first 10 hosts
            host_connections = [c for c in connections if c.get('source_host_id') == host.get('id')]
            
            analysis = {
                'host_name': host.get('name'),
                'ip_address': host.get('ip_address'),
                'status': host.get('status'),
                'connection_count': len(host_connections),
                'unique_destinations': len(set(c.get('dest_ip') for c in host_connections if c.get('dest_ip'))),
                'last_activity': max([c.get('last_seen', '') for c in host_connections], default='Unknown')
            }
            host_analysis.append(analysis)
        
        return host_analysis
    
    def _analyze_traffic_patterns(self, data: Dict) -> Dict[str, Any]:
        """Analyze traffic patterns"""
        connections = data.get('network_connections', [])
        
        # Analyze by time periods
        recent_connections = [c for c in connections if self._is_recent(c.get('last_seen'), hours=1)]
        daily_connections = [c for c in connections if self._is_recent(c.get('last_seen'), hours=24)]
        
        return {
            'recent_activity': {
                'last_hour': len(recent_connections),
                'last_24_hours': len(daily_connections),
                'total_recorded': len(connections)
            },
            'traffic_distribution': self._analyze_connections(data)
        }
    
    def _analyze_errors(self, data: Dict) -> Dict[str, Any]:
        """Analyze errors and issues"""
        errors = data.get('recent_errors', [])
        
        error_analysis = {
            'total_errors': len(errors),
            'error_types': {},
            'recent_errors': errors[:10]  # Last 10 errors
        }
        
        # Categorize errors
        for error in errors:
            level = error.get('level', 'unknown')
            error_analysis['error_types'][level] = error_analysis['error_types'].get(level, 0) + 1
        
        return error_analysis
    
    def _is_recent(self, timestamp: str, hours: int = 1) -> bool:
        """Check if timestamp is within the specified hours"""
        if not timestamp:
            return False
        
        try:
            ts = datetime.fromisoformat(timestamp.replace(' ', 'T'))
            cutoff = datetime.now() - timedelta(hours=hours)
            return ts > cutoff
        except:
            return False

if __name__ == "__main__":
    # Basic test
    print("AI Report Generator module loaded successfully")
