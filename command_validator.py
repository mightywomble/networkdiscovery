#!/usr/bin/env python3
"""
Command Validator for NetworkMap Chatbot
Analyzes generated bash scripts for security risks and provides detailed explanations
"""

import re
import json
from typing import Dict, List, Any, Tuple
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CommandValidator:
    """Validates bash scripts for security and safety concerns"""
    
    def __init__(self):
        """Initialize the Command Validator"""
        
        # Define dangerous command patterns
        self.dangerous_patterns = {
            # File system destructive operations
            'file_deletion': {
                'patterns': [
                    r'\brm\s+(-[rf]*\s+)?/',
                    r'\brm\s+(-[rf]*\s+)?\*',
                    r'\brmdir\s+',
                    r'\bshred\s+',
                    r'\bwipe\s+',
                ],
                'risk_level': 'critical',
                'description': 'File deletion commands that could remove important data',
                'examples': ['rm -rf /', 'rm *', 'rmdir /important']
            },
            
            # Disk operations
            'disk_operations': {
                'patterns': [
                    r'\bdd\s+',
                    r'\bmkfs\.',
                    r'\bfdisk\s+',
                    r'\bparted\s+',
                    r'\bwipefs\s+',
                ],
                'risk_level': 'critical',
                'description': 'Low-level disk operations that could destroy data or partitions',
                'examples': ['dd if=/dev/zero', 'mkfs.ext4', 'fdisk /dev/sda']
            },
            
            # System control
            'system_control': {
                'patterns': [
                    r'\breboot\b',
                    r'\bshutdown\s+',
                    r'\bhalt\b',
                    r'\binit\s+[06]',
                    r'\bpoweroff\b',
                ],
                'risk_level': 'high',
                'description': 'System restart/shutdown commands',
                'examples': ['reboot', 'shutdown -h now', 'init 0']
            },
            
            # User management
            'user_management': {
                'patterns': [
                    r'\buserdel\s+',
                    r'\bgroupdel\s+',
                    r'\bpasswd\s+',
                    r'\bchpasswd\s+',
                    r'\buseradd\s+',
                ],
                'risk_level': 'high',
                'description': 'User account management commands',
                'examples': ['userdel username', 'passwd root', 'chpasswd']
            },
            
            # Network security
            'network_security': {
                'patterns': [
                    r'\biptables\s+-F',
                    r'\bufw\s+(--force\s+)?disable',
                    r'\bfirewall-cmd\s+.*--permanent',
                ],
                'risk_level': 'high',
                'description': 'Firewall and network security modifications',
                'examples': ['iptables -F', 'ufw --force disable']
            },
            
            # Service control
            'service_control': {
                'patterns': [
                    r'\bsystemctl\s+stop\s+',
                    r'\bsystemctl\s+disable\s+',
                    r'\bservice\s+\w+\s+stop',
                ],
                'risk_level': 'medium',
                'description': 'Service stop/disable commands',
                'examples': ['systemctl stop sshd', 'service apache2 stop']
            },
            
            # Permission changes
            'permission_changes': {
                'patterns': [
                    r'\bchmod\s+777\s+',
                    r'\bchmod\s+\d*7\d*7',
                    r'\bchown\s+.*root',
                ],
                'risk_level': 'medium',
                'description': 'Potentially dangerous permission changes',
                'examples': ['chmod 777 /', 'chown root:root /etc/passwd']
            },
            
            # Network operations
            'network_operations': {
                'patterns': [
                    r'\bnmap\s+',
                    r'\bnetcat\s+',
                    r'\bnc\s+',
                    r'\btelnet\s+',
                ],
                'risk_level': 'low',
                'description': 'Network scanning or connection commands',
                'examples': ['nmap -p', 'netcat -l', 'nc -v']
            },
            
            # File downloads
            'file_downloads': {
                'patterns': [
                    r'\bcurl\s+.*\s+-o\s+',
                    r'\bwget\s+',
                    r'\bftp\s+',
                ],
                'risk_level': 'low',
                'description': 'File download commands that could introduce malware',
                'examples': ['curl -o file http://...', 'wget http://...']
            }
        }
        
        # Define safe command patterns
        self.safe_patterns = [
            r'\bls\s+', r'\bcat\s+', r'\bless\s+', r'\bmore\s+', r'\bhead\s+', r'\btail\s+',
            r'\bgrep\s+', r'\bawk\s+', r'\bsed\s+', r'\bcut\s+', r'\bsort\s+', r'\buniq\s+',
            r'\bwc\s+', r'\bfind\s+.*-type\s+f', r'\bdf\s+', r'\bdu\s+', r'\bfree\s+',
            r'\bps\s+', r'\btop\s+', r'\bhtop\s+', r'\buptime\s+', r'\bdate\s+',
            r'\bhostname\s+', r'\bwhoami\s+', r'\bid\s+', r'\bgroups\s+',
            r'\bip\s+addr', r'\bip\s+route', r'\bss\s+', r'\bnetstat\s+',
            r'\bmount\s+\|\s+grep', r'\blsblk\s+', r'\blscpu\s+', r'\blsmem\s+',
            r'\becho\s+', r'\bprintf\s+',
        ]
    
    def validate_script(self, script: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate a bash script for security and safety
        
        Args:
            script: The bash script to validate
            context: Additional context about the script generation
            
        Returns:
            dict: Validation results with risk assessment and recommendations
        """
        try:
            logger.info("Starting script validation")
            
            validation_result = {
                'script': script,
                'validated_at': datetime.now().isoformat(),
                'overall_risk': 'safe',
                'is_approved': True,
                'warnings': [],
                'risks': [],
                'safe_commands': [],
                'recommendations': [],
                'detailed_analysis': {},
                'execution_approval': 'auto_approved'
            }
            
            # Analyze script line by line
            lines = script.split('\n')
            line_analysis = []
            
            for line_num, line in enumerate(lines, 1):
                line_result = self._analyze_line(line, line_num)
                if line_result:
                    line_analysis.append(line_result)
            
            # Aggregate results
            validation_result['detailed_analysis']['lines'] = line_analysis
            validation_result = self._aggregate_analysis(validation_result, line_analysis)
            
            # Determine overall approval status
            validation_result = self._determine_approval_status(validation_result)
            
            logger.info(f"Script validation completed - Risk: {validation_result['overall_risk']}")
            return validation_result
            
        except Exception as e:
            logger.error(f"Error during script validation: {e}")
            return {
                'script': script,
                'validated_at': datetime.now().isoformat(),
                'overall_risk': 'error',
                'is_approved': False,
                'error': str(e),
                'warnings': [f'Validation failed: {str(e)}'],
                'risks': ['Unable to validate script safety'],
                'execution_approval': 'denied'
            }
    
    def _analyze_line(self, line: str, line_num: int) -> Dict[str, Any]:
        """Analyze a single line of the script"""
        line = line.strip()
        
        # Skip comments and empty lines
        if not line or line.startswith('#'):
            return None
        
        line_result = {
            'line_number': line_num,
            'content': line,
            'risk_level': 'safe',
            'issues': [],
            'is_safe_command': False
        }
        
        # Check against dangerous patterns
        for category, category_data in self.dangerous_patterns.items():
            for pattern in category_data['patterns']:
                if re.search(pattern, line, re.IGNORECASE):
                    issue = {
                        'category': category,
                        'risk_level': category_data['risk_level'],
                        'description': category_data['description'],
                        'pattern_matched': pattern,
                        'examples': category_data['examples']
                    }
                    line_result['issues'].append(issue)
                    
                    # Update line risk level to highest found
                    current_risk = line_result['risk_level']
                    new_risk = category_data['risk_level']
                    if self._risk_level_priority(new_risk) > self._risk_level_priority(current_risk):
                        line_result['risk_level'] = new_risk
        
        # Check if it's a known safe command
        for safe_pattern in self.safe_patterns:
            if re.search(safe_pattern, line, re.IGNORECASE):
                line_result['is_safe_command'] = True
                break
        
        return line_result if line_result['issues'] or line_result['is_safe_command'] else None
    
    def _risk_level_priority(self, risk_level: str) -> int:
        """Return numeric priority for risk levels"""
        priorities = {
            'safe': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
            'error': 5
        }
        return priorities.get(risk_level, 0)
    
    def _aggregate_analysis(self, validation_result: Dict, line_analysis: List[Dict]) -> Dict[str, Any]:
        """Aggregate line analysis into overall script assessment"""
        
        risk_counts = {'safe': 0, 'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        all_issues = []
        safe_command_count = 0
        
        for line_data in line_analysis:
            risk_level = line_data['risk_level']
            risk_counts[risk_level] += 1
            
            if line_data['is_safe_command']:
                safe_command_count += 1
                validation_result['safe_commands'].append({
                    'line': line_data['line_number'],
                    'command': line_data['content'][:50] + ('...' if len(line_data['content']) > 50 else '')
                })
            
            for issue in line_data['issues']:
                all_issues.append({
                    'line': line_data['line_number'],
                    'command': line_data['content'],
                    **issue
                })
        
        # Determine overall risk level
        if risk_counts['critical'] > 0:
            validation_result['overall_risk'] = 'critical'
        elif risk_counts['high'] > 0:
            validation_result['overall_risk'] = 'high'
        elif risk_counts['medium'] > 0:
            validation_result['overall_risk'] = 'medium'
        elif risk_counts['low'] > 0:
            validation_result['overall_risk'] = 'low'
        else:
            validation_result['overall_risk'] = 'safe'
        
        # Categorize issues
        for issue in all_issues:
            if issue['risk_level'] in ['critical', 'high']:
                validation_result['risks'].append({
                    'line': issue['line'],
                    'risk_level': issue['risk_level'],
                    'category': issue['category'],
                    'description': issue['description'],
                    'command': issue['command'][:100] + ('...' if len(issue['command']) > 100 else '')
                })
            else:
                validation_result['warnings'].append({
                    'line': issue['line'],
                    'risk_level': issue['risk_level'],
                    'category': issue['category'],
                    'description': issue['description'],
                    'command': issue['command'][:100] + ('...' if len(issue['command']) > 100 else '')
                })
        
        # Add summary statistics
        validation_result['detailed_analysis']['summary'] = {
            'total_lines_analyzed': len(line_analysis),
            'safe_commands_found': safe_command_count,
            'risk_distribution': risk_counts,
            'issues_found': len(all_issues)
        }
        
        return validation_result
    
    def _determine_approval_status(self, validation_result: Dict) -> Dict[str, Any]:
        """Determine if script should be auto-approved or require manual approval"""
        
        overall_risk = validation_result['overall_risk']
        risk_count = len(validation_result['risks'])
        warning_count = len(validation_result['warnings'])
        
        if overall_risk in ['critical', 'high']:
            validation_result['is_approved'] = False
            validation_result['execution_approval'] = 'manual_review_required'
            validation_result['recommendations'].extend([
                'This script contains high-risk operations that require manual review',
                'Consider using safer alternatives or running commands individually',
                'Ensure you have proper backups before proceeding'
            ])
            
        elif overall_risk == 'medium' and risk_count > 0:
            validation_result['is_approved'] = False
            validation_result['execution_approval'] = 'user_confirmation_required'
            validation_result['recommendations'].extend([
                'This script contains medium-risk operations',
                'Please review the identified risks before executing',
                'Consider testing on a non-production system first'
            ])
            
        elif overall_risk == 'low' or warning_count > 0:
            validation_result['is_approved'] = True
            validation_result['execution_approval'] = 'approved_with_warnings'
            validation_result['recommendations'].extend([
                'Script appears safe but contains some operations that should be monitored',
                'Review the warnings before executing'
            ])
            
        else:
            validation_result['is_approved'] = True
            validation_result['execution_approval'] = 'auto_approved'
            validation_result['recommendations'].append(
                'Script appears safe and contains only read-only operations'
            )
        
        return validation_result
    
    def create_validation_report(self, validation_result: Dict) -> str:
        """Create a human-readable validation report"""
        
        report_lines = [
            "=== SCRIPT VALIDATION REPORT ===",
            f"Validated at: {validation_result['validated_at']}",
            f"Overall Risk Level: {validation_result['overall_risk'].upper()}",
            f"Execution Status: {validation_result['execution_approval'].replace('_', ' ').title()}",
            ""
        ]
        
        # Summary statistics
        if 'detailed_analysis' in validation_result and 'summary' in validation_result['detailed_analysis']:
            summary = validation_result['detailed_analysis']['summary']
            report_lines.extend([
                "ANALYSIS SUMMARY:",
                f"• Lines analyzed: {summary['total_lines_analyzed']}",
                f"• Safe commands found: {summary['safe_commands_found']}",
                f"• Issues found: {summary['issues_found']}",
                ""
            ])
        
        # Critical risks
        if validation_result['risks']:
            report_lines.extend(["CRITICAL RISKS IDENTIFIED:"])
            for risk in validation_result['risks']:
                report_lines.append(f"• Line {risk['line']}: {risk['description']}")
                report_lines.append(f"  Command: {risk['command']}")
            report_lines.append("")
        
        # Warnings
        if validation_result['warnings']:
            report_lines.extend(["WARNINGS:"])
            for warning in validation_result['warnings']:
                report_lines.append(f"• Line {warning['line']}: {warning['description']}")
            report_lines.append("")
        
        # Safe commands
        if validation_result['safe_commands']:
            report_lines.extend(["SAFE OPERATIONS IDENTIFIED:"])
            for safe_cmd in validation_result['safe_commands'][:5]:  # Show first 5
                report_lines.append(f"• Line {safe_cmd['line']}: {safe_cmd['command']}")
            if len(validation_result['safe_commands']) > 5:
                report_lines.append(f"  ... and {len(validation_result['safe_commands']) - 5} more")
            report_lines.append("")
        
        # Recommendations
        if validation_result['recommendations']:
            report_lines.extend(["RECOMMENDATIONS:"])
            for rec in validation_result['recommendations']:
                report_lines.append(f"• {rec}")
            report_lines.append("")
        
        return "\n".join(report_lines)
    
    def get_safety_explanation(self, risk_level: str) -> Dict[str, Any]:
        """Get detailed explanation of safety levels"""
        
        explanations = {
            'safe': {
                'title': 'Safe Script',
                'description': 'This script contains only read-only operations and poses no risk to system integrity.',
                'color': 'success',
                'icon': 'fa-check-circle',
                'can_auto_execute': True
            },
            'low': {
                'title': 'Low Risk',
                'description': 'This script contains some operations that should be monitored but are generally safe.',
                'color': 'info',
                'icon': 'fa-info-circle',
                'can_auto_execute': True
            },
            'medium': {
                'title': 'Medium Risk',
                'description': 'This script contains operations that could affect system behavior. Review recommended.',
                'color': 'warning',
                'icon': 'fa-exclamation-triangle',
                'can_auto_execute': False
            },
            'high': {
                'title': 'High Risk',
                'description': 'This script contains potentially dangerous operations. Manual review required.',
                'color': 'danger',
                'icon': 'fa-exclamation-triangle',
                'can_auto_execute': False
            },
            'critical': {
                'title': 'Critical Risk',
                'description': 'This script contains dangerous operations that could damage the system. Do not execute without careful review.',
                'color': 'danger',
                'icon': 'fa-times-circle',
                'can_auto_execute': False
            }
        }
        
        return explanations.get(risk_level, explanations['medium'])

if __name__ == "__main__":
    # Basic test
    validator = CommandValidator()
    
    # Test with a safe script
    safe_script = """#!/bin/bash
echo "System information"
hostname
uptime
df -h
free -h
"""
    
    result = validator.validate_script(safe_script)
    print("Safe script validation:")
    print(validator.create_validation_report(result))
    print("\n" + "="*50 + "\n")
    
    # Test with a risky script
    risky_script = """#!/bin/bash
echo "Risky operations"
rm -rf /tmp/*
chmod 777 /etc/passwd
"""
    
    result = validator.validate_script(risky_script)
    print("Risky script validation:")
    print(validator.create_validation_report(result))
