#!/usr/bin/env python3
"""
Standalone AI Report HTML Formatter
Extracted from app.py for independent testing
"""

def format_ai_report_to_html(report):
    """Format AI report dictionary into readable HTML"""
    if not report:
        return "<p>No report data available.</p>"
    
    html = []
    
    # Add metadata header if available
    metadata = report.get('metadata', {})
    if metadata:
        html.append('<div class="nm-report-section">')
        html.append('<h2>Report Information</h2>')
        html.append(f'<p><strong>Generated:</strong> {metadata.get("generated_at", "Unknown")}</p>')
        html.append(f'<p><strong>AI Model:</strong> {metadata.get("ai_model", "Unknown").title()}</p>')
        html.append(f'<p><strong>Data Source:</strong> {metadata.get("data_type", "Unknown").replace("_", " ").title()}</p>')
        if metadata.get('generation_time'):
            html.append(f'<p><strong>Generation Time:</strong> {metadata.get("generation_time")}</p>')
        html.append('</div>')
    
    # Check if this is an error report
    if 'error_details' in report:
        html.append('<div class="nm-report-section">')
        html.append('<h2 style="color: #c9190b;">Report Generation Failed</h2>')
        html.append(f'<p>{report.get("error_details", "Unknown error occurred.")}</p>')
        html.append('</div>')
        return '\n'.join(html)
    
    # Format each section
    sections = [
        ('executive_summary', 'Executive Summary'),
        ('network_overview', 'Network Overview'), 
        ('security_analysis', 'Security Analysis'),
        ('performance_insights', 'Performance Insights'),
        ('infrastructure_analysis', 'Infrastructure Analysis'),
        ('recommendations', 'Recommendations'),
        ('detailed_findings', 'Detailed Findings')
    ]
    
    for section_key, section_title in sections:
        section = report.get(section_key, {})
        if not section:
            continue
            
        html.append('<div class="nm-report-section">')
        html.append(f'<h2>{section_title}</h2>')
        
        # Handle different section formats
        if 'summary' in section:
            html.append(f'<p>{section["summary"]}</p>')
        elif 'analysis' in section:
            html.append(f'<p>{section["analysis"]}</p>')
        
        # Add key points if available
        if 'key_points' in section and section['key_points']:
            html.append('<h4>Key Points:</h4>')
            html.append('<ul>')
            for point in section['key_points']:
                html.append(f'<li>{point}</li>')
            html.append('</ul>')
        
        # Add recommendations if available
        if 'recommendations' in section and section['recommendations']:
            html.append('<h4>Recommendations:</h4>')
            html.append('<ul>')
            for rec in section['recommendations']:
                html.append(f'<li>{rec}</li>')
            html.append('</ul>')
        
        # Add threats if available (security section)
        if 'threats_identified' in section and section['threats_identified']:
            html.append('<h4>Threats Identified:</h4>')
            html.append('<ul>')
            for threat in section['threats_identified']:
                html.append(f'<li>{threat}</li>')
            html.append('</ul>')
        
        # Add error information if section failed
        if 'error' in section:
            html.append(f'<p style="color: #c9190b;"><em>Error generating this section: {section["error"]}</em></p>')
        
        html.append('</div>')
    
    if not html or len(html) == 0:
        return "<p>Report generated but no displayable content found.</p>"
    
    return '\n'.join(html)

if __name__ == "__main__":
    # Test the formatter
    sample_report = {
        'metadata': {
            'generated_at': '2025-08-16T21:20:00',
            'ai_model': 'gemini',
            'data_type': 'all_data',
            'generation_time': '3.8 seconds'
        },
        'executive_summary': {
            'title': 'Executive Summary',
            'summary': 'Network analysis shows excellent performance with strong security posture.',
            'key_points': [
                'All monitored hosts are operational',
                'Network traffic patterns are normal',
                'Security monitoring is active and effective'
            ],
            'risk_level': 'LOW'
        },
        'network_overview': {
            'title': 'Network Overview',
            'analysis': 'The network consists of 5 monitored hosts with healthy connectivity patterns.',
        },
        'security_analysis': {
            'title': 'Security Analysis',
            'analysis': 'Comprehensive security scan shows no immediate threats.',
            'threats_identified': [
                'No critical security issues detected',
                'All security agents are functioning normally'
            ]
        }
    }
    
    formatted = format_ai_report_to_html(sample_report)
    print("✓ AI Report HTML Formatter Test")
    print(f"Generated {len(formatted)} characters of HTML")
    print("\n--- Sample Output ---")
    print(formatted[:500] + "...")
