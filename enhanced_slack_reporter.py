#!/usr/bin/env python3
"""
Enhanced DAST Slack Reporter with AI Classification
Combines vulnerability scanning with AI-powered classification and remediation
"""

import json
import os
import sys
from datetime import datetime
from typing import Dict, List, Optional
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from ai_classifier import VulnerabilityClassifier

# Load environment variables
load_dotenv()


class EnhancedDastSlackReporter:
    """Enhanced DAST reporter with AI classification"""
    
    def __init__(self, slack_token: str, channel: str, use_ai: bool = True):
        """
        Initialize the Enhanced DAST Slack Reporter
        
        Args:
            slack_token: Slack Bot Token
            channel: Slack channel to send reports to
            use_ai: Whether to use AI classification (default: True)
        """
        self.client = WebClient(token=slack_token)
        self.channel = channel
        self.use_ai = use_ai
        
        # Initialize AI classifier if enabled
        self.classifier = VulnerabilityClassifier(provider="auto") if use_ai else None
        
        # Severity color mapping
        self.severity_colors = {
            'High': '#FF0000',
            'Medium': '#FFA500',
            'Low': '#FFFF00',
            'Informational': '#0000FF'
        }
        
        # Category emojis
        self.category_emojis = {
            'XSS': '🔓',
            'SQLi': '💉',
            'AUTH': '🔐',
            'AUTHZ': '🚫',
            'CSRF': '🔄',
            'REDIRECT': '↗️',
            'HEADER': '📋',
            'SENSITIVE': '🔍',
            'CONFIG': '⚙️',
            'CRYPTO': '🔒',
            'INJECTION': '💉',
            'OTHER': '⚠️'
        }
    
    def parse_zap_report_with_classification(self, report_path: str) -> Dict:
        """
        Parse ZAP JSON report and classify vulnerabilities with AI
        
        Args:
            report_path: Path to ZAP JSON report file
            
        Returns:
            Dictionary containing parsed and classified vulnerability data
        """
        try:
            with open(report_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error reading report: {e}")
            return {}
        
        # Extract alerts
        alerts = data.get('site', [{}])[0].get('alerts', [])
        
        # Convert to our format
        vulnerabilities = []
        for alert in alerts:
            vuln = {
                'name': alert.get('name', 'Unknown'),
                'description': alert.get('desc', ''),
                'solution': alert.get('solution', ''),
                'confidence': alert.get('confidence', ''),
                'risk_level': self._map_risk_code(alert.get('riskcode', '0')),
                'instances': len(alert.get('instances', [])),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', '')
            }
            vulnerabilities.append(vuln)
        
        # Classify vulnerabilities with AI if enabled
        if self.classifier:
            print("🤖 Classifying vulnerabilities with AI...")
            classified_vulnerabilities = self.classifier.classify_batch(vulnerabilities)
            stats = self.classifier.get_statistics(classified_vulnerabilities)
        else:
            classified_vulnerabilities = vulnerabilities
            stats = {}
        
        # Organize by severity
        by_severity = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }
        
        for vuln in classified_vulnerabilities:
            classification = vuln.get('classification', {})
            severity = classification.get('adjusted_severity', vuln['risk_level'])
            by_severity[severity].append(vuln)
        
        # Create summary
        summary = {
            'total_alerts': len(alerts),
            'high_count': len(by_severity['High']),
            'medium_count': len(by_severity['Medium']),
            'low_count': len(by_severity['Low']),
            'info_count': len(by_severity['Informational']),
            'scan_timestamp': datetime.now().isoformat(),
            'target_url': data.get('site', [{}])[0].get('@name', 'Unknown'),
            'ai_stats': stats
        }
        
        return {
            'summary': summary,
            'vulnerabilities': by_severity,
            'classified_vulnerabilities': classified_vulnerabilities
        }
    
    def _map_risk_code(self, risk_code: str) -> str:
        """Map ZAP risk code to severity level"""
        mapping = {'3': 'High', '2': 'Medium', '1': 'Low', '0': 'Informational'}
        return mapping.get(str(risk_code), 'Informational')
    
    def create_enhanced_summary_message(self, report_data: Dict, pr_number: Optional[str] = None) -> str:
        """
        Create enhanced summary message with AI insights
        
        Args:
            report_data: Parsed and classified ZAP report data
            pr_number: Pull request number (if applicable)
            
        Returns:
            Formatted summary message
        """
        summary = report_data.get('summary', {})
        ai_stats = summary.get('ai_stats', {})
        
        # Header
        header = "🔒 **DAST Security Scan Results**"
        if pr_number:
            header += f" - PR #{pr_number}"
        
        # Risk summary
        risk_summary = []
        if summary.get('high_count', 0) > 0:
            risk_summary.append(f"🔴 {summary['high_count']} High")
        if summary.get('medium_count', 0) > 0:
            risk_summary.append(f"🟠 {summary['medium_count']} Medium")
        if summary.get('low_count', 0) > 0:
            risk_summary.append(f"🟡 {summary['low_count']} Low")
        if summary.get('info_count', 0) > 0:
            risk_summary.append(f"🔵 {summary['info_count']} Info")
        
        if not risk_summary:
            message = f"{header}\n✅ No security vulnerabilities found!"
        else:
            message = f"{header}\n📊 **Findings:** {', '.join(risk_summary)}"
        
        # Add target
        message += f"\n🎯 **Target:** {summary.get('target_url', 'Unknown')}"
        
        # Add AI classification stats if available
        if ai_stats.get('ai_classified', 0) > 0:
            message += f"\n🤖 **AI Analysis:** {ai_stats['ai_classified']}/{ai_stats['total']} findings classified with AI"
            
            # Show category breakdown
            if ai_stats.get('by_category'):
                top_categories = sorted(ai_stats['by_category'].items(), key=lambda x: x[1], reverse=True)[:3]
                category_str = ', '.join([f"{self.category_emojis.get(cat, '⚠️')} {cat}" for cat, count in top_categories])
                message += f"\n📁 **Top Issues:** {category_str}"
        
        # Add timestamp
        scan_time = summary.get('scan_timestamp', '')
        if scan_time:
            message += f"\n🕐 **Scan Time:** {scan_time[:19].replace('T', ' ')}"
        
        return message
    
    def create_enhanced_blocks(self, report_data: Dict) -> List[Dict]:
        """
        Create enhanced Slack blocks with AI classification
        
        Args:
            report_data: Parsed and classified ZAP report data
            
        Returns:
            List of Slack block kit blocks
        """
        blocks = []
        classified_vulns = report_data.get('classified_vulnerabilities', [])
        
        # Group by severity
        by_severity = {}
        for vuln in classified_vulns:
            classification = vuln.get('classification', {})
            severity = classification.get('adjusted_severity', vuln['risk_level'])
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(vuln)
        
        # Process each severity level
        for severity in ['High', 'Medium', 'Low']:
            vulns = by_severity.get(severity, [])
            if not vulns:
                continue
            
            # Severity header
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{severity} Risk Vulnerabilities ({len(vulns)}):*"
                }
            })
            
            # List vulnerabilities with AI classification
            for vuln in vulns[:5]:
                classification = vuln.get('classification', {})
                category = classification.get('category', 'OTHER')
                category_name = classification.get('category_name', 'Other')
                confidence = classification.get('confidence', 0)
                emoji = self.category_emojis.get(category, '⚠️')
                
                vuln_text = f"{emoji} *{vuln['name']}*"
                
                # Add category if AI classified
                if 'ai' in classification.get('method', ''):
                    vuln_text += f" [`{category_name}` - {confidence:.0%} confidence]"
                
                if vuln.get('instances', 0) > 1:
                    vuln_text += f" ({vuln['instances']} instances)"
                
                # Add explanation if available
                explanation = classification.get('explanation', '')
                if explanation:
                    vuln_text += f"\n_{explanation}_"
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": vuln_text
                    }
                })
            
            if len(vulns) > 5:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"... and {len(vulns) - 5} more {severity.lower()} risk issues"
                    }
                })
            
            blocks.append({"type": "divider"})
        
        return blocks
    
    def send_enhanced_report(self, report_data: Dict, pr_number: Optional[str] = None) -> bool:
        """
        Send enhanced DAST report with AI classification to Slack
        
        Args:
            report_data: Parsed and classified ZAP report data
            pr_number: Pull request number (if applicable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            summary = report_data.get('summary', {})
            
            # Create main message
            main_message = self.create_enhanced_summary_message(report_data, pr_number)
            
            # Determine color
            if summary.get('high_count', 0) > 0:
                color = self.severity_colors['High']
            elif summary.get('medium_count', 0) > 0:
                color = self.severity_colors['Medium']
            elif summary.get('low_count', 0) > 0:
                color = self.severity_colors['Low']
            else:
                color = '#00FF00'
            
            # Create attachment
            attachment = {
                "color": color,
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": main_message
                        }
                    }
                ]
            }
            
            # Add detailed blocks
            if summary.get('total_alerts', 0) > 0:
                detailed_blocks = self.create_enhanced_blocks(report_data)
                attachment["blocks"].extend(detailed_blocks)
            
            # Send to Slack
            response = self.client.chat_postMessage(
                channel=self.channel,
                text="🤖 AI-Enhanced DAST Security Scan Results",
                attachments=[attachment]
            )
            
            print(f"✅ Enhanced report sent successfully to Slack channel: {self.channel}")
            return True
            
        except SlackApiError as e:
            print(f"❌ Error sending message to Slack: {e.response['error']}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return False


def main():
    """Main function"""
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    report_path = os.getenv('ZAP_REPORT_PATH', 'report.json')
    pr_number = os.getenv('GITHUB_PR_NUMBER')
    use_ai = os.getenv('USE_AI_CLASSIFICATION', 'true').lower() == 'true'
    
    if not os.path.exists(report_path):
        print(f"❌ ZAP report file not found: {report_path}")
        sys.exit(1)
    
    if not slack_token:
        print("❌ SLACK_BOT_TOKEN not found")
        sys.exit(1)
    
    # Initialize enhanced reporter
    reporter = EnhancedDastSlackReporter(slack_token, slack_channel, use_ai=use_ai)
    
    # Parse and classify
    print(f"📖 Parsing ZAP report: {report_path}")
    report_data = reporter.parse_zap_report_with_classification(report_path)
    
    if not report_data:
        print("❌ Failed to parse ZAP report")
        sys.exit(1)
    
    # Send report
    print(f"📤 Sending enhanced report to Slack...")
    success = reporter.send_enhanced_report(report_data, pr_number)
    
    if success:
        print("🎉 AI-enhanced DAST report sent successfully!")
        sys.exit(0)
    else:
        print("❌ Failed to send report")
        sys.exit(1)


if __name__ == "__main__":
    main()
