#!/usr/bin/env python3
"""
AI-Enhanced DAST Slack Reporter
Processes OWASP ZAP scan results with AI classification and sends to Slack
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

# Load environment variables
load_dotenv()

# Import AI classifier
try:
    from ai_classifier_v2 import AIVulnerabilityClassifier
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False
    print("⚠️  AI classifier not available - using basic classification")


class AIEnhancedSlackReporter:
    """
    Enhanced Slack reporter with AI-powered vulnerability classification
    """
    
    def __init__(self, slack_token: str, channel: str, use_ai: bool = True):
        """
        Initialize the AI-Enhanced DAST Slack Reporter
        
        Args:
            slack_token: Slack Bot Token
            channel: Slack channel to send reports to
            use_ai: Whether to use AI classification (default: True)
        """
        self.client = WebClient(token=slack_token)
        self.channel = channel
        self.use_ai = use_ai and AI_AVAILABLE
        
        # Initialize AI classifier if enabled
        self.ai_classifier = None
        if self.use_ai:
            try:
                self.ai_classifier = AIVulnerabilityClassifier()
                print("🤖 AI-powered classification enabled")
            except Exception as e:
                print(f"⚠️  AI classifier initialization failed: {e}")
                self.use_ai = False
        
        # Severity color mapping for Slack attachments
        self.severity_colors = {
            'critical': '#8B0000',   # Dark Red
            'high': '#FF0000',       # Red
            'medium': '#FFA500',     # Orange
            'low': '#FFFF00',        # Yellow
            'informational': '#87CEEB'  # Sky Blue
        }
        
        # Risk level mapping
        self.risk_levels = {
            '3': 'High',
            '2': 'Medium',
            '1': 'Low',
            '0': 'Informational'
        }
        
        # Category emojis for better visualization
        self.category_emojis = {
            'XSS': '🔴',
            'SQLi': '💉',
            'AUTH': '🔐',
            'AUTHZ': '🚫',
            'CSRF': '🎭',
            'REDIRECT': '↪️',
            'HEADER': '📋',
            'CRYPTO': '🔒',
            'SENSITIVE': '🔓',
            'CONFIG': '⚙️',
            'INJECTION': '💊',
            'RCE': '💣',
            'OTHER': '⚠️'
        }

    def parse_zap_report(self, report_path: str) -> Dict:
        """
        Parse ZAP JSON report and extract key metrics with AI classification
        
        Args:
            report_path: Path to ZAP JSON report file
            
        Returns:
            Dictionary containing parsed vulnerability data with AI insights
        """
        try:
            with open(report_path, 'r', encoding='utf-8') as file:
                data = json.load(file)
        except FileNotFoundError:
            print(f"Error: Report file not found at {report_path}")
            return {}
        except json.JSONDecodeError:
            print(f"Error: Invalid JSON in report file {report_path}")
            return {}
        
        # Extract alerts from ZAP report
        alerts = data.get('site', [{}])[0].get('alerts', [])
        
        print(f"\n📊 Processing {len(alerts)} vulnerabilities...")
        
        # Categorize vulnerabilities by risk level
        vulnerabilities = {
            'Critical': [],
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }
        
        # AI-enhanced classification
        ai_classifications = []
        if self.use_ai and self.ai_classifier and alerts:
            print("🤖 Running AI classification...")
            # Prepare vulnerabilities for AI classification
            vulns_for_ai = []
            for alert in alerts:
                vulns_for_ai.append({
                    'name': alert.get('name', 'Unknown'),
                    'description': alert.get('desc', ''),
                    'solution': alert.get('solution', ''),
                    'risk': self.risk_levels.get(alert.get('riskcode', '0'), 'Unknown'),
                    'confidence': alert.get('confidence', '')
                })
            
            # Classify with AI
            try:
                ai_classifications = self.ai_classifier.bulk_classify(vulns_for_ai)
            except Exception as e:
                print(f"⚠️  AI classification failed: {e}")
                ai_classifications = []
        
        # Process alerts with AI insights
        for idx, alert in enumerate(alerts):
            risk_level = self.risk_levels.get(alert.get('riskcode', '0'), 'Informational')
            
            vuln_info = {
                'name': alert.get('name', 'Unknown'),
                'description': alert.get('desc', ''),
                'solution': alert.get('solution', ''),
                'confidence': alert.get('confidence', ''),
                'instances': len(alert.get('instances', [])),
                'cweid': alert.get('cweid', ''),
                'wascid': alert.get('wascid', '')
            }
            
            # Add AI insights if available
            if idx < len(ai_classifications):
                ai_result = ai_classifications[idx]
                vuln_info['ai_category'] = ai_result.get('category', 'OTHER')
                vuln_info['ai_severity'] = ai_result.get('severity_score', 5.0)
                vuln_info['ai_confidence'] = ai_result.get('confidence', 'medium')
                vuln_info['ai_provider'] = ai_result.get('provider', 'pattern_matching')
                vuln_info['attack_vector'] = ai_result.get('attack_vector', 'unknown')
                vuln_info['exploitability'] = ai_result.get('exploitability', 'unknown')
                vuln_info['business_impact'] = ai_result.get('business_impact', '')
                vuln_info['remediation_priority'] = ai_result.get('remediation_priority', risk_level.lower())
                
                # Adjust risk level based on AI severity if critical
                if ai_result.get('severity_score', 0) >= 9.0 and risk_level != 'Informational':
                    risk_level = 'Critical'
            
            vulnerabilities[risk_level].append(vuln_info)
        
        # Calculate summary statistics
        summary = {
            'total_alerts': len(alerts),
            'critical_count': len(vulnerabilities['Critical']),
            'high_count': len(vulnerabilities['High']),
            'medium_count': len(vulnerabilities['Medium']),
            'low_count': len(vulnerabilities['Low']),
            'info_count': len(vulnerabilities['Informational']),
            'scan_timestamp': datetime.now().isoformat(),
            'target_url': data.get('site', [{}])[0].get('@name', 'Unknown'),
            'ai_enabled': self.use_ai
        }
        
        return {
            'summary': summary,
            'vulnerabilities': vulnerabilities
        }

    def create_summary_message(self, report_data: Dict, pr_number: Optional[str] = None) -> str:
        """
        Create a concise AI-enhanced summary message for Slack
        
        Args:
            report_data: Parsed ZAP report data with AI insights
            pr_number: Pull request number (if applicable)
            
        Returns:
            Formatted summary message
        """
        summary = report_data.get('summary', {})
        
        # Build header
        header = "🔒 **DAST Security Scan Results**"
        if summary.get('ai_enabled'):
            header += " 🤖 (AI-Powered)"
        if pr_number:
            header += f" - PR #{pr_number}"
        
        # Risk summary with emojis
        risk_summary = []
        if summary.get('critical_count', 0) > 0:
            risk_summary.append(f"🔴 {summary['critical_count']} Critical")
        if summary.get('high_count', 0) > 0:
            risk_summary.append(f"🟠 {summary['high_count']} High")
        if summary.get('medium_count', 0) > 0:
            risk_summary.append(f"🟡 {summary['medium_count']} Medium")
        if summary.get('low_count', 0) > 0:
            risk_summary.append(f"🔵 {summary['low_count']} Low")
        if summary.get('info_count', 0) > 0:
            risk_summary.append(f"ℹ️ {summary['info_count']} Info")
        
        if not risk_summary:
            message = f"{header}\n✅ No security vulnerabilities found!"
        else:
            message = f"{header}\n📊 **Findings:** {', '.join(risk_summary)}"
        
        # Add target information
        target_url = summary.get('target_url', 'Unknown')
        message += f"\n🎯 **Target:** {target_url}"
        
        # Add scan timestamp
        scan_time = summary.get('scan_timestamp', '')
        if scan_time:
            message += f"\n🕐 **Scan Time:** {scan_time[:19].replace('T', ' ')}"
        
        return message

    def create_detailed_blocks(self, report_data: Dict) -> List[Dict]:
        """
        Create detailed AI-enhanced Slack blocks for vulnerabilities
        
        Args:
            report_data: Parsed ZAP report data with AI insights
            
        Returns:
            List of Slack block kit blocks
        """
        blocks = []
        vulnerabilities = report_data.get('vulnerabilities', {})
        ai_enabled = report_data.get('summary', {}).get('ai_enabled', False)
        
        # Process each severity level
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            vulns = vulnerabilities.get(severity, [])
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
            
            # List vulnerabilities with AI insights (limit to prevent overflow)
            for vuln in vulns[:5]:  # Limit to first 5 per severity
                # Build vulnerability text
                emoji = self.category_emojis.get(vuln.get('ai_category', 'OTHER'), '⚠️')
                vuln_text = f"{emoji} *{vuln['name']}*"
                
                if vuln.get('instances', 0) > 1:
                    vuln_text += f" ({vuln['instances']} instances)"
                
                # Add AI insights if available
                if ai_enabled and 'ai_category' in vuln:
                    ai_details = []
                    
                    if vuln.get('ai_severity'):
                        ai_details.append(f"Severity: {vuln['ai_severity']:.1f}/10")
                    
                    if vuln.get('attack_vector') and vuln['attack_vector'] != 'unknown':
                        ai_details.append(f"Vector: {vuln['attack_vector']}")
                    
                    if vuln.get('exploitability') and vuln['exploitability'] != 'unknown':
                        ai_details.append(f"Exploitability: {vuln['exploitability']}")
                    
                    if ai_details:
                        vuln_text += f"\n    _{' | '.join(ai_details)}_"
                    
                    if vuln.get('business_impact'):
                        vuln_text += f"\n    💼 Impact: {vuln['business_impact'][:100]}"
                
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
            
            # Add divider
            blocks.append({"type": "divider"})
        
        # Add AI attribution if enabled
        if ai_enabled:
            blocks.append({
                "type": "context",
                "elements": [{
                    "type": "mrkdwn",
                    "text": "🤖 Powered by AI Classification (Google Gemini)"
                }]
            })
        
        return blocks

    def send_report(self, report_data: Dict, pr_number: Optional[str] = None) -> bool:
        """
        Send AI-enhanced DAST report to Slack
        
        Args:
            report_data: Parsed ZAP report data with AI insights
            pr_number: Pull request number (if applicable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            summary = report_data.get('summary', {})
            
            # Create main message
            main_message = self.create_summary_message(report_data, pr_number)
            
            # Determine overall color based on highest severity
            if summary.get('critical_count', 0) > 0:
                color = self.severity_colors['critical']
            elif summary.get('high_count', 0) > 0:
                color = self.severity_colors['high']
            elif summary.get('medium_count', 0) > 0:
                color = self.severity_colors['medium']
            elif summary.get('low_count', 0) > 0:
                color = self.severity_colors['low']
            else:
                color = '#00FF00'  # Green for no issues
            
            # Create attachment with detailed information
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
            
            # Add detailed blocks if there are vulnerabilities
            if summary.get('total_alerts', 0) > 0:
                detailed_blocks = self.create_detailed_blocks(report_data)
                attachment["blocks"].extend(detailed_blocks)
            
            # Send message to Slack
            response = self.client.chat_postMessage(
                channel=self.channel,
                text="DAST Security Scan Results",
                attachments=[attachment]
            )
            
            print(f"✅ AI-enhanced report sent successfully to Slack channel: {self.channel}")
            return True
            
        except SlackApiError as e:
            print(f"❌ Error sending message to Slack: {e.response['error']}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return False


def main():
    """Main function to run the AI-enhanced DAST Slack reporter"""
    
    # Get configuration from environment variables
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    report_path = os.getenv('ZAP_REPORT_PATH', 'report.json')
    pr_number = os.getenv('GITHUB_PR_NUMBER')
    use_ai = os.getenv('USE_AI_CLASSIFICATION', 'true').lower() == 'true'
    
    # Check if report file exists
    if not os.path.exists(report_path):
        print(f"❌ ZAP report file not found: {report_path}")
        sys.exit(1)
    
    # Initialize reporter
    reporter = AIEnhancedSlackReporter(slack_token, slack_channel, use_ai=use_ai)
    
    # Parse ZAP report with AI classification
    print(f"📖 Parsing ZAP report with AI: {report_path}")
    report_data = reporter.parse_zap_report(report_path)
    
    if not report_data:
        print("❌ Failed to parse ZAP report")
        sys.exit(1)
    
    # Send AI-enhanced report
    print(f"📤 Sending AI-enhanced report to Slack...")
    success = reporter.send_report(report_data, pr_number)
    
    if success:
        print("🎉 AI-enhanced DAST report sent to Slack successfully!")
        sys.exit(0)
    else:
        print("❌ Failed to send DAST report to Slack")
        sys.exit(1)


if __name__ == "__main__":
    main()
