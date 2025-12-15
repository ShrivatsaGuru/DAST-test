#!/usr/bin/env python3
"""
DAST Slack Reporter
Processes OWASP ZAP scan results and sends formatted reports to Slack
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

# Load environment variables from .env file
load_dotenv()


class DastSlackReporter:
    def __init__(self, slack_token: str, channel: str):
        """
        Initialize the DAST Slack Reporter
        
        Args:
            slack_token: Slack Bot Token
            channel: Slack channel to send reports to
        """
        self.client = WebClient(token=slack_token)
        self.channel = channel
        
        # Severity color mapping for Slack attachments
        self.severity_colors = {
            'High': '#FF0000',      # Red
            'Medium': '#FFA500',    # Orange
            'Low': '#FFFF00',       # Yellow
            'Informational': '#0000FF'  # Blue
        }
        
        # Risk level mapping
        self.risk_levels = {
            '3': 'High',
            '2': 'Medium', 
            '1': 'Low',
            '0': 'Informational'
        }

    def parse_zap_report(self, report_path: str) -> Dict:
        """
        Parse ZAP JSON report and extract key metrics
        
        Args:
            report_path: Path to ZAP JSON report file
            
        Returns:
            Dictionary containing parsed vulnerability data
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
        
        # Categorize vulnerabilities by risk level
        vulnerabilities = {
            'High': [],
            'Medium': [],
            'Low': [],
            'Informational': []
        }
        
        for alert in alerts:
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
            vulnerabilities[risk_level].append(vuln_info)
        
        # Calculate summary statistics
        summary = {
            'total_alerts': len(alerts),
            'high_count': len(vulnerabilities['High']),
            'medium_count': len(vulnerabilities['Medium']),
            'low_count': len(vulnerabilities['Low']),
            'info_count': len(vulnerabilities['Informational']),
            'scan_timestamp': datetime.now().isoformat(),
            'target_url': data.get('site', [{}])[0].get('@name', 'Unknown')
        }
        
        return {
            'summary': summary,
            'vulnerabilities': vulnerabilities
        }

    def create_summary_message(self, report_data: Dict, pr_number: Optional[str] = None) -> str:
        """
        Create a concise summary message for Slack
        
        Args:
            report_data: Parsed ZAP report data
            pr_number: Pull request number (if applicable)
            
        Returns:
            Formatted summary message
        """
        summary = report_data.get('summary', {})
        
        # Build header
        header = "🔒 **DAST Security Scan Results**"
        if pr_number:
            header += f" - PR #{pr_number}"
        
        # Risk summary with emojis
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
        Create detailed Slack blocks for vulnerabilities
        
        Args:
            report_data: Parsed ZAP report data
            
        Returns:
            List of Slack block kit blocks
        """
        blocks = []
        vulnerabilities = report_data.get('vulnerabilities', {})
        
        # Process each severity level
        for severity in ['High', 'Medium', 'Low']:
            vulns = vulnerabilities.get(severity, [])
            if not vulns:
                continue
                
            # Severity header
            color = self.severity_colors.get(severity, '#808080')
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{severity} Risk Vulnerabilities ({len(vulns)}):*"
                }
            })
            
            # List vulnerabilities (limit to prevent message overflow)
            for vuln in vulns[:5]:  # Limit to first 5 per severity
                vuln_text = f"• *{vuln['name']}*"
                if vuln.get('instances', 0) > 1:
                    vuln_text += f" ({vuln['instances']} instances)"
                
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
        
        return blocks

    def send_report(self, report_data: Dict, pr_number: Optional[str] = None) -> bool:
        """
        Send DAST report to Slack
        
        Args:
            report_data: Parsed ZAP report data
            pr_number: Pull request number (if applicable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            summary = report_data.get('summary', {})
            
            # Create main message
            main_message = self.create_summary_message(report_data, pr_number)
            
            # Determine overall color based on highest severity
            if summary.get('high_count', 0) > 0:
                color = self.severity_colors['High']
            elif summary.get('medium_count', 0) > 0:
                color = self.severity_colors['Medium']
            elif summary.get('low_count', 0) > 0:
                color = self.severity_colors['Low']
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
            
            print(f"✅ Report sent successfully to Slack channel: {self.channel}")
            return True
            
        except SlackApiError as e:
            print(f"❌ Error sending message to Slack: {e.response['error']}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error: {str(e)}")
            return False

    def send_webhook_report(self, webhook_url: str, report_data: Dict, pr_number: Optional[str] = None) -> bool:
        """
        Send report via Slack webhook (alternative to bot token)
        
        Args:
            webhook_url: Slack webhook URL
            report_data: Parsed ZAP report data
            pr_number: Pull request number (if applicable)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            summary = report_data.get('summary', {})
            main_message = self.create_summary_message(report_data, pr_number)
            
            # Determine color
            if summary.get('high_count', 0) > 0:
                color = "danger"
            elif summary.get('medium_count', 0) > 0:
                color = "warning"
            else:
                color = "good"
            
            payload = {
                "text": "DAST Security Scan Results",
                "attachments": [{
                    "color": color,
                    "text": main_message,
                    "mrkdwn_in": ["text"]
                }]
            }
            
            response = requests.post(webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            print(f"✅ Report sent successfully via webhook")
            return True
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Error sending webhook: {str(e)}")
            return False


def main():
    """Main function to run the DAST Slack reporter"""
    
    # Get configuration from environment variables
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    report_path = os.getenv('ZAP_REPORT_PATH', 'report.json')
    pr_number = os.getenv('GITHUB_PR_NUMBER')
    
    # Check if report file exists
    if not os.path.exists(report_path):
        print(f"❌ ZAP report file not found: {report_path}")
        sys.exit(1)
    
    # Initialize reporter
    reporter = DastSlackReporter(slack_token or '', slack_channel)
    
    # Parse ZAP report
    print(f"📖 Parsing ZAP report: {report_path}")
    report_data = reporter.parse_zap_report(report_path)
    
    if not report_data:
        print("❌ Failed to parse ZAP report")
        sys.exit(1)
    
    # Send report
    print(f"📤 Sending report to Slack...")
    success = False
    
    if slack_webhook:
        print("Using Slack webhook...")
        success = reporter.send_webhook_report(slack_webhook, report_data, pr_number)
    elif slack_token:
        print("Using Slack bot token...")
        success = reporter.send_report(report_data, pr_number)
    else:
        print("❌ No Slack configuration found. Set SLACK_BOT_TOKEN or SLACK_WEBHOOK_URL")
        sys.exit(1)
    
    if success:
        print("🎉 DAST report sent to Slack successfully!")
        sys.exit(0)
    else:
        print("❌ Failed to send DAST report to Slack")
        sys.exit(1)


if __name__ == "__main__":
    main()