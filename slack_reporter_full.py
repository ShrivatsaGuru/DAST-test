#!/usr/bin/env python3
"""
Full DAST Slack Reporter with AI Classification & Remediation
Combines AI classification with actionable remediation guidance
"""

import os
import json
from typing import Dict, List, Optional
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from dotenv import load_dotenv
from ai_classifier_v2 import AIVulnerabilityClassifier
from remediation_engine import RemediationEngine

load_dotenv()


class FullDastSlackReporter:
    """
    Complete DAST reporter with:
    - AI-powered vulnerability classification
    - Intelligent remediation guidance
    - Rich Slack formatting with code examples
    - Actionable next steps
    """
    
    def __init__(self):
        """Initialize Slack client, AI classifier, and remediation engine"""
        self.slack_token = os.getenv('SLACK_BOT_TOKEN')
        self.channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
        
        if not self.slack_token or self.slack_token == 'your-slack-bot-token-here':
            raise ValueError("SLACK_BOT_TOKEN not configured in .env")
        
        self.client = WebClient(token=self.slack_token)
        
        # Initialize AI components
        use_ai = os.getenv('USE_AI_CLASSIFICATION', 'true').lower() == 'true'
        self.ai_classifier = AIVulnerabilityClassifier() if use_ai else None
        self.remediation_engine = RemediationEngine()
        
        print(f"✅ Full DAST Reporter initialized")
        print(f"   🤖 AI Classification: {'Enabled' if use_ai else 'Disabled'}")
        print(f"   🔧 Remediation Engine: Enabled")
        print(f"   📢 Target Channel: {self.channel}")
    
    def parse_zap_report(self, report_path: str, language: str = "javascript") -> Dict:
        """
        Parse ZAP report with AI classification and remediation
        
        Args:
            report_path: Path to ZAP JSON report
            language: Programming language for code examples
            
        Returns:
            Dict with classified vulnerabilities and remediation guidance
        """
        print(f"\n📖 Reading ZAP report: {report_path}")
        
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        site = data.get('site', [{}])[0]
        alerts = site.get('alerts', [])
        
        print(f"📊 Found {len(alerts)} vulnerability types")
        
        # Process with AI classification
        if self.ai_classifier:
            print("\n🤖 Running AI classification...")
            classified_alerts = self.ai_classifier.bulk_classify(alerts)
        else:
            classified_alerts = alerts
        
        # Generate remediation guidance
        print(f"\n🔧 Generating remediation guidance...")
        remediations = self.remediation_engine.generate_bulk_remediation(
            classified_alerts, 
            language=language
        )
        
        # Merge remediation with vulnerabilities
        for alert, remediation in zip(classified_alerts, remediations):
            alert['remediation'] = remediation
        
        # Calculate statistics
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Informational': 0}
        for alert in classified_alerts:
            risk = alert.get('riskdesc', 'Low').split()[0]
            severity_counts[risk] = severity_counts.get(risk, 0) + 1
        
        return {
            'site': site.get('@name', 'Unknown'),
            'alerts': classified_alerts,
            'total': len(classified_alerts),
            'severity_counts': severity_counts,
            'ai_enabled': self.ai_classifier is not None,
            'remediation_enabled': True
        }
    
    def create_summary_blocks(self, report_data: Dict) -> List[Dict]:
        """Create Slack blocks for summary section"""
        
        severity = report_data['severity_counts']
        total = report_data['total']
        
        # Determine overall severity emoji
        if severity.get('Critical', 0) > 0:
            status_emoji = "🚨"
            status_text = "CRITICAL ISSUES FOUND"
        elif severity.get('High', 0) > 0:
            status_emoji = "⚠️"
            status_text = "HIGH PRIORITY ISSUES"
        elif severity.get('Medium', 0) > 0:
            status_emoji = "⚡"
            status_text = "MEDIUM PRIORITY ISSUES"
        else:
            status_emoji = "✅"
            status_text = "LOW/INFO ISSUES ONLY"
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{status_emoji} DAST Security Scan Report",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Target:*\n{report_data['site']}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Status:*\n{status_text}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Total Issues:*\n{total}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*AI Analysis:*\n{'✅ Enabled' if report_data['ai_enabled'] else '❌ Disabled'}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Severity Breakdown:*\n"
                           f"🔴 Critical: {severity.get('Critical', 0)} | "
                           f"🟠 High: {severity.get('High', 0)} | "
                           f"🟡 Medium: {severity.get('Medium', 0)} | "
                           f"🟢 Low: {severity.get('Low', 0)} | "
                           f"ℹ️ Info: {severity.get('Informational', 0)}"
                }
            },
            {"type": "divider"}
        ]
        
        return blocks
    
    def create_vulnerability_blocks(self, alert: Dict, index: int) -> List[Dict]:
        """Create detailed Slack blocks for a single vulnerability with remediation"""
        
        name = alert.get('name', 'Unknown Vulnerability')
        risk = alert.get('riskdesc', 'Low').split()[0]
        desc = alert.get('desc', 'No description')[:200]
        
        # Get AI classification
        ai_category = alert.get('ai_category', 'OTHER')
        ai_severity = alert.get('ai_severity_score', 0)
        attack_vector = alert.get('ai_attack_vector', 'Unknown')
        exploitability = alert.get('ai_exploitability', 'Unknown')
        
        # Get remediation
        remediation = alert.get('remediation', {})
        rem_summary = remediation.get('summary', 'Review security best practices')
        rem_priority = remediation.get('priority', 'medium').upper()
        rem_effort = remediation.get('effort', 'medium').upper()
        rem_steps = remediation.get('steps', [])
        code_before = remediation.get('code_before', '')
        code_after = remediation.get('code_after', '')
        testing = remediation.get('testing', '')
        is_ai_rem = remediation.get('ai_generated', False)
        
        # Risk emoji
        risk_emoji = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢',
            'Informational': 'ℹ️'
        }.get(risk, '⚪')
        
        blocks = [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{index}. {risk_emoji} {name}*\n{desc}..."
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Risk Level:*\n{risk}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Category:*\n{ai_category}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*AI Severity:*\n{ai_severity}/10"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Exploitability:*\n{exploitability}"
                    }
                ]
            }
        ]
        
        # Remediation section
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"🔧 *Remediation {'(AI-Powered)' if is_ai_rem else '(Template)'}*\n"
                       f"*Quick Fix:* {rem_summary}\n"
                       f"*Priority:* {rem_priority} | *Effort:* {rem_effort}"
            }
        })
        
        # Steps
        if rem_steps:
            steps_text = "\n".join([f"{i+1}. {step}" for i, step in enumerate(rem_steps[:3])])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*📋 Fix Steps:*\n{steps_text}"
                }
            })
        
        # Code examples
        if code_after and len(code_after) > 20:
            # Truncate for Slack
            code_preview = code_after[:300] + "..." if len(code_after) > 300 else code_after
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*💻 Fixed Code:*\n```{code_preview}```"
                }
            })
        
        # Testing guidance
        if testing:
            blocks.append({
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"🧪 *Testing:* {testing[:150]}"
                    }
                ]
            })
        
        blocks.append({"type": "divider"})
        
        return blocks
    
    def send_report(self, report_data: Dict):
        """Send complete report to Slack with remediation guidance"""
        
        print(f"\n📤 Sending report to Slack channel: {self.channel}")
        
        try:
            # Summary section
            blocks = self.create_summary_blocks(report_data)
            
            # Add top vulnerabilities (limit to 5 for readability)
            alerts = sorted(
                report_data['alerts'],
                key=lambda x: {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'Informational': 0}
                .get(x.get('riskdesc', 'Low').split()[0], 0),
                reverse=True
            )
            
            top_alerts = alerts[:5]
            
            blocks.append({
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🔍 Top {len(top_alerts)} Vulnerabilities & Fixes",
                    "emoji": True
                }
            })
            
            for i, alert in enumerate(top_alerts, 1):
                vuln_blocks = self.create_vulnerability_blocks(alert, i)
                blocks.extend(vuln_blocks)
            
            # Footer with action items
            critical_count = report_data['severity_counts'].get('Critical', 0)
            high_count = report_data['severity_counts'].get('High', 0)
            
            if critical_count > 0 or high_count > 0:
                action_text = (
                    f"⚡ *IMMEDIATE ACTION REQUIRED*\n"
                    f"• {critical_count + high_count} critical/high issues need fixing\n"
                    f"• Review AI-powered remediation guidance above\n"
                    f"• Implement fixes and re-scan within 24 hours"
                )
            else:
                action_text = (
                    f"✅ *Good Security Posture*\n"
                    f"• No critical/high issues found\n"
                    f"• Address medium/low issues as time permits\n"
                    f"• Continue regular security scanning"
                )
            
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": action_text
                }
            })
            
            # Send message
            response = self.client.chat_postMessage(
                channel=self.channel,
                blocks=blocks,
                text=f"DAST Scan: {report_data['total']} vulnerabilities found"
            )
            
            print(f"✅ Report sent successfully!")
            print(f"   Message TS: {response['ts']}")
            print(f"   Channel: {response['channel']}")
            
        except SlackApiError as e:
            print(f"❌ Error sending to Slack: {e.response['error']}")
            raise


def main():
    """Main entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python slack_reporter_full.py <zap-report.json> [language]")
        sys.exit(1)
    
    report_path = sys.argv[1]
    language = sys.argv[2] if len(sys.argv) > 2 else "javascript"
    
    if not os.path.exists(report_path):
        print(f"❌ Report file not found: {report_path}")
        sys.exit(1)
    
    print("=" * 60)
    print("🚀 Full DAST Slack Reporter")
    print("   AI Classification + Remediation Guidance")
    print("=" * 60)
    
    reporter = FullDastSlackReporter()
    report_data = reporter.parse_zap_report(report_path, language)
    reporter.send_report(report_data)
    
    print("\n" + "=" * 60)
    print("✅ Complete! Check Slack for the detailed report.")
    print("=" * 60)


if __name__ == "__main__":
    main()
