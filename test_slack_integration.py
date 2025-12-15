#!/usr/bin/env python3
"""
Test script for DAST Slack Reporter
Creates sample ZAP report data and tests Slack integration
"""

import json
import os
import sys
from dotenv import load_dotenv
from slack_reporter import DastSlackReporter

# Load environment variables from .env file
load_dotenv()

def create_sample_zap_report():
    """Create a sample ZAP report for testing"""
    sample_report = {
        "site": [{
            "@name": "https://dast-test-production.up.railway.app/",
            "alerts": [
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "Medium",
                    "desc": "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance.",
                    "solution": "Phase: Architecture and Design\nUse a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.",
                    "cweid": "79",
                    "wascid": "8",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/search?q=<script>alert(1)</script>",
                            "method": "GET",
                            "param": "q"
                        }
                    ]
                },
                {
                    "name": "Open Redirect",
                    "riskcode": "2",
                    "confidence": "Medium",
                    "desc": "Open redirect vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way.",
                    "solution": "Assume all input is malicious. Use an \"accept known good\" input validation strategy.",
                    "cweid": "601",
                    "wascid": "38",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/redirect?url=https://evil.com",
                            "method": "GET",
                            "param": "url"
                        }
                    ]
                },
                {
                    "name": "Missing Anti-clickjacking Header",
                    "riskcode": "2",
                    "confidence": "Medium",
                    "desc": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.",
                    "solution": "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers.",
                    "cweid": "1021",
                    "wascid": "15",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/",
                            "method": "GET"
                        }
                    ]
                },
                {
                    "name": "X-Content-Type-Options Header Missing",
                    "riskcode": "1",
                    "confidence": "Medium",
                    "desc": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'.",
                    "solution": "Ensure that the application/web server sets the Content-Type header appropriately.",
                    "cweid": "693",
                    "wascid": "15",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/",
                            "method": "GET"
                        }
                    ]
                },
                {
                    "name": "Information Disclosure - Sensitive Information in URL",
                    "riskcode": "0",
                    "confidence": "Medium",
                    "desc": "The request appeared to contain sensitive information leaked in the URL.",
                    "solution": "Do not pass sensitive information in URIs.",
                    "cweid": "200",
                    "wascid": "13",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/user?id=1",
                            "method": "GET",
                            "param": "id"
                        }
                    ]
                }
            ]
        }]
    }
    
    return sample_report

def test_slack_integration():
    """Test the Slack integration with sample data"""
    
    print("🧪 Testing DAST Slack Reporter...")
    
    # Create sample report file
    sample_data = create_sample_zap_report()
    test_report_path = "test_report.json"
    
    with open(test_report_path, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    print(f"✅ Created test report: {test_report_path}")
    
    # Get Slack credentials
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    
    # Test parsing
    reporter = DastSlackReporter(slack_token or 'dummy-token', slack_channel)
    report_data = reporter.parse_zap_report(test_report_path)
    
    if not report_data:
        print("❌ Failed to parse test report")
        return False
    
    print("✅ Successfully parsed test report")
    print(f"📊 Summary: {report_data['summary']}")
    
    # Test message creation
    summary_message = reporter.create_summary_message(report_data, pr_number="123")
    print("\n📝 Generated Summary Message:")
    print("=" * 50)
    print(summary_message)
    print("=" * 50)
    
    # Test detailed blocks
    detailed_blocks = reporter.create_detailed_blocks(report_data)
    print(f"\n🔍 Generated {len(detailed_blocks)} detailed blocks")
    
    # Check if we have actual Slack credentials
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_webhook = os.getenv('SLACK_WEBHOOK_URL')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    
    if slack_webhook or slack_token:
        print("\n🚀 Found Slack credentials - sending test message...")
        
        # Initialize reporter with actual credentials
        reporter = DastSlackReporter(slack_token or '', slack_channel)
        
        if slack_webhook:
            print("Using Slack webhook...")
            success = reporter.send_webhook_report(slack_webhook, report_data, pr_number="123")
        else:
            print(f"Using Slack bot token for channel: {slack_channel}")
            success = reporter.send_report(report_data, pr_number="123")
        
        if success:
            print("✅ Test message sent successfully!")
        else:
            print("❌ Failed to send test message")
    else:
        print("\n⚠️  No Slack credentials found. Set SLACK_BOT_TOKEN or SLACK_WEBHOOK_URL to test actual sending.")
        print("   You can still see the generated message format above.")
    
    # Cleanup
    os.remove(test_report_path)
    print(f"🧹 Cleaned up test file: {test_report_path}")
    
    return True

if __name__ == "__main__":
    success = test_slack_integration()
    if success:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Tests failed!")
        sys.exit(1)