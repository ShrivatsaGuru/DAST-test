#!/usr/bin/env python3
"""
Test AI-Enhanced Slack Reporter
Creates sample ZAP report and sends AI-enhanced notification to Slack
"""

import json
import os
import sys
from slack_reporter_ai import AIEnhancedSlackReporter

def create_sample_zap_report():
    """Create a comprehensive sample ZAP report for testing"""
    sample_report = {
        "site": [{
            "@name": "https://dast-test-production.up.railway.app/",
            "alerts": [
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "Medium",
                    "desc": "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product. Successful XSS attacks can lead to unauthorized access and data theft.",
                    "solution": "Phase: Architecture and Design - Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. Examples include React, Angular, and Vue.js when used properly.",
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
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "High",
                    "desc": "SQL injection attacks occur when an attacker passes malicious SQL commands to a database server through user input fields. This can lead to unauthorized data access, data manipulation, or complete system compromise.",
                    "solution": "Use parameterized queries and prepared statements. Implement proper input validation and sanitization. Follow the principle of least privilege for database access.",
                    "cweid": "89",
                    "wascid": "19",
                    "instances": [
                        {
                            "uri": "https://dast-test-production.up.railway.app/user?id=1' OR '1'='1",
                            "method": "GET",
                            "param": "id"
                        }
                    ]
                },
                {
                    "name": "Open Redirect",
                    "riskcode": "2",
                    "confidence": "Medium",
                    "desc": "Open redirect vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way. This can be exploited for phishing attacks.",
                    "solution": "Assume all input is malicious. Use an accept known good input validation strategy. Validate and whitelist redirect URLs.",
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
                    "solution": "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site.",
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
                    "desc": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing.",
                    "solution": "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.",
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
                    "name": "Sensitive Information in URL",
                    "riskcode": "0",
                    "confidence": "Medium",
                    "desc": "The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies.",
                    "solution": "Do not pass sensitive information in URIs. Use POST with proper encryption instead.",
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

def test_ai_slack_integration():
    """Test the AI-enhanced Slack integration with sample data"""
    
    print("🧪 Testing AI-Enhanced DAST Slack Reporter\n")
    print("=" * 60)
    
    # Create sample report file
    sample_data = create_sample_zap_report()
    test_report_path = "test_report_ai.json"
    
    with open(test_report_path, 'w') as f:
        json.dump(sample_data, f, indent=2)
    
    print(f"✅ Created test report: {test_report_path}\n")
    
    # Get Slack credentials
    slack_token = os.getenv('SLACK_BOT_TOKEN')
    slack_channel = os.getenv('SLACK_CHANNEL', '#security-alerts')
    use_ai = os.getenv('USE_AI_CLASSIFICATION', 'true').lower() == 'true'
    
    if not slack_token:
        print("❌ SLACK_BOT_TOKEN not found in environment")
        print("   Set it in your .env file")
        return False
    
    # Initialize AI-enhanced reporter
    print(f"🔧 Initializing AI-enhanced reporter...")
    print(f"   Channel: {slack_channel}")
    print(f"   AI Classification: {'Enabled' if use_ai else 'Disabled'}")
    print()
    
    reporter = AIEnhancedSlackReporter(slack_token, slack_channel, use_ai=use_ai)
    
    # Parse report with AI classification
    print("📖 Parsing ZAP report with AI classification...")
    report_data = reporter.parse_zap_report(test_report_path)
    
    if not report_data:
        print("❌ Failed to parse test report")
        return False
    
    summary = report_data['summary']
    print(f"\n📊 Summary:")
    print(f"   Total Alerts: {summary['total_alerts']}")
    print(f"   Critical: {summary['critical_count']}")
    print(f"   High: {summary['high_count']}")
    print(f"   Medium: {summary['medium_count']}")
    print(f"   Low: {summary['low_count']}")
    print(f"   Info: {summary['info_count']}")
    print(f"   AI Enabled: {summary['ai_enabled']}")
    
    # Show AI insights
    if summary['ai_enabled']:
        print(f"\n🤖 AI-Enhanced Insights:")
        vulns = report_data['vulnerabilities']
        for severity in ['Critical', 'High', 'Medium']:
            for vuln in vulns.get(severity, [])[:2]:  # Show first 2
                if 'ai_category' in vuln:
                    print(f"   • {vuln['name']}")
                    print(f"     Category: {vuln['ai_category']}")
                    print(f"     AI Severity: {vuln.get('ai_severity', 'N/A'):.1f}/10")
                    print(f"     Exploitability: {vuln.get('exploitability', 'unknown')}")
                    if vuln.get('business_impact'):
                        print(f"     Impact: {vuln['business_impact'][:60]}...")
    
    # Send to Slack
    print(f"\n📤 Sending AI-enhanced report to Slack...")
    print("=" * 60)
    
    success = reporter.send_report(report_data, pr_number="123")
    
    # Cleanup
    os.remove(test_report_path)
    print(f"🧹 Cleaned up test file: {test_report_path}")
    
    if success:
        print("\n" + "=" * 60)
        print("🎉 SUCCESS! AI-enhanced report sent to Slack!")
        print("=" * 60)
        print(f"\n✅ Check your Slack channel: {slack_channel}")
        print("📱 You should see:")
        print("   • AI-powered vulnerability categorization")
        print("   • Intelligent severity scoring")
        print("   • Attack vector analysis")
        print("   • Exploitability assessment")
        print("   • Business impact insights")
        return True
    else:
        print("\n❌ Failed to send report to Slack")
        return False

if __name__ == "__main__":
    try:
        success = test_ai_slack_integration()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nTest cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
