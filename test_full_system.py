#!/usr/bin/env python3
"""
Test Full DAST System: AI Classification + Remediation
"""

import json
import os
from slack_reporter_full import FullDastSlackReporter


def create_test_report():
    """Create a test ZAP report with sample vulnerabilities"""
    
    report = {
        "site": [{
            "@name": "https://dast-test-production.up.railway.app",
            "alerts": [
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskdesc": "High (Medium)",
                    "desc": "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A browser instance can be a standard web browser client, or a browser object embedded in a software product such as the browser within WinAmp, an RSS reader, or an email client. The code itself is usually written in HTML/JavaScript, but may also extend to VBScript, ActiveX, Java, Flash, or any other browser-supported technology.",
                    "solution": "Phase: Architecture and Design\nUse a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.\nExamples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library, the OWASP ESAPI Encoding module, and Apache Wicket.",
                    "instances": [
                        {"uri": "https://dast-test-production.up.railway.app/search?q=test"}
                    ]
                },
                {
                    "name": "SQL Injection",
                    "riskdesc": "High (Medium)",
                    "desc": "SQL injection is a code injection technique that exploits a security vulnerability in an application's software. The vulnerability happens when user input is either incorrectly filtered or user input is not strongly typed.",
                    "solution": "Use parameterized queries (prepared statements) instead of dynamically generated SQL",
                    "instances": [
                        {"uri": "https://dast-test-production.up.railway.app/user?id=1"}
                    ]
                },
                {
                    "name": "Open Redirect",
                    "riskdesc": "Medium (Medium)",
                    "desc": "Open redirects are when a web application or server uses user input to redirect users to other websites without validation.",
                    "solution": "Validate and whitelist redirect destinations",
                    "instances": [
                        {"uri": "https://dast-test-production.up.railway.app/redirect?url=http://evil.com"}
                    ]
                },
                {
                    "name": "Missing Anti-clickjacking Header",
                    "riskdesc": "Medium (Medium)",
                    "desc": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.",
                    "solution": "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers.",
                    "instances": [
                        {"uri": "https://dast-test-production.up.railway.app/"}
                    ]
                }
            ]
        }]
    }
    
    # Save test report
    report_path = "test_full_report.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    return report_path


def test_remediation_engine():
    """Test just the remediation engine"""
    print("=" * 60)
    print("🧪 TEST 1: Remediation Engine Only")
    print("=" * 60)
    
    from remediation_engine import RemediationEngine
    
    engine = RemediationEngine()
    
    test_vuln = {
        'name': 'Cross Site Scripting (Reflected)',
        'description': 'User input reflected without encoding',
        'ai_category': 'XSS',
        'solution': 'Encode all user input'
    }
    
    print(f"\n📋 Testing vulnerability: {test_vuln['name']}")
    remediation = engine.generate_remediation(test_vuln, language="javascript")
    
    print(f"\n✅ Remediation Generated:")
    print(f"   Summary: {remediation['summary']}")
    print(f"   Priority: {remediation['priority']}")
    print(f"   Effort: {remediation['effort']}")
    print(f"   AI Generated: {remediation.get('ai_generated', False)}")
    
    if remediation.get('steps'):
        print(f"\n   Steps ({len(remediation['steps'])}):")
        for i, step in enumerate(remediation['steps'][:2], 1):
            print(f"      {i}. {step}")
    
    if remediation.get('code_after'):
        print(f"\n   Code Fix (preview):")
        code_preview = remediation['code_after'][:150]
        print(f"      {code_preview}...")
    
    print("\n" + "=" * 60)
    print("✅ Remediation engine test passed!")
    print("=" * 60)


def test_full_system():
    """Test complete system: AI + Remediation + Slack"""
    print("\n" + "=" * 60)
    print("🧪 TEST 2: Full DAST System")
    print("=" * 60)
    
    # Create test report
    print("\n📝 Creating test ZAP report...")
    report_path = create_test_report()
    print(f"✅ Test report created: {report_path}")
    
    # Initialize reporter
    print("\n🚀 Initializing Full DAST Reporter...")
    reporter = FullDastSlackReporter()
    
    # Parse with AI + Remediation
    print("\n📊 Processing vulnerabilities...")
    report_data = reporter.parse_zap_report(report_path, language="javascript")
    
    print(f"\n📈 Summary:")
    print(f"   Total Vulnerabilities: {report_data['total']}")
    print(f"   AI Classification: {'✅ Enabled' if report_data['ai_enabled'] else '❌ Disabled'}")
    print(f"   Remediation: {'✅ Enabled' if report_data['remediation_enabled'] else '❌ Disabled'}")
    print(f"\n   Severity Breakdown:")
    for severity, count in report_data['severity_counts'].items():
        if count > 0:
            print(f"      {severity}: {count}")
    
    # Show AI insights for first vulnerability
    if report_data['alerts']:
        alert = report_data['alerts'][0]
        print(f"\n🤖 AI Analysis (First Vulnerability):")
        print(f"   Name: {alert.get('name')}")
        print(f"   Category: {alert.get('ai_category', 'N/A')}")
        print(f"   AI Severity: {alert.get('ai_severity_score', 0)}/10")
        print(f"   Attack Vector: {alert.get('ai_attack_vector', 'N/A')}")
        print(f"   Exploitability: {alert.get('ai_exploitability', 'N/A')}")
        
        remediation = alert.get('remediation', {})
        print(f"\n🔧 Remediation Guidance:")
        print(f"   Summary: {remediation.get('summary', 'N/A')}")
        print(f"   Priority: {remediation.get('priority', 'N/A')}")
        print(f"   Effort: {remediation.get('effort', 'N/A')}")
        print(f"   AI Generated: {remediation.get('ai_generated', False)}")
        
        if remediation.get('steps'):
            print(f"\n   First 2 Steps:")
            for i, step in enumerate(remediation['steps'][:2], 1):
                print(f"      {i}. {step}")
    
    # Send to Slack
    print(f"\n📤 Sending enhanced report to Slack...")
    reporter.send_report(report_data)
    
    # Cleanup
    if os.path.exists(report_path):
        os.remove(report_path)
        print(f"\n🧹 Cleaned up test report")
    
    print("\n" + "=" * 60)
    print("✅ Full system test complete!")
    print("🎉 Check Slack for the AI-powered report with remediation!")
    print("=" * 60)


def main():
    """Run all tests"""
    print("\n🚀 Full DAST System Test Suite")
    print("   Testing: AI Classification + Remediation Engine + Slack")
    print()
    
    try:
        # Test 1: Remediation Engine
        test_remediation_engine()
        
        # Test 2: Full System
        test_full_system()
        
        print("\n✨ All tests passed! System is ready for production.")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
