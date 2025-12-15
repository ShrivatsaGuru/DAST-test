#!/usr/bin/env python3
"""
Test AI-Enhanced Integration
Tests the complete workflow with AI classification
"""

import json
import os
from dotenv import load_dotenv
from enhanced_slack_reporter import EnhancedDastSlackReporter

# Load environment variables
load_dotenv()


def create_test_report():
    """Create a test ZAP report"""
    return {
        "site": [{
            "@name": "https://dast-test-production.up.railway.app/",
            "alerts": [
                {
                    "name": "Cross Site Scripting (Reflected)",
                    "riskcode": "3",
                    "confidence": "Medium",
                    "desc": "Cross-site Scripting (XSS) is an attack technique that involves echoing attacker-supplied code into a user's browser instance. A cross-site scripting vulnerability is used by attackers to circumvent access controls such as the same-origin policy.",
                    "solution": "Phase: Architecture and Design - Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. Examples of libraries and frameworks that make it easier to generate properly encoded output include Microsoft's Anti-XSS library.",
                    "cweid": "79",
                    "wascid": "8",
                    "instances": [{"uri": "https://example.com/search?q=test"}]
                },
                {
                    "name": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "High",
                    "desc": "SQL injection is a code injection technique that exploits a security vulnerability occurring in the database layer of an application. The vulnerability is present when user input is either incorrectly filtered for string literal escape characters embedded in SQL statements.",
                    "solution": "Use prepared statements with parameterized queries. This is the most effective way to prevent SQL injection attacks.",
                    "cweid": "89",
                    "wascid": "19",
                    "instances": [{"uri": "https://example.com/user?id=1"}]
                },
                {
                    "name": "Open Redirect",
                    "riskcode": "2",
                    "confidence": "Medium",
                    "desc": "Open redirect vulnerabilities arise when an application incorporates user-controllable data into the target of a redirection in an unsafe way.",
                    "solution": "Assume all input is malicious. Use an 'accept known good' input validation strategy.",
                    "cweid": "601",
                    "wascid": "38",
                    "instances": [{"uri": "https://example.com/redirect?url=https://evil.com"}]
                },
                {
                    "name": "Missing Anti-clickjacking Header",
                    "riskcode": "2",
                    "confidence": "Medium",
                    "desc": "The response does not include either Content-Security-Policy with 'frame-ancestors' directive or X-Frame-Options to protect against 'ClickJacking' attacks.",
                    "solution": "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers.",
                    "cweid": "1021",
                    "wascid": "15",
                    "instances": [{"uri": "https://example.com/"}]
                },
                {
                    "name": "Password Autocomplete in Browser",
                    "riskcode": "1",
                    "confidence": "Medium",
                    "desc": "The AUTOCOMPLETE attribute is not disabled on an HTML FORM/INPUT element containing password type input.",
                    "solution": "Turn off the AUTOCOMPLETE attribute in forms or individual input elements containing password inputs by using AUTOCOMPLETE='OFF'.",
                    "cweid": "525",
                    "wascid": "15",
                    "instances": [{"uri": "https://example.com/login"}]
                },
                {
                    "name": "Information Disclosure - Suspicious Comments",
                    "riskcode": "0",
                    "confidence": "Low",
                    "desc": "The response appears to contain suspicious comments which may help an attacker.",
                    "solution": "Remove all comments that return information that may help an attacker.",
                    "cweid": "200",
                    "wascid": "13",
                    "instances": [{"uri": "https://example.com/"}]
                }
            ]
        }]
    }


def test_ai_classification():
    """Test AI classification"""
    print("🧪 Testing AI-Enhanced DAST Integration\n")
    print("=" * 60)
    
    # Create test report
    print("\n1️⃣  Creating test ZAP report...")
    test_data = create_test_report()
    test_report_path = "test_enhanced_report.json"
    
    with open(test_report_path, 'w') as f:
        json.dump(test_data, f, indent=2)
    print("✅ Test report created")
    
    # Initialize reporter
    print("\n2️⃣  Initializing AI-Enhanced Reporter...")
    slack_token = os.getenv('SLACK_BOT_TOKEN', 'test-token')
    slack_channel = os.getenv('SLACK_CHANNEL', '#test')
    use_ai = os.getenv('USE_AI_CLASSIFICATION', 'true').lower() == 'true'
    
    reporter = EnhancedDastSlackReporter(slack_token, slack_channel, use_ai=use_ai)
    print(f"✅ Reporter initialized (AI: {'Enabled' if use_ai else 'Disabled'})")
    
    # Parse and classify
    print("\n3️⃣  Parsing and classifying vulnerabilities...")
    report_data = reporter.parse_zap_report_with_classification(test_report_path)
    
    if not report_data:
        print("❌ Failed to parse report")
        return False
    
    print("✅ Report parsed successfully")
    
    # Show summary
    summary = report_data['summary']
    print(f"\n📊 Summary:")
    print(f"   Total findings: {summary['total_alerts']}")
    print(f"   High: {summary['high_count']}")
    print(f"   Medium: {summary['medium_count']}")
    print(f"   Low: {summary['low_count']}")
    print(f"   Info: {summary['info_count']}")
    
    # Show AI stats if available
    ai_stats = summary.get('ai_stats', {})
    if ai_stats:
        print(f"\n🤖 AI Classification Stats:")
        print(f"   AI-classified: {ai_stats.get('ai_classified', 0)}/{ai_stats.get('total', 0)}")
        print(f"   High confidence: {ai_stats.get('high_confidence', 0)}")
        
        if ai_stats.get('by_category'):
            print(f"\n📁 Categories found:")
            for category, count in sorted(ai_stats['by_category'].items(), key=lambda x: x[1], reverse=True):
                print(f"   {category}: {count}")
    
    # Show classified vulnerabilities
    print(f"\n🔍 Classified Vulnerabilities:")
    print("-" * 60)
    
    for vuln in report_data['classified_vulnerabilities'][:3]:  # Show first 3
        classification = vuln.get('classification', {})
        print(f"\n   📌 {vuln['name']}")
        print(f"      Category: {classification.get('category_name', 'Unknown')}")
        print(f"      Confidence: {classification.get('confidence', 0):.0%}")
        print(f"      Method: {classification.get('method', 'unknown')}")
        print(f"      Severity: {classification.get('original_severity', 'N/A')} → {classification.get('adjusted_severity', 'N/A')}")
        if classification.get('explanation'):
            print(f"      Explanation: {classification['explanation']}")
    
    if len(report_data['classified_vulnerabilities']) > 3:
        print(f"\n   ... and {len(report_data['classified_vulnerabilities']) - 3} more")
    
    # Test Slack message creation
    print(f"\n4️⃣  Testing Slack message creation...")
    message = reporter.create_enhanced_summary_message(report_data, pr_number="999")
    print("✅ Message created successfully")
    print(f"\n📝 Sample Message:")
    print("=" * 60)
    print(message)
    print("=" * 60)
    
    # Try to send if Slack is configured
    has_slack = os.getenv('SLACK_BOT_TOKEN') and os.getenv('SLACK_BOT_TOKEN') != 'test-token'
    
    if has_slack:
        print(f"\n5️⃣  Sending to Slack...")
        success = reporter.send_enhanced_report(report_data, pr_number="999")
        if success:
            print("✅ Report sent to Slack successfully!")
        else:
            print("❌ Failed to send to Slack")
    else:
        print(f"\n5️⃣  Skipping Slack send (no valid token configured)")
        print("   To test Slack integration, add SLACK_BOT_TOKEN to .env")
    
    # Cleanup
    print(f"\n6️⃣  Cleaning up...")
    os.remove(test_report_path)
    print("✅ Test file removed")
    
    print(f"\n" + "=" * 60)
    print("🎉 All tests completed successfully!")
    print("=" * 60)
    
    # Show setup status
    print(f"\n📋 Configuration Status:")
    print(f"   Slack Token: {'✅ Configured' if has_slack else '❌ Not configured'}")
    print(f"   Gemini API: {'✅ Configured' if os.getenv('GEMINI_API_KEY') else '❌ Not configured'}")
    print(f"   Groq API: {'✅ Configured' if os.getenv('GROQ_API_KEY') else '❌ Not configured'}")
    print(f"   AI Classification: {'✅ Enabled' if use_ai else '❌ Disabled'}")
    
    if not os.getenv('GEMINI_API_KEY') and not os.getenv('GROQ_API_KEY'):
        print(f"\n💡 Tip: Get free API keys from:")
        print(f"   • Gemini: https://makersuite.google.com/app/apikey")
        print(f"   • Groq: https://console.groq.com/keys")
        print(f"   See FREE_AI_SETUP.md for details")
    
    return True


if __name__ == "__main__":
    try:
        test_ai_classification()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
