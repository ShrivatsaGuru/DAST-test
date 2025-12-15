import os
import sys
import json
import requests
from google import genai
from google.genai import types

# --- Configuration ---
# The script expects these environment variables to be set in the GitHub workflow
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
USE_AI_CLASSIFICATION = os.environ.get("USE_AI_CLASSIFICATION", 'false').lower() == 'true'

# Define the structure for the AI response
# This uses a JSON schema to ensure the model returns a predictable, parseable response.
AI_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "A brief, non-technical summary of the overall security posture."},
        "threat_category": {"type": "string", "description": "Overall security rating: None, Low, Medium, High, or Urgent/Red Alert."},
        "vulnerability_analysis": {
            "type": "array",
            "description": "Detailed analysis of the top 3-5 critical vulnerabilities found.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the vulnerability."},
                    "diagnosis": {"type": "string", "description": "Detailed explanation of the vulnerability and its potential impact."},
                    "severity": {"type": "string", "description": "Severity assigned by the AI: Low, Medium, High, or Critical."},
                    "remediation": {"type": "string", "description": "Specific, actionable steps to fix the vulnerability, including code examples if relevant."}
                },
                "required": ["name", "diagnosis", "severity", "remediation"]
            }
        },
        "next_steps": {"type": "string", "description": "Clear next steps for the security team or developer."}
    },
    "required": ["summary", "threat_category", "vulnerability_analysis", "next_steps"]
}

# --- Core Functions ---

def read_zap_report(file_path):
    """Reads the ZAP JSON report from the specified path."""
    try:
        with open(file_path, 'r') as f:
            report_data = json.load(f)
        return report_data
    except FileNotFoundError:
        print(f"❌ Report file not found: {file_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"❌ Failed to decode JSON from file: {file_path}")
        sys.exit(1)

def analyze_with_gemini(report_data):
    """Sends the ZAP report to Gemini for structured analysis and summarization."""
    if not GEMINI_API_KEY:
        print("❌ GEMINI_API_KEY not found in environment variables.")
        return None

    print("🤖 Sending report to Gemini API for analysis...")
    
    # Initialize the client
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    # Convert ZAP report to a string for the prompt
    report_string = json.dumps(report_data, indent=2)

    # System prompt to guide the model's behavior
    system_instruction = (
        "You are an expert security analyst. Your task is to review the provided "
        "OWASP ZAP DAST scan report (in JSON format) and provide a concise, structured "
        "summary for a development team. Categorize the overall threat level into "
        "one of five categories: None, Low, Medium, High, or Urgent/Red Alert. "
        "For the top 3-5 most critical vulnerabilities, provide a clear diagnosis "
        "and specific, actionable remediation advice. Your output MUST be valid JSON "
        "that strictly adheres to the provided JSON schema."
    )

    prompt = f"Analyze the following OWASP ZAP DAST report:\n\n{report_string}"

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=AI_REPORT_SCHEMA,
            )
        )
        
        # The response text will be a JSON string conforming to the schema
        return json.loads(response.text)
        
    except Exception as e:
        print(f"❌ Gemini API call failed: {e}")
        return None

def format_slack_message(ai_report):
    """Formats the AI-generated JSON into a Slack-friendly Markdown message."""
    
    # Define color based on threat level
    color_map = {
        "None": "#36a64f",      # Green
        "Low": "#f2c744",       # Yellow
        "Medium": "#ff9900",    # Orange
        "High": "#ff0000",      # Red
        "Urgent/Red Alert": "#8b0000" # Dark Red
    }
    threat_color = color_map.get(ai_report.get("threat_category", "Unknown"), "#cccccc")
    
    # Start building the Slack message using the 'attachments' format
    attachments = []
    
    # --- Main Summary Attachment ---
    summary_attachment = {
        "color": threat_color,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 DAST Scan AI Report: {ai_report.get('threat_category', 'Unknown Threat')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Overall Summary:*\n{ai_report['summary']}"
                }
            }
        ]
    }
    attachments.append(summary_attachment)

    # --- Vulnerability Details Attachments ---
    for vul in ai_report.get("vulnerability_analysis", []):
        vul_attachment = {
            "color": threat_color, # Keep the same color for consistency
            "blocks": [
                {
                    "type": "divider"
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*:warning: Vulnerability: {vul['name']} (Severity: {vul['severity']})*\n\n"
                                f"*Diagnosis:*\n{vul['diagnosis']}\n\n"
                                f"*Actionable Fixes:*\n{vul['remediation']}"
                    }
                }
            ]
        }
        attachments.append(vul_attachment)

    # --- Next Steps Attachment ---
    next_steps_attachment = {
        "color": "#007bff", # Blue for action items
        "blocks": [
            {
                "type": "divider"
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*:runner: Next Steps:*\n{ai_report['next_steps']}"
                }
            }
        ]
    }
    attachments.append(next_steps_attachment)
    
    # Final payload structure
    slack_payload = {
        "text": f"DAST Scan Report for ${{ vars.TARGET_URL }} analysis complete.",
        "attachments": attachments
    }
    
    return slack_payload

def send_to_slack(payload):
    """Posts the formatted payload to the Slack Webhook URL."""
    if not SLACK_WEBHOOK_URL:
        print("❌ SLACK_WEBHOOK_URL not found in environment variables. Skipping Slack notification.")
        return

    print("Sending message to Slack...")
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        print("✅ Successfully sent report to Slack.")
    except requests.exceptions.HTTPError as err:
        print(f"❌ HTTP Error sending to Slack: {err}")
    except requests.exceptions.RequestException as err:
        print(f"❌ An error occurred sending to Slack: {err}")

# --- Main Execution ---

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python slack_reporter_full.py <path_to_report.json> [language_tag (optional)]")
        sys.exit(1)

    report_file_path = sys.argv[1]
    
    # 1. Read the ZAP report
    zap_report = read_zap_report(report_file_path)
    
    if USE_AI_CLASSIFICATION:
        # 2. Analyze the report using Gemini
        ai_report_data = analyze_with_gemini(zap_report)
        
        if ai_report_data:
            # 3. Format the report for Slack
            slack_payload = format_slack_message(ai_report_data)
            
            # 4. Send the report to Slack
            send_to_slack(slack_payload)
        else:
            print("🛑 AI analysis failed. Cannot proceed with Slack report.")
            sys.exit(1)
    else:
        # Fallback for when AI is disabled (not the user's requested path, but good practice)
        print("AI classification is disabled. Skipping analysis.")
        # You would add code here to send a basic, raw report if AI analysis is skipped.
        # For this exercise, we assume AI is required.
        sys.exit(0) # Exit successfully if AI is intentionally skipped
