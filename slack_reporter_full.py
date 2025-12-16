import os
import sys
import json
import requests
from google import genai
from google.genai import types

# --- Configuration ---
# Environment variables set in the GitHub workflow
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL")
USE_AI_CLASSIFICATION = os.environ.get("USE_AI_CLASSIFICATION", 'false').lower() == 'true'

# Define a strict JSON schema for Gemini's output to ensure reliable parsing
AI_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {"type": "string", "description": "A brief, non-technical summary of the overall security posture."},
        "threat_category": {"type": "string", "description": "Overall security rating: None, Low, Medium, High, or Urgent/Red Alert."},
        "vulnerability_analysis": {
            "type": "array",
            "description": "Detailed analysis of the top 3-5 critical vulnerabilities found in the report.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Name of the vulnerability (e.g., Cross-Site Scripting)."},
                    "diagnosis": {"type": "string", "description": "Detailed explanation of the vulnerability, its location, and its potential impact."},
                    "severity": {"type": "string", "description": "Severity assigned by the AI: Low, Medium, High, or Critical."},
                    "remediation": {"type": "string", "description": "Specific, actionable steps to fix the vulnerability, including security best practices."}
                },
                "required": ["name", "diagnosis", "severity", "remediation"]
            }
        },
        "next_steps": {"type": "string", "description": "Clear, concise next steps for the security team or developer."}
    },
    "required": ["summary", "threat_category", "vulnerability_analysis", "next_steps"]
}

# --- Core Functions ---

def read_zap_report_from_stdin():
    """Reads the ZAP JSON report content directly from Standard Input (the pipe)."""
    try:
        # sys.stdin.read() captures the entire content piped from 'cat report.json |'
        report_string = sys.stdin.read()
        if not report_string.strip():
            raise ValueError("No content received from stdin. The ZAP report is likely empty or missing.")
            
        report_data = json.loads(report_string)
        return report_data
    except json.JSONDecodeError as e:
        print(f"❌ Failed to decode JSON from standard input. Check ZAP output format. Error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Error reading report from pipe: {e}")
        sys.exit(1)

def analyze_with_gemini(report_data):
    """Sends the ZAP report to Gemini for structured analysis and summarization."""
    if not GEMINI_API_KEY:
        print("❌ GEMINI_API_KEY not found in environment variables.")
        return None

    print("🤖 Sending report to Gemini API for analysis...")
    
    # Initialize the client
    client = genai.Client(api_key=GEMINI_API_KEY)
    
    # Convert ZAP report data to a string for the prompt
    report_string = json.dumps(report_data, indent=2)

    # System prompt to guide the model's behavior
    system_instruction = (
        "You are an expert security analyst specializing in DAST (Dynamic Application Security Testing). "
        "Review the provided OWASP ZAP DAST scan report (in JSON format) and create a concise, "
        "structured summary for a development team. Categorize the overall threat level into "
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
        print(f"❌ Gemini API call failed. Check API key and quota. Error: {e}")
        return None

def format_slack_message(ai_report):
    """Formats the AI-generated JSON into a Slack-friendly message block payload."""
    
    # Define color based on threat level for visual cues in Slack
    color_map = {
        "None": "#36a64f",      # Green
        "Low": "#f2c744",       # Yellow
        "Medium": "#ff9900",    # Orange
        "High": "#ff0000",      # Red
        "Urgent/Red Alert": "#8b0000", # Dark Red
        "Unknown": "#cccccc"
    }
    threat_category = ai_report.get("threat_category", "Unknown")
    threat_color = color_map.get(threat_category, "#cccccc")
    
    attachments = []
    
    # --- Main Summary Attachment ---
    summary_attachment = {
        "color": threat_color,
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 AI DAST Report: {threat_category}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary:*\n{ai_report['summary']}"
                }
            }
        ]
    }
    attachments.append(summary_attachment)

    # --- Vulnerability Details Attachments ---
    for vul in ai_report.get("vulnerability_analysis", []):
        vul_attachment = {
            "color": threat_color,
            "blocks": [
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*:warning: {vul['name']}* (Severity: *{vul['severity']}*)\n\n"
                            f"*Diagnosis:*\n{vul['diagnosis']}\n\n"
                            f"*Actionable Fixes:*\n{vul['remediation']}"
                        )
                    }
                }
            ]
        }
        attachments.append(vul_attachment)

    # --- Next Steps Attachment ---
    next_steps_attachment = {
        "color": "#007bff", # Blue for action items
        "blocks": [
            {"type": "divider"},
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
    
    slack_payload = {
        "text": f"DAST Scan and AI Analysis Complete. Overall Threat Level: {threat_category}",
        "attachments": attachments
    }
    
    return slack_payload

def send_to_slack(payload):
    """Posts the formatted payload to the Slack Webhook URL."""
    if not SLACK_WEBHOOK_URL:
        print("❌ SLACK_WEBHOOK_URL not found. Skipping Slack notification.")
        return

    print("Sending message to Slack...")
    headers = {'Content-Type': 'application/json'}
    
    try:
        response = requests.post(SLACK_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        print("✅ Successfully sent AI-generated report to Slack.")
    except requests.exceptions.HTTPError as err:
        print(f"❌ HTTP Error sending to Slack. Check Webhook URL. Error: {err}")
    except requests.exceptions.RequestException as err:
        print(f"❌ An error occurred sending to Slack: {err}")

# --- Main Execution ---

if __name__ == "__main__":
    
    # 1. Read the ZAP report directly from the pipe (sys.stdin)
    zap_report = read_zap_report_from_stdin()
    
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
        print("AI classification is disabled. Script finished successfully.")
        sys.exit(0)
