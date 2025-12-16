import os
import sys
import json
from google import genai
from google.genai import types

# --- Configuration ---
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

# Define the structured output format for Gemini
AI_REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "overall_threat_level": {"type": "string", "description": "Overall security rating for the site: None, Low, Medium, High, or Urgent/Red Alert."},
        "summary": {"type": "string", "description": "A brief, non-technical summary of the findings."},
        "critical_vulnerabilities": {
            "type": "array",
            "description": "Analysis of the top 3 most critical vulnerabilities.",
            "items": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "category": {"type": "string", "description": "Category of the vulnerability (e.g., Injection, XSS, Misconfiguration, etc.)"},
                    "diagnosis": {"type": "string", "description": "Detailed explanation of the vulnerability and its impact."},
                    "remediation_steps": {"type": "string", "description": "Specific, actionable steps to fix the vulnerability, formatted in markdown."}
                },
                "required": ["name", "category", "diagnosis", "remediation_steps"]
            }
        },
        "next_steps": {"type": "string", "description": "Clear next steps for the security team."}
    },
    "required": ["overall_threat_level", "summary", "critical_vulnerabilities", "next_steps"]
}

def analyze_report(report_data):
    """Sends the ZAP report to Gemini for structured analysis."""
    if not GEMINI_API_KEY:
        print("❌ Error: GEMINI_API_KEY environment variable not set.")
        return None

    print("\n🤖 Sending ZAP report to Gemini for structured analysis...")
    
    try:
        client = genai.Client(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"❌ Error initializing Gemini client: {e}")
        return None
        
    report_string = json.dumps(report_data, indent=2)

    system_instruction = (
        "You are an expert security analyst reviewing a DAST report. "
        "Summarize the findings, categorize the overall threat level (None, Low, Medium, High, Urgent/Red Alert), "
        "and provide detailed, actionable remediation steps for the most critical issues. "
        "Your output MUST be a JSON object strictly following the provided schema."
    )

    prompt = f"Analyze the following OWASP ZAP DAST report (JSON):\n\n{report_string}"

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
        
        # Print the raw JSON response text for logging
        print("\n--- AI-GENERATED REPORT JSON ---")
        print(response.text)
        print("--------------------------------\n")
        
        return json.loads(response.text)
        
    except Exception as e:
        print(f"❌ Gemini API call failed. Error: {e}")
        return None

def main():
    if len(sys.argv) < 2:
        print("Usage: python ai_analyst.py <path_to_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]

    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            zap_report = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: Report file not found at {report_path}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"❌ Error: Failed to parse JSON from {report_path}")
        sys.exit(1)

    ai_report = analyze_report(zap_report)

    if ai_report:
        print(f"✅ AI Analysis Complete. Overall Threat: {ai_report.get('overall_threat_level')}")
        # Optionally save the structured AI report for other steps (e.g., Slack)
        with open("ai_report.json", "w") as f:
            json.dump(ai_report, f, indent=2)
        print("✅ Structured AI report saved to ai_report.json.")
        
    else:
        print("🛑 AI analysis failed. Exiting.")
        sys.exit(1)

if __name__ == "__main__":
    main()
