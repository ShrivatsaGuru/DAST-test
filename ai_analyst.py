import json
import os
from collections import defaultdict
from google import genai

# ------------------ CONFIG ------------------
GEMINI_MODEL = "gemini-2.5-flash"

SEVERITY_MAP = {
    0: ("None", "⚪"),
    1: ("Low", "🟢"),
    2: ("Medium", "🟡"),
    3: ("High", "🟠"),
    4: ("Critical", "🔴"),
}

CATEGORY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

# ------------------ GEMINI CLIENT ------------------
client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])

# ------------------ LOAD ZAP REPORT ------------------
with open("zap_report.json", "r") as f:
    zap = json.load(f)

sites = zap.get("site", [])
alerts = sites[0].get("alerts", []) if sites else []

grouped = defaultdict(list)

# ------------------ ANALYZE EACH VULNERABILITY ------------------
for alert in alerts:
    risk_code = int(alert.get("riskcode", 0))
    severity, emoji = SEVERITY_MAP[risk_code]

    prompt = f"""
You are a senior application security engineer.

You are analyzing an OWASP ZAP DAST finding.

IMPORTANT RULES:
- This is a DAST scan. Do NOT invent exact file names or line numbers.
- If exact code location is unknown, say: "Not available from DAST scan"
- Be clear, concise, and practical.
- Provide secure coding examples.
- Output PLAIN TEXT (not JSON).

Vulnerability Name:
{alert.get("alert")}

Affected URL:
{alert.get("url")}

Parameter:
{alert.get("param")}

Evidence:
{alert.get("evidence")}

Description:
{alert.get("desc")}

ZAP Suggested Solution:
{alert.get("solution")}

Create a structured explanation with the following sections:

1. What is the problem?
2. Where is it likely located in the codebase?
3. Why is this dangerous?
4. How to fix it (include a short secure code example)
"""

    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt
    )

    grouped[severity].append({
        "emoji": emoji,
        "title": alert.get("alert"),
        "endpoint": alert.get("url"),
        "analysis": response.text.strip()
    })

# ------------------ BUILD SLACK REPORT ------------------
lines = []
lines.append("🛡️ *ZAP DAST Security Report – Gemini AI Analysis*")
lines.append("")
lines.append("This report summarizes the vulnerabilities detected by OWASP ZAP and analyzed by Gemini AI.")
lines.append("")

# Summary
lines.append("*📊 Summary*")
for sev in CATEGORY_ORDER:
    lines.append(f"{SEVERITY_MAP[[k for k,v in SEVERITY_MAP.items() if v[0]==sev][0]][1]} {sev}: {len(grouped.get(sev, []))}")
lines.append("\n---\n")

# Detailed sections
for severity in CATEGORY_ORDER:
    findings = grouped.get(severity, [])
    if not findings:
        continue

    emoji = findings[0]["emoji"]
    lines.append(f"{emoji} *{severity} Severity Issues*")
    lines.append("")

    for idx, v in enumerate(findings, start=1):
        lines.append(f"*{idx}. {v['title']}*")
        lines.append(f"• *Affected Endpoint:* `{v['endpoint']}`")
        lines.append(v["analysis"])
        lines.append("\n---\n")

# ------------------ WRITE OUTPUT ------------------
final_report = "\n".join(lines)

with open("slack_report.txt", "w") as f:
    f.write(final_report)

print("✅ Gemini analysis complete")
print("📄 Slack-ready report written to slack_report.txt")
