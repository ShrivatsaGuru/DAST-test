import os
import json
from choose_model import get_model

with open("reports/deduplicated_report.json", encoding="utf-8") as f:
    issues = json.load(f)["issues"]

sarif_issues = []

# Choose provider: "gemini" (default), or "openai" in the future
ai = get_model("gemini")

for issue in issues:
    print("Sending issue to Gemini model...")  # Debug print
    resolution = ai.get_resolution(issue)
    print("Received response from Gemini.")    # Debug print
    sarif_issues.append({
        "file": issue["file"],
        "start_line": issue["start_line"],
        "end_line": issue["end_line"],
        "rule_id": issue["rule_id"],
        "message": issue["message"],
        "code": issue["code"],
        "resolution": resolution
    })

print("Writing output file...")  # Debug print

with open("reports/resolution.json", "w", encoding="utf-8") as f:
    json.dump({"issues": sarif_issues}, f, indent=2, ensure_ascii=False)

print("✅ Gemini resolutions written to reports/resolution.json")