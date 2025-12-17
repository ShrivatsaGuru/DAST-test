import json
import uuid

with open("reports/resolution.json", encoding="utf-8") as f:
    issues = json.load(f)["issues"]

sarif = {
    "version": "2.1.0",
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "AI SAST Gemini",
                    "informationUri": "https://github.com/aayushxrj/ai-sast-dast-pipeline-ci-cd",
                    "rules": []
                }
            },
            "results": []
        }
    ]
}

rule_ids = set()
for issue in issues:
    rule_id = issue["rule_id"]
    if rule_id not in rule_ids:
        sarif["runs"][0]["tool"]["driver"]["rules"].append({
            "id": rule_id,
            "name": rule_id,
            # "shortDescription": {"text": issue["message"][:120]},
            "shortDescription": {"text": rule_id},
            "fullDescription": {"text": issue["message"]},
            "help": {"text": issue["resolution"], "markdown": issue["resolution"]}
        })
        rule_ids.add(rule_id)

    sarif["runs"][0]["results"].append({
        "ruleId": rule_id,
        "message": {
            "text": f"{issue['message']}\n\nGemini Suggestion: {issue['resolution']}"
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": issue["file"]},
                    "region": {
                        "startLine": issue["start_line"],
                        "endLine": issue["end_line"],
                    }
                }
            }
        ]
    })

with open("reports/final_report.sarif", "w", encoding="utf-8") as f:
    json.dump(sarif, f, indent=2, ensure_ascii=False)

print("✅ SARIF file written to reports/final_report.sarif")