import json
from pathlib import Path

def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def safe_load_json(path, default):
    p = Path(path)
    if p.exists() and p.stat().st_size > 0:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default

def get_standard_level(tool, severity):
    severity = severity.upper()
    if tool == "bandit":
        return {
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note"
        }.get(severity, "warning")
    elif tool == "semgrep":
        return {
            "ERROR": "error",
            "WARNING": "warning",
            "INFO": "note"
        }.get(severity, "warning")
    elif tool == "gitleaks":
        return "error"
    return "warning"

bandit_data = safe_load_json("reports/bandit_report.json", {})
semgrep_data = safe_load_json("reports/semgrep_report.json", {})
gitleaks_data = safe_load_json("reports/gitleaks_report.json", [])

combined_issues = []

# Semgrep
for item in semgrep_data.get("results", []):
    start = item.get("start", {})
    end = item.get("end", {})
    extra = item.get("extra", {})
    metadata = extra.get("metadata", {})

    combined_issues.append({
        "tool": "semgrep",
        "file": item["path"],
        "start_line": start.get("line", 0),
        "end_line": end.get("line", start.get("line", 0)),
        "start_column": start.get("col", 0),
        "end_column": end.get("col", start.get("col", 0)),
        "severity": extra.get("severity", "UNKNOWN"),
        "level": get_standard_level("semgrep", extra.get("severity", "UNKNOWN")),
        "confidence": metadata.get("confidence", ""),
        "rule_id": item["check_id"],
        "message": extra.get("message", ""),
        "cwe": metadata.get("cwe", [""])[0],
        "source_url": metadata.get("source", ""),
       "code": extra.get("lines", "") 
    })

# Bandit
for item in bandit_data.get("results", []):
    start_line = item["line_number"]
    end_line = max(item.get("line_range", [start_line]))
    combined_issues.append({
        "tool": "bandit",
        "file": item["filename"],
        "start_line": start_line,
        "end_line": end_line,
        "start_column": item.get("col_offset", 0),
        "end_column": item.get("col_offset", 0),
        "severity": item["issue_severity"],
        "level": get_standard_level("bandit", item["issue_severity"]),
        "confidence": item["issue_confidence"],
        "rule_id": item["test_id"],
        "message": item["issue_text"],
        "cwe": item.get("issue_cwe", {}).get("id", ""),
        "source_url": item.get("more_info", ""),
        "code": item.get("code", "")
    })


# Gitleaks
for item in gitleaks_data:
    combined_issues.append({
        "tool": "gitleaks",
        "file": item["File"],
        "start_line": item["StartLine"],
        "end_line": item["EndLine"],
        "start_column": item["StartColumn"],
        "end_column": item["EndColumn"],
        "severity": "HIGH",
        "level": get_standard_level("gitleaks", "HIGH"),
        "confidence": "HIGH",
        "rule_id": item["RuleID"],
        "message": item["Description"],
        "cwe": None,
        "source_url": None,
        "code": item["Match"]
    })

# Save output
Path("reports").mkdir(exist_ok=True)
with open("reports/combined_report.json", "w") as f:
    json.dump({"issues": combined_issues}, f, indent=2)

print(f"✅ Combined {len(combined_issues)} issues into reports/combined_report.json")
