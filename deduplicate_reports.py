import json
from pathlib import Path

INPUT_FILE = "reports/combined_report.json"
OUTPUT_FILE = "reports/deduplicated_report.json"

def load_issues(path):
    with open(path) as f:
        return json.load(f).get("issues", [])

def deduplicate(issues):
    seen = set()
    deduped = []

    for issue in issues:
        key = (
            issue["start_line"],
            issue["end_line"],
        )
        if key not in seen:
            seen.add(key)
            deduped.append(issue)
    return deduped

def save_issues(path, issues):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"issues": issues}, f, indent=2)

def main():
    print(f"🔄 Loading issues from: {INPUT_FILE}")
    all_issues = load_issues(INPUT_FILE)
    print(f"📊 Total issues before deduplication: {len(all_issues)}")

    unique_issues = deduplicate(all_issues)
    print(f"✅ Unique issues after deduplication: {len(unique_issues)}")

    save_issues(OUTPUT_FILE, unique_issues)
    print(f"💾 Saved deduplicated issues to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
