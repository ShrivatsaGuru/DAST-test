import os
import json
import requests
import subprocess
from collections import defaultdict

# --- Setup ---
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
REPO = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = os.environ["PR_NUMBER"]

# Load security issues from JSON
with open("reports/resolution.json", encoding="utf-8") as f:
    issues = json.load(f).get("issues", [])

# --- Fetch PR Info ---
headers = {"Authorization": f"token {GITHUB_TOKEN}"}
pr_url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}"
pr_resp = requests.get(pr_url, headers=headers)
pr_resp.raise_for_status()

pr_data = pr_resp.json()
commit_sha = pr_data["head"]["sha"]
base_sha = pr_data["base"]["sha"]

# --- Fetch diff between base and head ---
subprocess.run(["git", "fetch", "origin", base_sha], check=True)
diff_output = subprocess.run(
    ["git", "diff", base_sha, commit_sha, "--unified=0"],
    stdout=subprocess.PIPE, text=True
).stdout

# Optional debug
print("📄 Raw git diff output (first 500 chars):\n", diff_output[:500])

# --- Parse changed lines ---
changed_lines = defaultdict(set)
current_file = None
for line in diff_output.splitlines():
    if line.startswith("+++ b/"):
        current_file = line[6:]
    elif line.startswith("@@"):
        parts = line.split(" ")
        if len(parts) >= 3 and current_file:
            new_range = parts[2]
            if new_range.startswith("+"):
                start_end = new_range[1:].split(",")
                start = int(start_end[0])
                count = int(start_end[1]) if len(start_end) > 1 else 1
                for i in range(start, start + count):
                    changed_lines[current_file].add(i)

# Debug: print changed lines
print("📄 Detected changed lines:")
for f, lines in changed_lines.items():
    print(f"  {f}: {sorted(lines)}")

# --- Filter issues for changed lines ---
comments = []
for issue in issues:
    path = issue["file"]
    line = issue["end_line"]
    if line in changed_lines.get(path, set()):
        comments.append({
            "path": path,
            "side": "RIGHT",
            "line": line,
            "body": f'{issue["message"]}\n\n**Suggested Fix:**\n{issue["resolution"]}'
        })

# --- Post review or skip ---
if not comments:
    print("⚠️ No commentable issues found on changed lines.")
    exit(0)

review_url = f"https://api.github.com/repos/{REPO}/pulls/{PR_NUMBER}/reviews"
review_data = {
    "commit_id": commit_sha,
    "body": "🔐 Automated security review comments.",
    "event": "COMMENT",
    "comments": comments
}
resp = requests.post(review_url, headers=headers, json=review_data)
resp.raise_for_status()
print("✅ PR review comments posted.")
