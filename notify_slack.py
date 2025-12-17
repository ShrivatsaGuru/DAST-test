import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

RESOLUTION_PATH = "reports/resolution.json"
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
GITHUB_EVENT_NAME = os.getenv("GITHUB_EVENT_NAME")
GITHUB_SERVER_URL = os.getenv("GITHUB_SERVER_URL", "https://github.com")

# PR-specific
PR_NUMBER = os.getenv("GITHUB_PR_NUMBER")
PR_TITLE = os.getenv("GITHUB_PR_TITLE")
PR_AUTHOR = os.getenv("GITHUB_PR_AUTHOR")

# Push-specific
PUSH_AUTHOR = os.getenv("GITHUB_PUSH_AUTHOR")
PUSH_BRANCH = os.getenv("GITHUB_PUSH_BRANCH")
GITHUB_SHA = os.getenv("GITHUB_SHA")

# Workflow run
GITHUB_RUN_ID = os.getenv("GITHUB_RUN_ID")


def get_issues_count():
    try:
        with open(RESOLUTION_PATH, encoding="utf-8") as f:
            data = json.load(f)
            return len(data.get("issues", []))
    except Exception:
        return 0


def main():
    issues_count = get_issues_count()
    repo_url = f"{GITHUB_SERVER_URL}/{GITHUB_REPOSITORY}"
    security_tab_url = f"{repo_url}/security/code-scanning"
    workflow_url = f"{repo_url}/actions/runs/{GITHUB_RUN_ID}"

    msg = ""

    if GITHUB_EVENT_NAME == "pull_request_target":
        pr_url = f"{repo_url}/pull/{PR_NUMBER}"
        msg += f":warning: *{issues_count} security issue(s) detected in Pull Request scan.*\n"
        msg += f"> *PR:* <{pr_url}|#{PR_NUMBER} - {PR_TITLE}> by `{PR_AUTHOR}`\n"
    else:
        commit_url = f"{repo_url}/commit/{GITHUB_SHA}"
        msg += f":warning: *{issues_count} security issue(s) detected in Push scan.*\n"
        msg += f"> *Branch:* `{PUSH_BRANCH}` | *Author:* `{PUSH_AUTHOR}` | <{commit_url}|View Commit>\n"

    msg += f"> *Security tab:* <{security_tab_url}|View all security issues>\n"
    msg += f"> *Artifacts:* <{workflow_url}|Download scan reports>"

    payload = {"text": msg}
    resp = requests.post(SLACK_WEBHOOK_URL, json=payload)
    if resp.status_code != 200:
        print(f"Failed to send Slack notification: {resp.text}")
    else:
        print("✅ Slack notification sent.")


if __name__ == "__main__":
    main()
