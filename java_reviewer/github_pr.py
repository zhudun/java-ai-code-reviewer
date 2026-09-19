from __future__ import annotations

import json
import os
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from java_reviewer.models import ReviewReport
from java_reviewer.reporters.markdown import render_markdown


def post_review_comment(report: ReviewReport, title: str = "Java AI Code Review") -> str | None:
    token = os.environ.get("GITHUB_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    number = _pr_number()
    if not token or not repo or not number:
        return None
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com")
    body = f"## {title}\n\n" + render_markdown(report)
    payload = json.dumps({"body": body}).encode("utf-8")
    url = f"{api}/repos/{repo}/issues/{number}/comments"
    request = Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "java-ai-code-reviewer",
        },
    )
    try:
        with urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
        return data.get("html_url")
    except (HTTPError, URLError, TimeoutError):
        return None


def _pr_number() -> str | None:
    if os.environ.get("GITHUB_EVENT_NAME") == "pull_request":
        event_path = os.environ.get("GITHUB_EVENT_PATH")
        if event_path and os.path.exists(event_path):
            data = json.loads(open(event_path, encoding="utf-8").read())
            number = data.get("number") or data.get("pull_request", {}).get("number")
            if number:
                return str(number)
    return os.environ.get("PR_NUMBER")
