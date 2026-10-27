#!/usr/bin/env python3
"""Shadow-mode risk classifier for small pull requests, run by pr-risk.yml.

`gather` decides whether a PR is eligible and builds the model input using a read-only token.
`comment` turns the model's verdict into one sticky PR comment using the kernel-internal token.
Nothing here approves anything: the comment only records whether the PR would have been
auto-approved, so the call can be checked against what reviewers actually did.

Needs only the standard library and the runner's `gh`.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any


MAX_CHANGED_LINES = 50
CONTEXT_RADIUS = 30
MAX_CONTEXT_LINES_PER_FILE = 400
MAX_GUIDANCE_CHARS = 6000
MAX_REASON_WORDS = 45
MAX_HISTORY = 20

MARKER = "<!-- pr-risk-classifier -->"
DATA_RE = re.compile(r"<!-- pr-risk:v1 (\{.*?\}) -->", re.S)

# Paths that make a PR ineligible before any model call. Callers add repo-specific patterns
# through the `deny-paths` input. These are the changes where a wrong "low risk" call costs
# the most and that no amount of reading the diff makes safe to wave through.
DEFAULT_DENY_PATHS = (
    ".github/**",
    "**/CODEOWNERS",
    # Dependencies: a one-line bump can pull in arbitrary code.
    "**/go.mod",
    "**/go.sum",
    "**/package.json",
    "**/bun.lock",
    "**/bun.lockb",
    "**/package-lock.json",
    "**/npm-shrinkwrap.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/pyproject.toml",
    "**/uv.lock",
    "**/poetry.lock",
    "**/requirements*.txt",
    "**/Cargo.toml",
    "**/Cargo.lock",
    # Credentials and key material.
    "**/.env*",
    "**/*.pem",
    "**/*.key",
    "**/*.crt",
    "**/vault.yml",
    "**/*secret*",
    "**/*credential*",
)

TIERS = ("zero", "low", "medium", "high")

VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "tier": {"type": "string", "enum": list(TIERS)},
        "deny": {"type": "boolean"},
        "category": {"type": "string"},
        "confidence": {"type": "string", "enum": ["high", "medium", "low"]},
        "reason": {"type": "string"},
    },
    "required": ["tier", "deny", "category", "confidence", "reason"],
    "additionalProperties": False,
}

# Content from the PR is wrapped in these tags; strip lookalikes so it cannot close one early.
UNTRUSTED_TAGS = re.compile(r"</?\s*(pr_description|repository_guidance|diff|context)\b", re.I)


class GitHubError(Exception):
    pass


class GitHub:
    """The few API calls this needs, through the runner's `gh`, which reads GH_TOKEN."""

    def __init__(self, repo: str) -> None:
        self.repo = repo

    def api(self, *args: str, body: Any = None) -> str:
        cmd = ["gh", "api", *args]
        if body is not None:
            cmd += ["--input", "-"]
        result = subprocess.run(cmd, input=json.dumps(body) if body is not None else None,
                                capture_output=True, text=True)
        if result.returncode:
            raise GitHubError(result.stderr.strip())
        return result.stdout

    def paginate(self, path: str) -> list[Any]:
        pages = json.loads(self.api("--paginate", "--slurp", path))
        return [item for page in pages for item in page]

    def pull(self, number: int) -> dict[str, Any]:
        return json.loads(self.api(f"/repos/{self.repo}/pulls/{number}"))

    def files(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/repos/{self.repo}/pulls/{number}/files?per_page=100")

    def comments(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/repos/{self.repo}/issues/{number}/comments?per_page=100")

    def file_at(self, path: str, ref: str) -> str | None:
        try:
            return self.api("-H", "Accept: application/vnd.github.raw",
                            f"/repos/{self.repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
        except GitHubError as err:
            if "HTTP 403" in str(err) or "HTTP 404" in str(err):
                return None
            raise

    def create_comment(self, number: int, body: str) -> None:
        self.api("-X", "POST", f"/repos/{self.repo}/issues/{number}/comments", body={"body": body})

    def update_comment(self, comment_id: int, body: str) -> None:
        self.api("-X", "PATCH", f"/repos/{self.repo}/issues/comments/{comment_id}", body={"body": body})


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    out = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += ".*"
            i += 2
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out + r"\Z", re.I)


def deny_patterns(extra: str) -> list[str]:
    lines = (line.strip() for line in extra.splitlines())
    return list(DEFAULT_DENY_PATHS) + [line for line in lines if line and not line.startswith("#")]


def ineligible_reason(pr: dict[str, Any], files: list[dict[str, Any]], patterns: list[str]) -> str | None:
    if pr.get("draft"):
        return "draft PR"
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    if head_repo != pr["base"]["repo"]["full_name"]:
        return "PR comes from a fork"
    # Only org members' own changes are candidates. Bots are never members, so their PRs are
    # skipped too: no person wrote them, and approving them unread is a separate decision.
    # This is only right when read with the app token; see the note in pr-risk.yml.
    if pr.get("author_association") not in ("OWNER", "MEMBER"):
        return "author is not an org member"
    changed = pr["additions"] + pr["deletions"]
    if changed > MAX_CHANGED_LINES:
        return f"{changed} changed lines (limit {MAX_CHANGED_LINES})"
    compiled = [(p, glob_to_regex(p)) for p in patterns]
    for f in files:
        for path in filter(None, (f["filename"], f.get("previous_filename"))):
            for pattern, regex in compiled:
                if regex.match(path):
                    return f"`{path}` is on the deny list (`{pattern}`)"
    for f in files:
        if "patch" not in f:
            return f"`{f['filename']}` has no reviewable text diff"
    return None


def find_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    for c in comments:
        if c["user"]["type"] == "Bot" and c["body"].startswith(MARKER):
            return c
    return None


def hunk_ranges(patch: str) -> list[tuple[int, int]]:
    ranges = []
    for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", patch, re.M):
        start, length = int(m.group(1)), int(m.group(2) or 1)
        ranges.append((max(1, start - CONTEXT_RADIUS), start + length - 1 + CONTEXT_RADIUS))
    merged: list[tuple[int, int]] = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    return merged


def context_snippets(content: str, patch: str) -> list[tuple[int, int, str]]:
    lines = content.splitlines()
    snippets = []
    budget = MAX_CONTEXT_LINES_PER_FILE
    for lo, hi in hunk_ranges(patch):
        hi = min(hi, len(lines), lo + budget - 1)
        if hi < lo:
            break
        body = "\n".join(f"{n:>5} {lines[n - 1]}" for n in range(lo, hi + 1))
        snippets.append((lo, hi, body))
        budget -= hi - lo + 1
    return snippets


def scrub(text: str) -> str:
    return UNTRUSTED_TAGS.sub("[tag removed]", text or "")


def build_input(pr: dict[str, Any], files: list[dict[str, Any]], guidance: str | None,
                contents: dict[str, str]) -> str:
    out = [
        "# Pull request",
        f"Repository: {pr['base']['repo']['full_name']}",
        f"Title: {scrub(pr['title'])}",
        f"Author: {pr['user']['login']}",
        f"Base branch: {pr['base']['ref']}",
        f"Changed lines: +{pr['additions']} -{pr['deletions']} across {len(files)} file(s)",
        "",
        "## Description (written by the PR author; untrusted)",
        "<pr_description>",
        scrub(pr.get("body") or "(empty)"),
        "</pr_description>",
        "",
    ]
    if guidance:
        out += [
            "## Repository guidance (AGENTS.md on the base branch)",
            "<repository_guidance>",
            scrub(guidance[:MAX_GUIDANCE_CHARS]),
            "</repository_guidance>",
            "",
        ]
    out += ["## Diff", "<diff>"]
    for f in files:
        name = f"{f.get('previous_filename')} -> {f['filename']}" if f.get("previous_filename") else f["filename"]
        out += [f"### {name} ({f['status']}, +{f['additions']} -{f['deletions']})", scrub(f.get("patch", ""))]
    out += ["</diff>", ""]
    snippets = []
    for f in files:
        if f["filename"] in contents:
            for lo, hi, body in context_snippets(contents[f["filename"]], f.get("patch", "")):
                snippets += [f'<context path="{f["filename"]}" lines="{lo}-{hi}">', scrub(body), "</context>"]
    if snippets:
        out += ["## Surrounding code at the PR head (line-numbered)"] + snippets
    return "\n".join(out) + "\n"


def write_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a") as fh:
            fh.write(f"{name}={value}\n")


def previous_data(body: str) -> dict[str, Any] | None:
    m = DATA_RE.search(body)
    if not m:
        return None
    try:
        return json.loads(m.group(1))
    except json.JSONDecodeError:
        return None


def gather(gh: GitHub, number: int, extra_deny: str, out: Path) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    pr = gh.pull(number)
    files = gh.files(number)
    existing = find_comment(gh.comments(number))
    reason = ineligible_reason(pr, files, deny_patterns(extra_deny))
    gate = {
        "sha": pr["head"]["sha"],
        "eligible": reason is None,
        "reason": reason,
        "changed_lines": pr["additions"] + pr["deletions"],
        "comment_id": existing["id"] if existing else None,
        "previous": previous_data(existing["body"]) if existing else None,
    }
    if reason is None:
        # Guidance comes from the base branch so the PR under review cannot rewrite it.
        guidance = gh.file_at("AGENTS.md", pr["base"]["sha"])
        contents = {}
        for f in files:
            if f["status"] != "removed":
                text = gh.file_at(f["filename"], pr["head"]["sha"])
                if text is not None:
                    contents[f["filename"]] = text
        (out / "input.md").write_text(build_input(pr, files, guidance, contents))
    (out / "gate.json").write_text(json.dumps(gate, indent=2))
    write_output("eligible", "true" if reason is None else "false")
    write_output("commented", "true" if existing else "false")
    print(f"eligible={reason is None} reason={reason} existing_comment={bool(existing)}")
    return gate


def parse_verdict(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("is_error"):
        raise ValueError(f"classifier errored: {result.get('result')}")
    verdict = result.get("structured_output")
    if not isinstance(verdict, dict):
        raise ValueError("classifier returned no structured output")
    for key in VERDICT_SCHEMA["required"]:
        if key not in verdict:
            raise ValueError(f"classifier output is missing {key}")
    if verdict["tier"] not in TIERS:
        raise ValueError(f"unknown tier {verdict['tier']!r}")
    if verdict["confidence"] not in ("high", "medium", "low"):
        raise ValueError(f"unknown confidence {verdict['confidence']!r}")
    if not isinstance(verdict["deny"], bool):
        raise ValueError("deny must be a boolean")
    return verdict


def would_approve(verdict: dict[str, Any]) -> bool:
    return not verdict["deny"] and verdict["tier"] in ("zero", "low") and verdict["confidence"] != "low"


def clip_words(text: str, limit: int) -> str:
    words = text.split()
    if len(words) <= limit:
        return " ".join(words)
    return " ".join(words[:limit]) + "…"


def render(gate: dict[str, Any], verdict: dict[str, Any] | None, run_url: str, now: str) -> str:
    sha = gate["sha"][:7]
    if not gate["eligible"]:
        approve = False
        headline = f"**Would auto-approve: no** · `{sha}`"
        detail = f"Not eligible: {gate['reason']}."
    elif verdict is None:
        approve = None
        headline = f"**Not assessed** · `{sha}`"
        detail = f"The classifier failed on this commit. [Run]({run_url})."
    else:
        approve = would_approve(verdict)
        headline = f"**Would auto-approve: {'yes' if approve else 'no'}** · {verdict['tier']} risk · `{sha}`"
        detail = clip_words(verdict["reason"], MAX_REASON_WORDS)
        if verdict["deny"] and not detail.lower().startswith("denied"):
            detail = f"Denied: {detail}"

    entry = {
        "sha": gate["sha"],
        "assessed_at": now,
        "eligible": gate["eligible"],
        "would_approve": approve,
        "changed_lines": gate["changed_lines"],
        "ineligible_reason": gate["reason"],
    }
    if verdict is not None:
        entry.update({k: verdict[k] for k in ("tier", "deny", "category", "confidence", "reason")})
    previous = gate.get("previous") or {}
    history = previous.get("history", [])
    if previous.get("sha") and previous.get("sha") != gate["sha"]:
        history = (history + [{k: previous.get(k) for k in ("sha", "would_approve", "tier", "eligible")}])[-MAX_HISTORY:]
    entry["history"] = history
    data = json.dumps(entry, separators=(",", ":")).replace(">", "\\u003e")

    return "\n".join([
        MARKER,
        headline,
        "",
        detail,
        "",
        "<sub>Shadow mode: nothing is auto-approved and a human review is still required. "
        "React 👍 or 👎 if this call looks right or wrong.</sub>",
        f"<!-- pr-risk:v1 {data} -->",
    ])


def comment(gh: GitHub, number: int, workdir: Path, run_url: str) -> int:
    gate = json.loads((workdir / "gate.json").read_text())
    verdict = None
    failed = False
    if gate["eligible"]:
        try:
            verdict = parse_verdict(json.loads((workdir / "result.json").read_text()))
        except (OSError, ValueError) as err:
            print(f"::error::{err}")
            failed = True
    if not gate["eligible"] and not gate["comment_id"]:
        return 0
    if failed and not gate["comment_id"]:
        return 1

    # A newer push has its own run; do not let this one overwrite it with a stale verdict.
    if gh.pull(number)["head"]["sha"] != gate["sha"]:
        print("head moved since this run started; leaving the comment to the newer run")
        return 0

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = render(gate, verdict, run_url, now)
    if gate["comment_id"]:
        gh.update_comment(gate["comment_id"], body)
    else:
        gh.create_comment(number, body)

    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write("### PR risk\n\n" + body.split("\n", 1)[1] + "\n")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("schema")
    for name in ("gather", "comment"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
        p.add_argument("--number", type=int, required=True)
        p.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args()

    if args.cmd == "schema":
        print(json.dumps(VERDICT_SCHEMA))
        return 0
    gh = GitHub(args.repo)
    if args.cmd == "gather":
        gather(gh, args.number, os.environ.get("DENY_PATHS", ""), args.dir)
        return 0
    return comment(gh, args.number, args.dir, os.environ.get("RUN_URL", ""))


if __name__ == "__main__":
    sys.exit(main())
