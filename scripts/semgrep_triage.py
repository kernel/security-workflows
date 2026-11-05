#!/usr/bin/env python3
"""GitHub side of the Semgrep triage agent, run by semgrep.yml.

`gather` writes the PR's commentable lines and existing inline comments for the agent to read.
`post` checks the agent's JSON result against the Semgrep findings, the PR diff, and the
comments already on the PR, then posts the remaining comments as one review.

The agent itself has no GitHub token or shell; only these runner steps call the API.
Needs only the standard library and the runner's `gh`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_COMMENTS = 5


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

    def files(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/repos/{self.repo}/pulls/{number}/files?per_page=100")

    def review_comments(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/repos/{self.repo}/pulls/{number}/comments?per_page=100")

    def create_review(self, number: int, review: dict[str, Any]) -> None:
        self.api("--method", "POST", f"/repos/{self.repo}/pulls/{number}/reviews", body=review)


def commentable_lines(files: list[dict[str, Any]]) -> dict[str, list[list[int]]]:
    """New-file line ranges of each diff hunk: the lines a review comment can be placed on."""
    lines: dict[str, list[list[int]]] = {}
    for f in files:
        for m in re.finditer(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", f.get("patch") or "", re.M):
            start, length = int(m.group(1)), int(m.group(2) or 1)
            if length:
                lines.setdefault(f["filename"], []).append([start, start + length - 1])
    return lines


def comment_locations(comments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"path": c["path"], "line": c.get("line"), "original_line": c.get("original_line"),
             "author": (c.get("user") or {}).get("login")} for c in comments]


def gather(gh: GitHub, number: int, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "commentable-lines.json").write_text(json.dumps(commentable_lines(gh.files(number)), indent=1))
    (out / "existing-comments.json").write_text(json.dumps(comment_locations(gh.review_comments(number)), indent=1))


def parse_result(text: str) -> dict[str, Any]:
    """The agent's final message: one JSON object, possibly inside a code fence."""
    text = text.strip()
    fenced = re.fullmatch(r"```(?:json)?\s*\n(.*)\n```", text, re.S)
    result = json.loads(fenced.group(1) if fenced else text)
    if not isinstance(result, dict) or not isinstance(result.get("comments"), list):
        raise ValueError("expected an object with a comments array")
    omitted = result.setdefault("omitted", 0)
    if not isinstance(omitted, int) or isinstance(omitted, bool) or omitted < 0:
        raise ValueError("omitted must be a non-negative integer")
    return result


def select_comments(result: dict[str, Any], findings: list[dict[str, Any]],
                    commentable: dict[str, list[list[int]]],
                    existing: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Comments that sit on a Semgrep finding, inside the diff, on a line nobody has commented on."""
    taken = {(c["path"], n) for c in existing for n in (c.get("line"), c.get("original_line")) if n}
    kept: list[dict[str, Any]] = []
    for c in result["comments"]:
        path, line, body = (c.get("path"), c.get("line"), c.get("body")) if isinstance(c, dict) else (None,) * 3
        if not (isinstance(path, str) and isinstance(line, int) and not isinstance(line, bool)
                and isinstance(body, str) and body.strip()):
            print(f"::warning::Dropping malformed comment: {json.dumps(c)[:200]}")
            continue
        where = f"{path}:{line}"
        if not any(f["path"] == path and f["start"]["line"] <= line <= f["end"]["line"] for f in findings):
            print(f"::warning::Dropping comment on {where}: no Semgrep finding there")
        elif not any(lo <= line <= hi for lo, hi in commentable.get(path, [])):
            print(f"::warning::Dropping comment on {where}: line is outside the PR diff")
        elif (path, line) in taken:
            print(f"Skipping {where}: the line already has a review comment")
        else:
            taken.add((path, line))
            kept.append({"path": path, "line": line, "body": body})
    return kept[:MAX_COMMENTS], result["omitted"] + max(0, len(kept) - MAX_COMMENTS)


def post(gh: GitHub, number: int, commit: str, workdir: Path, results: Path) -> int:
    try:
        result = parse_result((workdir / "agent-output.txt").read_text())
    except (OSError, ValueError) as e:
        print(f"::error::The triage agent did not return a valid result: {e}")
        return 1
    findings = json.loads(results.read_text()).get("results", [])
    commentable = json.loads((workdir / "commentable-lines.json").read_text())
    # Re-read right before posting: other reviewers may have commented while the agent ran.
    existing = comment_locations(gh.review_comments(number))
    comments, omitted = select_comments(result, findings, commentable, existing)
    if not comments:
        print("No actionable security findings.")
        return 0
    review: dict[str, Any] = {"commit_id": commit, "event": "COMMENT", "comments": comments}
    if omitted:
        review["body"] = (f"{omitted} more actionable Semgrep finding{'s' if omitted != 1 else ''} "
                          f"not posted (limit: {MAX_COMMENTS} inline comments).")
    gh.create_review(number, review)
    print(f"Posted {len(comments)} inline comment(s).")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("gather", "post"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
        p.add_argument("--number", type=int, required=True)
        p.add_argument("--dir", type=Path, required=True)
        if name == "post":
            p.add_argument("--commit", required=True)
            p.add_argument("--results", type=Path, required=True)
    args = parser.parse_args(argv)
    gh = GitHub(args.repo)
    if args.command == "gather":
        gather(gh, args.number, args.dir)
        return 0
    return post(gh, args.number, args.commit, args.dir, args.results)


if __name__ == "__main__":
    sys.exit(main())
