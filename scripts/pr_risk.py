#!/usr/bin/env python3
"""Shadow-mode risk classifier for small pull requests, run by pr-risk.yml.

`gather` decides whether a PR is eligible and builds the model input using a read-only token.
`verdict` turns pi's JSON event stream into result.json, the verdict envelope `comment` reads.
`comment` turns the model's verdict into one sticky PR comment using the kernel-internal token.
Nothing here approves anything: the comment only records whether the PR would have been
auto-approved, so the call can be checked against what reviewers actually did.

Needs only the standard library and the runner's `gh`.
"""

from __future__ import annotations

import argparse
import datetime
import difflib
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
# One line of diff or context longer than this is cut, keeping the shape of the change
# readable without feeding the model megabytes of base64 — a canvas replay table line is ~76KB.
MAX_LINE_CHARS = 200
# The shared ends kept around the differing middle when a -/+ pair is clipped.
PAIR_EDGE_CHARS = 80

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
# Cursor Bugbot adds a risk label (such as "Low Risk") to PR descriptions. The model read it as
# an attempt to steer its verdict and denied on it, so it is removed before the model sees it.
BUGBOT_SUMMARY = re.compile(r"<!-- CURSOR_SUMMARY -->.*?<!-- /CURSOR_SUMMARY -->", re.S)


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

    def permission(self, login: str) -> str:
        data = json.loads(self.api(f"/repos/{self.repo}/collaborators/{urllib.parse.quote(login)}/permission"))
        return data["permission"]

    def merge_base(self, base: str, head: str) -> str:
        """The commit a PR's diff is measured from, not the base branch tip."""
        data = json.loads(self.api(f"/repos/{self.repo}/compare/{base}...{head}"))
        return data["merge_base_commit"]["sha"]

    def file_at(self, path: str, ref: str) -> str | None:
        try:
            text = self.api("-H", "Accept: application/vnd.github.raw",
                            f"/repos/{self.repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
        except UnicodeDecodeError:
            # Binary content does not decode as text; there is no diff to read.
            return None
        except GitHubError as err:
            if "HTTP 403" in str(err) or "HTTP 404" in str(err):
                return None
            raise
        if "\x00" in text:
            # Git treats NUL bytes as binary (UTF-16 and friends); no text diff either.
            return None
        return text

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


def ineligible_reason(pr: dict[str, Any], files: list[dict[str, Any]], patterns: list[str],
                      author_permission: str) -> str | None:
    if pr.get("draft"):
        return "draft PR"
    head_repo = (pr["head"].get("repo") or {}).get("full_name")
    if head_repo != pr["base"]["repo"]["full_name"]:
        return "PR comes from a fork"
    # Only changes by people who can already push here are candidates. Bots have no repo
    # permission, so their PRs are skipped too: no person wrote them, and approving them unread
    # is a separate decision. author_association can't be used: every Kernel member is private,
    # and both the workflow token and the event payload report private members as CONTRIBUTOR.
    if author_permission not in ("admin", "write"):
        return "author does not have write access"
    changed = pr["additions"] + pr["deletions"]
    if changed > MAX_CHANGED_LINES:
        return f"{changed} changed lines (limit {MAX_CHANGED_LINES})"
    compiled = [(p, glob_to_regex(p)) for p in patterns]
    for f in files:
        for path in filter(None, (f["filename"], f.get("previous_filename"))):
            for pattern, regex in compiled:
                if regex.match(path):
                    return f"`{path}` is on the deny list (`{pattern}`)"
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
    lines = content.split("\n")
    snippets = []
    budget = MAX_CONTEXT_LINES_PER_FILE
    for lo, hi in hunk_ranges(patch):
        hi = min(hi, len(lines), lo + budget - 1)
        if hi < lo:
            break
        body = "\n".join(f"{n:>5} {clip_line(lines[n - 1])}" for n in range(lo, hi + 1))
        snippets.append((lo, hi, body))
        budget -= hi - lo + 1
    return snippets


def scrub(text: str) -> str:
    return UNTRUSTED_TAGS.sub("[tag removed]", text or "")


def clip_line(line: str) -> str:
    """One diff or context line, with very long lines cut to what the model can usefully read."""
    if len(line) <= MAX_LINE_CHARS:
        return line
    return f"{line[:MAX_LINE_CHARS]}… [{len(line):,} chars]"


def clip_middle(text: str, limit: int) -> str:
    return text if len(text) <= limit else f"{text[:limit]}… [{len(text):,} chars]"


def clip_pair(old: str, new: str) -> tuple[str, str]:
    """One -/+ pair of a diff, clipped so the first place the lines differ stays visible.

    Clipping both lines at the same width can hide the change: two lines sharing a long
    prefix clip to identical visible text and the change reads as a no-op. The shared prefix
    and suffix are cut to PAIR_EDGE_CHARS instead, leaving the differing middle in view.
    """
    if len(old) <= MAX_LINE_CHARS and len(new) <= MAX_LINE_CHARS:
        return old, new
    o, n = old[1:], new[1:]
    prefix = os.path.commonprefix([o, n])
    suffix = os.path.commonprefix([o[len(prefix):][::-1], n[len(prefix):][::-1]])[::-1]
    om = o[len(prefix):len(o) - len(suffix) or None]
    nm = n[len(prefix):len(n) - len(suffix) or None]
    head, tail = clip_middle(prefix, PAIR_EDGE_CHARS), clip_middle(suffix, PAIR_EDGE_CHARS)
    return (f"-{head}…{clip_middle(om, MAX_LINE_CHARS)}…{tail}",
            f"+{head}…{clip_middle(nm, MAX_LINE_CHARS)}…{tail}")


def clip_diff(text: str) -> str:
    """A diff, clipped line by line, with the first difference of each -/+ pair kept visible."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        if not lines[i].startswith("-") or lines[i].startswith("---"):
            out.append(clip_line(lines[i]))
            i += 1
            continue
        j = i
        while j < len(lines) and lines[j].startswith("-") and not lines[j].startswith("---"):
            j += 1
        k = j
        while k < len(lines) and lines[k].startswith("+") and not lines[k].startswith("+++"):
            k += 1
        olds, news = lines[i:j], lines[j:k]
        if news:
            for o, n in zip(olds, news):
                out.extend(clip_pair(o, n))
            out.extend(clip_line(line) for line in olds[len(news):] + news[len(olds):])
        else:
            out.extend(clip_line(line) for line in olds)
        i = k
    return "\n".join(out)


def count_changed_lines(patch: str) -> int:
    """The + and - lines of a diff, which is what the changed-lines cap counts."""
    return sum(1 for line in patch.split("\n")
               if line[:1] in "+-" and not line.startswith(("+++", "---")))


def synthesize_patch(gh: GitHub, f: dict[str, Any], base_sha: str, head: str | None) -> str | None:
    """A unified diff for a file GitHub renders no patch for, from the merge base to the head.

    GitHub omits the patch when the diff is too large to show, which is normal for files with
    very long lines, such as data tables — not only binaries, the old assumption. `head` is
    the file's content at the PR head, already fetched for the context; `base_sha` is the
    merge base, which is what GitHub measures the diff and the line counts from, so changes
    made on the base branch after the branch point do not leak into the diff inverted.
    Binary or unfetchable content (None from file_at), and no content change between the two
    ends (no hunks), return None so the PR stays ineligible as before.
    """
    old_path = f.get("previous_filename") or f["filename"]
    base = "" if f["status"] == "added" else gh.file_at(old_path, base_sha)
    if base is None or head is None:
        return None
    patch = "\n".join(difflib.unified_diff(
        base.split("\n"), head.split("\n"),
        fromfile=f"a/{old_path}", tofile=f"b/{f['filename']}", lineterm=""))
    return patch if "@@" in patch else None


def build_input(pr: dict[str, Any], files: list[dict[str, Any]], guidance: str | None,
               contents: dict[str, str], synthesized: dict[str, str]) -> str:
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
        scrub(BUGBOT_SUMMARY.sub("", pr.get("body") or "").strip() or "(empty)"),
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
        patch = f.get("patch")
        origin = ""
        if patch is None:
            patch = synthesized.get(f["filename"], "")
            origin = " · diff synthesized from the file contents at both ends, as GitHub renders none"
        out += [f"### {name} ({f['status']}, +{f['additions']} -{f['deletions']}{origin})",
                clip_diff(scrub(patch))]
    out += ["</diff>", ""]
    snippets = []
    for f in files:
        if f["filename"] in contents:
            patch = f.get("patch") or synthesized.get(f["filename"], "")
            for lo, hi, body in context_snippets(contents[f["filename"]], patch):
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
    reason = ineligible_reason(pr, files, deny_patterns(extra_deny), gh.permission(pr["user"]["login"]))
    synthesized = {}
    if reason is None:
        # Guidance comes from the base branch so the PR under review cannot rewrite it.
        guidance = gh.file_at("AGENTS.md", pr["base"]["sha"])
        contents = {}
        for f in files:
            if f["status"] != "removed":
                text = gh.file_at(f["filename"], pr["head"]["sha"])
                if text is not None:
                    contents[f["filename"]] = text
        # A missing patch means binary or unfetchable content (ineligible, as before) or a diff
        # too large for GitHub to render, which is diffed from the merge base — the commit
        # GitHub measures the diff and the line counts from, so base-branch changes made after
        # the branch point do not leak into the synthesized diff inverted.
        base_sha = gh.merge_base(pr["base"]["sha"], pr["head"]["sha"])
        changed = pr["additions"] + pr["deletions"]
        for f in files:
            if "patch" not in f:
                head = "" if f["status"] == "removed" else contents.get(f["filename"])
                patch = synthesize_patch(gh, f, base_sha, head)
                if patch is None:
                    reason = f"`{f['filename']}` has no reviewable text diff"
                    break
                synthesized[f["filename"]] = patch
                # GitHub reports zero line counts for content it treats as binary, so the
                # synthesized diff's own count is what the size cap sees for those files.
                changed += count_changed_lines(patch) - (f["additions"] + f["deletions"])
        if reason is None and changed > MAX_CHANGED_LINES:
            reason = f"{changed} changed lines (limit {MAX_CHANGED_LINES})"
    if reason is None:
        (out / "input.md").write_text(build_input(pr, files, guidance, contents, synthesized))
    gate = {
        "sha": pr["head"]["sha"],
        "eligible": reason is None,
        "reason": reason,
        "changed_lines": pr["additions"] + pr["deletions"],
        "comment_id": existing["id"] if existing else None,
        "previous": previous_data(existing["body"]) if existing else None,
    }
    (out / "gate.json").write_text(json.dumps(gate, indent=2))
    write_output("eligible", "true" if reason is None else "false")
    write_output("commented", "true" if existing else "false")
    print(f"eligible={reason is None} reason={reason} existing_comment={bool(existing)}")
    return gate


def schema_error(value: Any) -> str | None:
    if not isinstance(value, dict):
        return "reply is not a JSON object"
    props = VERDICT_SCHEMA["properties"]
    extra = sorted(set(value) - set(props))
    if extra:
        return f"unexpected keys {extra}"
    for key in VERDICT_SCHEMA["required"]:
        if key not in value:
            return f"missing {key}"
    for key, spec in props.items():
        expected = {"string": str, "boolean": bool}[spec["type"]]
        if not isinstance(value[key], expected):
            return f"{key} must be a {spec['type']}"
        if "enum" in spec and value[key] not in spec["enum"]:
            return f"{key} must be one of {spec['enum']}"
    return None


def verdict_from_events(events: str) -> dict[str, Any]:
    """Build the result envelope `parse_verdict` reads from `pi --mode json` output.

    pi has no schema-constrained output, so the model replies with one JSON object and it is
    checked here against VERDICT_SCHEMA. Anything else is reported as a classifier error.
    """
    reply = None
    for line in events.split("\n"):
        if not line.strip():
            continue
        event = json.loads(line)
        message = event.get("message") or {}
        if event.get("type") == "message_end" and message.get("role") == "assistant":
            reply = message
    if reply is None:
        return {"is_error": True, "result": "pi produced no assistant reply"}
    if reply.get("stopReason") != "stop":
        detail = reply.get("errorMessage") or "no error message"
        return {"is_error": True, "result": f"pi stopped with {reply.get('stopReason')}: {detail}"}
    text = "".join(c["text"] for c in reply["content"] if c.get("type") == "text").strip()
    fenced = re.fullmatch(r"```(?:json)?\s*(.*?)\s*```", text, re.S)
    try:
        value = json.loads(fenced.group(1) if fenced else text)
    except json.JSONDecodeError:
        value = None
    error = schema_error(value) if value is not None else "reply is not JSON"
    if error:
        return {"is_error": True, "result": f"classifier reply does not match the verdict schema: {error}"}
    return {"is_error": False, "result": text, "structured_output": value}


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
    sub.add_parser("verdict").add_argument("--dir", type=Path, required=True)
    for name in ("gather", "comment"):
        p = sub.add_parser(name)
        p.add_argument("--repo", required=True)
        p.add_argument("--number", type=int, required=True)
        p.add_argument("--dir", type=Path, required=True)
    args = parser.parse_args()

    if args.cmd == "schema":
        print(json.dumps(VERDICT_SCHEMA))
        return 0
    if args.cmd == "verdict":
        result = verdict_from_events((args.dir / "pi-events.jsonl").read_text())
        (args.dir / "result.json").write_text(json.dumps(result, indent=2))
        return 0
    gh = GitHub(args.repo)
    if args.cmd == "gather":
        gather(gh, args.number, os.environ.get("DENY_PATHS", ""), args.dir)
        return 0
    return comment(gh, args.number, args.dir, os.environ.get("RUN_URL", ""))


if __name__ == "__main__":
    sys.exit(main())
