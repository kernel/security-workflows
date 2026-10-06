import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/breakglass-merge.yml"

# Replace only the remote GitHub API; execute the workflow's real shell.
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
path = Path(os.environ["FAKE_STATE"])
state = json.loads(path.read_text())
args = sys.argv[2:]
method = args[args.index("-X") + 1] if "-X" in args else "GET"
endpoint = next(a for a in args if a.startswith("/repos/")).split("?", 1)[0]
data = {}
for i, arg in enumerate(args):
    if arg in ("-f", "-F"):
        key, value = args[i + 1].split("=", 1)
        data[key] = json.loads(value) if arg == "-F" and value in ("true", "false") else value
parts = endpoint.split("/")
number = int(parts[5]) if len(parts) > 5 else None
result = {}
error = None
if method == "GET" and len(parts) == 4:
    result = state["repo"]
elif method == "GET" and parts[4] == "stacks":
    order = state.get("stack_order", [int(n) for n in state["prs"]])
    result = {"pull_requests": [state["prs"][str(n)] for n in order]}
elif method == "GET" and "/merge-async/" in endpoint:
    state["polls"] = state.get("polls", 0) + 1
    status = "pending" if state["polls"] < state.get("complete_after", 1) else state.get("terminal_status", "merged")
    if status == "merged":
        state["prs"][str(number)]["state"] = "closed"
        state["merged"] = [number]
    result = {"status": status, "details": {"message": "merge conflict" if status == "failed" else status}}
elif method == "GET":
    key = str(number)
    state.setdefault("reads", {})[key] = state.get("reads", {}).get(key, 0) + 1
    if state.get("change_head") == number and state["reads"][key] >= 2:
        state["prs"][key]["head"]["sha"] = "changed"
    if state.get("change_base") == number and state["reads"][key] >= 2:
        state["prs"][key]["base"]["ref"] = "unexpected"
    if state.get("change_stack") and state["reads"][key] >= 2:
        state["stack_order"] = [4, 1, 2, 3]
        state["prs"]["4"] = {"number": 4, "state": "open"}
    result = state["prs"][key]
elif endpoint.endswith("/comments"):
    if state.get("fail_comment") == number:
        error = "comment unavailable"
        del state["fail_comment"]
    else:
        state.setdefault("comments", []).append({"number": number, **data})
elif endpoint.endswith("/merge-async"):
    state.setdefault("requests", []).append({"number": number, **data})
    if state.get("submit_error"):
        error = "HTTP 403 forbidden"
    elif not any(c["number"] == number for c in state.get("comments", [])):
        error = "missing audit comment before merge"
    else:
        result = {"status": "pending", "details": {"uuid": "request-id", "expected_head_sha": data["sha"]}}
elif endpoint.endswith("/merge"):
    error = "Merging stacked PRs via this endpoint is not supported. Use the asynchronous merge endpoint instead. (HTTP 403)"
else:
    raise RuntimeError((method, endpoint, data))
path.write_text(json.dumps(state))
if error:
    print(error, file=sys.stderr)
    sys.exit(1)
print(json.dumps(result))
'''


def pr(number, head, base, stacked=True):
    return {
        "number": number, "state": "open", "draft": False,
        "stack": {"number": 42, "position": number, "base": {"ref": "main"}} if stacked else None,
        "author_association": "MEMBER",
        "head": {"ref": head, "sha": f"sha-{number}", "repo": {"full_name": "kernel/example"}},
        "base": {"ref": base, "repo": {"full_name": "kernel/example"}},
    }


class BreakglassTests(unittest.TestCase):
    def run_workflow(self, *, body="/breakglass emergency fix needed", association="MEMBER", number=1, **changes):
        state = {
            "repo": {"default_branch": "main", "allow_merge_commit": True, "allow_squash_merge": True},
            "prs": {"1": pr(1, "first", "main"), "2": pr(2, "second", "first"), "3": pr(3, "third", "second")},
            **changes,
        }
        workflow = yaml.safe_load(WORKFLOW.read_text())
        steps = workflow["jobs"]["merge"]["steps"]
        merge = next(s["run"] for s in steps if s["name"] == "Merge without approval")
        refusal = next(s["run"] for s in steps if s["name"] == "Explain the refusal")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "gh").write_text(FAKE_GH)
            (root / "gh").chmod(0o755)
            (root / "sleep").write_text("#!/bin/sh\nexit 0\n")
            (root / "sleep").chmod(0o755)
            (root / "state.json").write_text(json.dumps(state))
            env = {
                **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                "FAKE_STATE": str(root / "state.json"), "ACTOR": "operator",
                "REPO": "kernel/example", "NUMBER": str(number), "BODY": body,
                "REQUESTER_ASSOCIATION": association, "GITHUB_STEP_SUMMARY": str(root / "summary"),
                "RUN_URL": "https://example.com/run",
            }
            result = subprocess.run(["bash", "-c", merge], env=env, cwd=root, capture_output=True, text=True)
            if result.returncode:
                subprocess.run(["bash", "-c", refusal], env=env, cwd=root, check=True, capture_output=True)
            return result, json.loads((root / "state.json").read_text())

    def test_merges_only_bottom_pr_using_async_endpoint(self):
        result, state = self.run_workflow(complete_after=2)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["merged"], [1])
        self.assertEqual(state["requests"], [{"number": 1, "merge_method": "squash", "sha": "sha-1", "merge_action": "direct_merge", "bypass_rules": True}])
        self.assertEqual(state["prs"]["2"]["state"], "open")
        self.assertEqual(state["prs"]["3"]["state"], "open")
        self.assertEqual([c["number"] for c in state["comments"]], [1])
        self.assertIn("emergency fix needed", state["comments"][0]["body"])

    def test_refuses_higher_pr_with_open_pr_below_it(self):
        result, state = self.run_workflow(number=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("requests", state)
        self.assertNotIn("merged", state)
        self.assertIn("below this one first: #1", state["comments"][-1]["body"])

    def test_allows_next_pr_after_lower_pr_has_merged(self):
        prs = {"1": pr(1, "first", "main"), "2": pr(2, "second", "main"), "3": pr(3, "third", "second")}
        prs["1"].update(state="closed", merged_at="2026-01-01T00:00:00Z")
        result, state = self.run_workflow(number=2, prs=prs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["merged"], [2])
        self.assertEqual(state["prs"]["3"]["state"], "open")

    def test_unstacked_pr_uses_same_async_merge_path(self):
        result, state = self.run_workflow(prs={"1": pr(1, "first", "main", stacked=False)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["merged"], [1])
        self.assertEqual(state["requests"][0]["merge_method"], "squash")

    def test_rejects_unauthorized_requests_without_merge_submission(self):
        for case in ("requester", "fork", "author", "short_reason", "audit_failure"):
            with self.subTest(case=case):
                changes = {}
                prs = {"1": pr(1, "first", "main")}
                if case == "requester":
                    changes["association"] = "CONTRIBUTOR"
                elif case == "fork":
                    prs["1"]["head"]["repo"]["full_name"] = "external/example"
                elif case == "author":
                    prs["1"]["author_association"] = "CONTRIBUTOR"
                elif case == "short_reason":
                    changes["body"] = "/breakglass short"
                elif case == "audit_failure":
                    changes["fail_comment"] = 1
                result, state = self.run_workflow(prs=prs, **changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("requests", state)
                if case == "requester":
                    self.assertNotIn("comments", state)

    def test_refuses_moved_head_base_or_new_downstack_pr(self):
        for change in ("change_head", "change_base", "change_stack"):
            with self.subTest(change=change):
                result, state = self.run_workflow(**{change: 1})
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("requests", state)
                self.assertNotIn("merged", state)

    def test_reports_terminal_failure_and_does_not_claim_success(self):
        result, state = self.run_workflow(terminal_status="failed")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("merged", state)
        self.assertIn("Could not merge: merge conflict", state["comments"][-1]["body"])

    def test_timeout_or_queue_reports_unconfirmed_merge(self):
        for changes in ({"complete_after": 100}, {"terminal_status": "enqueued"}, {"submit_error": True}):
            with self.subTest(changes=changes):
                result, state = self.run_workflow(**changes)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("merged", state)
                body = state["comments"][-1]["body"]
                self.assertIn("merge not confirmed", body)
                self.assertNotIn("Nothing was merged", body)

    def test_ignores_other_commands_with_breakglass_prefix(self):
        result, state = self.run_workflow(body="/breakglass-stack emergency fix needed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("requests", state)
        self.assertNotIn("comments", state)


if __name__ == "__main__":
    unittest.main()
