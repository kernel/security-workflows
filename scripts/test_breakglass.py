import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/breakglass-merge.yml"

# Replace only the remote GitHub API; execute the workflow's real shell and Python.
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
        data[key] = value
if "--input" in args:
    data = json.load(sys.stdin)
parts = endpoint.split("/")
number = int(parts[5]) if len(parts) > 5 else None
result = {}
error = None
if method == "GET" and len(parts) == 4:
    result = state["repo"]
elif method == "GET" and endpoint.endswith("/pulls"):
    prs = [p for p in state["prs"].values() if p["state"] == "open"]
    if "base" in data:
        prs = [p for p in prs if p["base"]["ref"] == data["base"]]
    result = [prs[:1], prs[1:]] if "--slurp" in args else prs
elif method == "GET":
    key = str(number)
    state.setdefault("reads", {})[key] = state.get("reads", {}).get(key, 0) + 1
    if state.get("change_head") == number and state["reads"][key] >= 2:
        state["prs"][key]["head"]["sha"] = "changed"
    if state.get("change_base") == number and state["reads"][key] >= 2:
        state["prs"][key]["base"]["ref"] = "unexpected"
    result = state["prs"][key]
elif endpoint.endswith("/comments"):
    if state.get("fail_comment") == number:
        error = "comment unavailable"
    else:
        state.setdefault("comments", []).append({"number": number, **data})
elif method == "PATCH":
    state["prs"][str(number)]["base"]["ref"] = data["base"]
    state.setdefault("retargeted", []).append(number)
    result = state["prs"][str(number)]
elif endpoint.endswith("/merge"):
    pr = state["prs"][str(number)]
    if not any(c["number"] == number for c in state.get("comments", [])):
        error = "missing audit comment before merge"
    elif state.get("fail_merge") == number:
        error = "merge conflict"
    elif state.get("merge_false") == number:
        result = {"merged": False, "message": "not mergeable"}
    elif data["sha"] != pr["head"]["sha"]:
        error = "head changed"
    else:
        pr["state"] = "closed"
        state.setdefault("merged", []).append({"number": number, "base": pr["base"]["ref"], **data})
        if state.get("auto_retarget"):
            for child in state["prs"].values():
                if child["base"]["ref"] == pr["head"]["ref"]:
                    child["base"]["ref"] = pr["base"]["ref"]
        result = {"merged": True}
else:
    raise RuntimeError((method, endpoint, data))
path.write_text(json.dumps(state))
if error:
    print(error, file=sys.stderr)
    sys.exit(1)
print(json.dumps(result))
'''


def pr(number, head, base):
    return {
        "number": number, "state": "open", "draft": False,
        "author_association": "MEMBER",
        "head": {"ref": head, "sha": f"sha-{number}", "repo": {"full_name": "kernel/example"}},
        "base": {"ref": base, "repo": {"full_name": "kernel/example"}},
    }


class BreakglassTests(unittest.TestCase):
    def run_workflow(self, *, body="/breakglass --stack emergency fix needed", association="MEMBER", **changes):
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
            (root / "state.json").write_text(json.dumps(state))
            env = {
                **os.environ, "PATH": f"{root}:{os.environ['PATH']}",
                "FAKE_STATE": str(root / "state.json"), "ACTOR": "operator",
                "REPO": "kernel/example", "NUMBER": "1", "BODY": body,
                "REQUESTER_ASSOCIATION": association, "GITHUB_STEP_SUMMARY": str(root / "summary"),
                "RUN_URL": "https://example.com/run",
            }
            result = subprocess.run(["bash", "-c", merge], env=env, cwd=root, capture_output=True, text=True)
            if result.returncode:
                subprocess.run(["bash", "-c", refusal], env=env, cwd=root, check=True, capture_output=True)
            return result, json.loads((root / "state.json").read_text())

    def test_merges_stack_bottom_up_into_main_with_audit_per_pr(self):
        result, state = self.run_workflow()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(m["number"], m["base"], m["merge_method"], m["sha"]) for m in state["merged"]],
                         [(1, "main", "merge", "sha-1"), (2, "main", "merge", "sha-2"), (3, "main", "merge", "sha-3")])
        self.assertEqual(state["retargeted"], [2, 3])
        self.assertEqual([c["number"] for c in state["comments"]], [1, 2, 3])
        for comment in state["comments"]:
            self.assertIn("emergency fix needed", comment["body"])
            self.assertIn("@operator", comment["body"])

    def test_single_pr_command_preserves_squash_preference(self):
        result, state = self.run_workflow(body="/breakglass emergency fix needed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(state["merged"], [{"number": 1, "base": "main", "merge_method": "squash", "sha": "sha-1"}])
        self.assertNotIn("retargeted", state)

    def test_refuses_unsafe_or_ambiguous_stack_before_any_merge(self):
        for case in ("fork", "author", "draft", "branching", "cycle", "nondefault", "no_merge_commits"):
            with self.subTest(case=case):
                prs = {"1": pr(1, "first", "main"), "2": pr(2, "second", "first")}
                repo = {"default_branch": "main", "allow_merge_commit": True}
                if case == "fork":
                    prs["2"]["head"]["repo"]["full_name"] = "external/example"
                elif case == "author":
                    prs["2"]["author_association"] = "CONTRIBUTOR"
                elif case == "draft":
                    prs["2"]["draft"] = True
                elif case == "branching":
                    prs["3"] = pr(3, "other", "first")
                elif case == "cycle":
                    prs["2"]["head"]["ref"] = "main"
                elif case == "nondefault":
                    prs["1"]["base"]["ref"] = "other"
                elif case == "no_merge_commits":
                    repo["allow_merge_commit"] = False
                result, state = self.run_workflow(prs=prs, repo=repo)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("merged", state)
                self.assertNotIn("retargeted", state)
                self.assertIn("Breakglass did not merge", state["comments"][-1]["body"])

    def test_denies_nonmember_silently(self):
        result, state = self.run_workflow(association="CONTRIBUTOR")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("merged", state)
        self.assertNotIn("comments", state)

    def test_stops_on_moved_head_after_retargeting(self):
        result, state = self.run_workflow(change_head=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([m["number"] for m in state["merged"]], [1])
        self.assertEqual(state["retargeted"], [2])
        self.assertIn("#1", state["comments"][-1]["body"])
        self.assertIn("changed", state["comments"][-1]["body"])

    def test_handles_github_automatically_retargeting_dependents(self):
        result, state = self.run_workflow(auto_retarget=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([(m["number"], m["base"]) for m in state["merged"]], [(1, "main"), (2, "main"), (3, "main")])
        self.assertNotIn("retargeted", state)

    def test_stack_option_does_not_count_toward_reason_length(self):
        result, state = self.run_workflow(body="/breakglass --stack short")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("merged", state)
        self.assertIn("at least 10 characters", state["comments"][-1]["body"])

    def test_stops_if_dependent_base_moves_after_retargeting(self):
        result, state = self.run_workflow(change_base=2)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual([m["number"] for m in state["merged"]], [1])
        self.assertIn("changed", state["comments"][-1]["body"])

    def test_ignores_other_commands_with_breakglass_prefix(self):
        result, state = self.run_workflow(body="/breakglass-stack emergency fix needed")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("merged", state)
        self.assertNotIn("comments", state)

    def test_stops_on_merge_or_audit_failure_and_reports_partial_progress(self):
        for failure in ("fail_merge", "fail_comment", "merge_false"):
            with self.subTest(failure=failure):
                result, state = self.run_workflow(**{failure: 2})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual([m["number"] for m in state["merged"]], [1])
                self.assertIn("#1", state["comments"][-1]["body"])
                self.assertIn("stopped", state["comments"][-1]["body"].lower())


if __name__ == "__main__":
    unittest.main()
