#!/usr/bin/env python3
"""Credential-boundary and merge-gate tests for .github/workflows/sandboxed-agent.yml."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/sandboxed-agent.yml").read_text())
JOB = WORKFLOW["jobs"]["agent"]
MERGE_GATE = ROOT / ".github/workflows/sandboxed-agent/merge-gate.sh"


def step(name: str) -> dict:
    for entry in JOB["steps"]:
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"missing step: {name}")


class CredentialBoundaryTest(unittest.TestCase):
    def test_app_key_reaches_only_the_minting_steps(self):
        users = {entry["name"] for entry in JOB["steps"] if "ADMIN_APP_PRIVATE_KEY" in yaml.safe_dump(entry)}
        self.assertEqual(users, {"Agent GitHub credentials", "Merge token"})

    def test_sandbox_steps_get_no_github_credential(self):
        for entry in JOB["steps"]:
            text = yaml.safe_dump(entry)
            if "sbx exec" in entry.get("run", "") or "sbx create" in entry.get("run", ""):
                self.assertNotRegex(text, r"secrets\.ADMIN|github\.token|outputs\.token", entry["name"])

    def test_state_is_outside_the_workspace_the_sandbox_reads(self):
        self.assertEqual(JOB["env"]["STATE"], "${{ github.workspace }}/../sandboxed-agent")
        run = step("Agent GitHub credentials")["run"]
        self.assertIn('> "$STATE/app-key.pem"', run)
        self.assertIn("umask 077", run)

    def test_agent_token_is_limited_to_the_caller_repository(self):
        run = step("Agent GitHub credentials")["run"]
        self.assertIn('--arg repository "${GITHUB_REPOSITORY#*/}"', run)
        self.assertIn("--argjson permissions \"$APP_PERMISSIONS\"", run)
        self.assertIn("sbx secret set github --command", run)

    def test_job_token_is_read_only(self):
        self.assertEqual(
            JOB["permissions"],
            {"actions": "read", "checks": "read", "contents": "read", "pull-requests": "read", "statuses": "read", "id-token": "write"},
        )

    def test_merge_token_only_for_a_ready_outcome(self):
        merge = step("Merge token")
        self.assertEqual(merge["if"], "inputs.merge && startsWith(steps.read-outcome.outputs.outcome, 'ready:')")
        self.assertNotIn("repositories", merge["with"])

    def test_teardown_always_runs_and_revokes(self):
        teardown = step("Tear down")
        self.assertEqual(teardown["if"], "always()")
        self.assertIn("installation/token", teardown["run"])
        self.assertIn("sbx rm --force", teardown["run"])


class MergeGateTest(unittest.TestCase):
    HEAD = "a" * 40

    def run_gate(self, *, state="OPEN", runs, statuses=None, after_merge="MERGED"):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "runs.json").write_text(json.dumps({"check_runs": runs}))
            (tmp / "status.json").write_text(json.dumps(statuses or {"total_count": 0, "state": "pending"}))
            (tmp / "state").write_text(state)
            gh = tmp / "gh"
            gh.write_text(f"""#!/bin/bash
echo "GH_TOKEN=$GH_TOKEN $*" >> {tmp}/calls
case "$*" in
  "pr view"*"--jq .state") cat {tmp}/state ;;
  "pr view"*"--jq .headRefOid") echo {self.HEAD} ;;
  api*check-runs*) cat {tmp}/runs.json ;;
  api*/status) cat {tmp}/status.json ;;
  "pr merge"*) echo {after_merge} > {tmp}/state ;;
esac
""")
            gh.chmod(0o755)
            (tmp / "sleep").write_text("#!/bin/bash\nexit 0\n")
            (tmp / "sleep").chmod(0o755)
            env = {
                **os.environ,
                "PATH": f"{tmp}:{os.environ['PATH']}",
                "GH_TOKEN": "read-token",
                "MERGE_TOKEN": "merge-token",
                "GITHUB_REPOSITORY": "kernel/example",
                "CHECKS_TIMEOUT_MINUTES": "0",
            }
            result = subprocess.run(["bash", str(MERGE_GATE), "7"], env=env, capture_output=True, text=True)
            calls = (tmp / "calls").read_text() if (tmp / "calls").exists() else ""
            return result, calls

    def run_(self, name, conclusion="success", status="completed", completed_at="2026-01-01T00:00:00Z"):
        return {"name": name, "status": status, "conclusion": conclusion, "completed_at": completed_at}

    def test_merges_when_bugbot_and_checks_pass(self):
        result, calls = self.run_gate(runs=[self.run_("Cursor Bugbot"), self.run_("test")])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"GH_TOKEN=merge-token pr merge 7 --repo kernel/example --squash --delete-branch --match-head-commit {self.HEAD}", calls)
        self.assertNotIn("GH_TOKEN=merge-token api", calls)

    def test_refuses_without_a_green_bugbot(self):
        for runs in (
            [self.run_("test")],
            [self.run_("Cursor Bugbot", conclusion="neutral"), self.run_("test")],
            [self.run_("Cursor Bugbot", conclusion="failure")],
        ):
            result, calls = self.run_gate(runs=runs)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("pr merge", calls)

    def test_refuses_with_a_failing_or_pending_check(self):
        for runs in (
            [self.run_("Cursor Bugbot"), self.run_("test", conclusion="failure")],
            [self.run_("Cursor Bugbot"), self.run_("test", status="in_progress", conclusion=None)],
        ):
            result, calls = self.run_gate(runs=runs)
            self.assertEqual(result.returncode, 1)
            self.assertNotIn("pr merge", calls)

    def test_refuses_with_failing_commit_statuses(self):
        result, calls = self.run_gate(runs=[self.run_("Cursor Bugbot")], statuses={"total_count": 1, "state": "failure"})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("pr merge", calls)

    def test_refuses_a_pull_request_the_agent_already_merged(self):
        result, calls = self.run_gate(state="MERGED", runs=[self.run_("Cursor Bugbot")])
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("pr merge", calls)


if __name__ == "__main__":
    unittest.main()
