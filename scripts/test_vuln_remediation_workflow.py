#!/usr/bin/env python3
"""Credential-boundary tests for .github/workflows/vuln-remediation.yml."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.safe_load((ROOT / ".github/workflows/vuln-remediation.yml").read_text())
JOBS = WORKFLOW["jobs"]
TOKEN_REF = re.compile(r"GH_TOKEN|GITHUB_TOKEN|steps\.[\w-]+\.outputs\.token|github\.token")


def step(job: str, name: str) -> dict:
    for entry in JOBS[job]["steps"]:
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"missing {job} step: {name}")


def index(job: str, name: str) -> int:
    return JOBS[job]["steps"].index(step(job, name))


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def init_repo(path: Path) -> None:
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test")
    (path / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}\n')
    (path / "package-lock.json").write_text('{"lockfileVersion": 3, "left-pad": "1.0.0"}\n')
    (path / "index.js").write_text("console.log(1)\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "base")


def run_step(entry: dict, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-e", "-c", entry["run"]], cwd=cwd, env={**os.environ, **env}, capture_output=True, text=True)


class WorkflowCredentialBoundary(unittest.TestCase):
    def test_actions_are_pinned_and_checkouts_do_not_persist_credentials(self):
        for job_name, job in JOBS.items():
            for entry in job["steps"]:
                uses = entry.get("uses")
                if not uses:
                    continue
                self.assertRegex(uses, r"^[\w/-]+@[0-9a-f]{40}$", f"{job_name}: {uses}")
                if job_name in ("fix", "pr") and uses.startswith("actions/checkout@"):
                    self.assertIs(entry["with"]["persist-credentials"], False)
                    self.assertNotIn("token", entry["with"])

    def test_default_token_is_read_only(self):
        self.assertEqual(WORKFLOW["permissions"], {"contents": "read"})

    def test_fix_job_only_has_a_revoked_read_token(self):
        tokens = [entry for entry in JOBS["fix"]["steps"] if "create-github-app-token" in entry.get("uses", "")]
        self.assertEqual(len(tokens), 1)
        read_token = tokens[0]["with"]
        self.assertEqual(read_token["permission-contents"], "read")
        self.assertFalse([key for key, value in read_token.items() if key.startswith("permission-") and value != "read"])
        self.assertNotIn("owner", read_token)
        self.assertNotIn("repositories", read_token)

        revoke = step("fix", "Revoke private module read token")
        self.assertEqual(revoke["run"].strip(), "gh api --method DELETE /installation/token")
        self.assertEqual(revoke["env"]["GH_TOKEN"], "${{ steps.read-token.outputs.token }}")
        self.assertIn("always()", revoke["if"])

        token_users = [
            entry["name"]
            for entry in JOBS["fix"]["steps"]
            if "steps.read-token.outputs.token" in yaml.safe_dump(entry)
        ]
        self.assertEqual(token_users, ["Install JS dependencies", "Apply Socket fixes", "Revoke private module read token"])
        for name in token_users:
            self.assertLess(index("fix", name), index("fix", "Install Pi"))
        for entry in JOBS["fix"]["steps"]:
            self.assertNotIn("git config --global", entry.get("run", ""))

    def test_agent_step_has_only_model_credentials(self):
        agent = step("fix", "Run fallback agent")
        env = agent["env"]
        secrets = sorted(key for key, value in env.items() if "secrets." in str(value))
        self.assertEqual(secrets, ["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
        self.assertEqual(env["PI_PREFERRED_MODEL"], "${{ vars.PI_PREFERRED_MODEL }}")
        self.assertNotRegex(yaml.safe_dump(agent), TOKEN_REF)
        self.assertIn("security-workflows-ref", env["PROMPT_URL"])
        self.assertIn("pi --print --no-session --approve", agent["run"])
        self.assertIn('@"$RUNNER_TEMP/fix-prompt.md"', agent["run"])
        self.assertNotIn("CURSOR", yaml.safe_dump(JOBS))
        for name in ("Snapshot remediation diff", "Validate remediation diff", "Confirm fixes"):
            self.assertLess(index("fix", "Run fallback agent"), index("fix", name))

    def test_publish_job_never_runs_repository_code(self):
        pr = JOBS["pr"]
        self.assertEqual(pr["needs"], ["triage", "fix"])
        self.assertEqual(pr["if"], "needs.fix.outputs.publish == 'true'")
        runs = "\n".join(entry.get("run", "") for entry in pr["steps"])
        self.assertNotRegex(runs, r"(?m)^\s*(go|bun|npm|npx|node|pi|make|socket|uv|pip)\b")
        self.assertNotIn("secrets.ANTHROPIC_API_KEY", yaml.safe_dump(pr))
        self.assertNotIn("secrets.SOCKET_API_TOKEN", yaml.safe_dump(pr))
        for entry in pr["steps"]:
            self.assertNotIn("continue-on-error", entry)
        mint = index("pr", "Generate app token")
        self.assertLess(index("pr", "Apply validated changes"), mint)
        for entry in pr["steps"][:mint]:
            self.assertNotRegex(yaml.safe_dump(entry), TOKEN_REF)
        self.assertEqual(mint, len(pr["steps"]) - 2)


class SnapshotStep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        init_repo(self.repo)
        self.base = git(self.repo, "rev-parse", "HEAD").strip()
        self.work = self.root / "remediation"
        self.work.mkdir()
        self.output = self.root / "output"
        self.env = {"RUNNER_TEMP": str(self.root), "GITHUB_OUTPUT": str(self.output), "AGENT_BASE": self.base}

    def tearDown(self):
        self.tmp.cleanup()

    def snapshot(self) -> subprocess.CompletedProcess:
        return run_step(step("fix", "Snapshot remediation diff"), self.repo, self.env)

    def test_captures_committed_and_uncommitted_tracked_changes_on_a_clean_tree(self):
        (self.repo / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}\n')
        git(self.repo, "commit", "-qam", "agent commit")
        (self.repo / "package-lock.json").write_text('{"lockfileVersion": 3, "left-pad": "1.3.0"}\n')
        (self.repo / "bun.lock").write_text("untracked\n")
        (self.repo / "remediation-context.json").write_text("{}\n")

        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("has_changes=true", self.output.read_text())
        self.assertEqual((self.work / "changed-files.txt").read_text().split(), ["package-lock.json", "package.json"])
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").strip(), self.base)
        self.assertFalse((self.repo / "bun.lock").exists())
        self.assertFalse((self.repo / "remediation-context.json").exists())
        self.assertEqual(git(self.repo, "diff", "--cached", "--name-only").split(), ["package-lock.json", "package.json"])

    def test_no_changes(self):
        (self.repo / "fix-result.json").write_text("{}\n")
        result = self.snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("has_changes=false", self.output.read_text())
        self.assertIn("No dependency changes", (self.work / "fix-result.json").read_text())


class PublishStep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        init_repo(self.repo)
        self.work = self.root / "remediation"
        self.work.mkdir()
        (self.work / "remediation-context.json").write_text('{"fixes": []}\n')
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        curl = bin_dir / "curl"
        curl.write_text(f'#!/bin/sh\nwhile [ "$1" != "-o" ]; do shift; done\ncp {ROOT / "scripts/vuln_remediation.py"} "$2"\n')
        curl.chmod(0o755)
        self.env = {"RUNNER_TEMP": str(self.root), "PATH": f"{bin_dir}:{os.environ['PATH']}"}

    def tearDown(self):
        self.tmp.cleanup()

    def stage(self, files: dict[str, str], executable: bool = False) -> None:
        source = self.root / "source"
        git(self.root, "clone", "-q", str(self.repo), str(source))
        for path, content in files.items():
            (source / path).write_text(content)
            if executable:
                (source / path).chmod(0o755)
        git(source, "add", "-A")
        (self.work / "changes.patch").write_text(git(source, "diff", "--cached", "--binary", "--no-renames"))
        (self.work / "changed-files.txt").write_text(git(source, "diff", "--cached", "--name-only", "--no-renames"))

    def publish(self) -> subprocess.CompletedProcess:
        script = step("pr", "Apply validated changes")["run"].replace("${{ inputs.security-workflows-ref }}", "main")
        return run_step({"run": script}, self.repo, self.env)

    def test_commits_validated_dependency_changes(self):
        self.stage({"package-lock.json": '{"lockfileVersion": 3, "left-pad": "1.3.0"}\n'})
        result = self.publish()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git(self.repo, "branch", "--show-current").strip(), "security/vuln-remediation")
        self.assertEqual(git(self.repo, "show", "--name-only", "--format=", "HEAD").split(), ["package-lock.json"])

    def test_rejects_source_changes(self):
        self.stage({"index.js": "console.log(2)\n"})
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only dependency manifests and lockfiles may change", result.stderr)

    def test_rejects_executable_files(self):
        self.stage({"package-lock.json": "#!/bin/sh\n"}, executable=True)
        self.assertIn("100755", (self.work / "changes.patch").read_text())
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("executable files are not allowed", result.stderr)

    def test_rejects_symlinks(self):
        self.stage({})
        source = self.root / "source"
        (source / "package-lock.json").unlink()
        (source / "package-lock.json").symlink_to("index.js")
        git(source, "add", "-A")
        (self.work / "changes.patch").write_text(git(source, "diff", "--cached", "--binary", "--no-renames"))
        (self.work / "changed-files.txt").write_text(git(source, "diff", "--cached", "--name-only", "--no-renames"))
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular, non-executable files", result.stdout + result.stderr)

    def test_rejects_patch_that_differs_from_validated_files(self):
        self.stage({"package-lock.json": '{"lockfileVersion": 3}\n'})
        (self.work / "changed-files.txt").write_text("package.json\n")
        result = self.publish()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
