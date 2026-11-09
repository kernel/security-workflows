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
WORKFLOW_PATH = ROOT / ".github/workflows/vuln-remediation.yml"
TOKEN_REF = re.compile(r"GH_TOKEN|GITHUB_TOKEN|steps\.[\w-]+\.outputs\.token|github\.token")
MODEL_KEYS = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY"}


def load_jobs(text: str | None = None) -> dict:
    return yaml.safe_load(text if text is not None else WORKFLOW_PATH.read_text())["jobs"]


JOBS = load_jobs()


def step(job: str, name: str) -> dict:
    for entry in JOBS[job]["steps"]:
        if entry.get("name") == name:
            return entry
    raise AssertionError(f"missing {job} step: {name}")


def index(job: str, name: str) -> int:
    return JOBS[job]["steps"].index(step(job, name))


def secrets_of(job: dict) -> set[str]:
    return set(re.findall(r"secrets\.(\w+)", yaml.safe_dump(job)))


def agent_jobs(jobs: dict) -> list[str]:
    return [name for name, job in jobs.items() if re.search(r"(?m)^\s*pi\b", "\n".join(s.get("run", "") for s in job["steps"]))]


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def init_repo(path: Path) -> str:
    path.mkdir()
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "test@example.com")
    git(path, "config", "user.name", "Test")
    (path / "package.json").write_text('{"dependencies": {"left-pad": "1.0.0"}}\n')
    (path / "package-lock.json").write_text('{"lockfileVersion": 3, "left-pad": "1.0.0"}\n')
    (path / "index.js").write_text("console.log(1)\n")
    git(path, "add", "-A")
    git(path, "commit", "-q", "-m", "base")
    return git(path, "rev-parse", "HEAD").strip()


def run_step(entry: dict, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess:
    script = entry["run"].replace("${{ inputs.security-workflows-ref }}", "main")
    return subprocess.run(["bash", "-e", "-c", script], cwd=cwd, env={**os.environ, **env}, capture_output=True, text=True)


class WorkflowCredentialBoundary(unittest.TestCase):
    def test_actions_are_pinned_and_checkouts_do_not_persist_credentials(self):
        for job_name, job in JOBS.items():
            for entry in job["steps"]:
                uses = entry.get("uses")
                if not uses:
                    continue
                self.assertRegex(uses, r"^[\w/-]+@[0-9a-f]{40}$", f"{job_name}: {uses}")
                if job_name in ("fix", "agent", "verify", "pr") and uses.startswith("actions/checkout@"):
                    self.assertIs(entry["with"]["persist-credentials"], False)
                    self.assertNotIn("token", entry["with"])

    def test_default_token_is_read_only(self):
        self.assertEqual(yaml.safe_load(WORKFLOW_PATH.read_text())["permissions"], {"contents": "read"})
        for job in JOBS.values():
            self.assertNotIn("permissions", job)

    def test_agent_job_references_only_model_keys(self):
        self.assertEqual(agent_jobs(JOBS), ["agent"])
        agent = JOBS["agent"]
        self.assertEqual(secrets_of(agent), MODEL_KEYS)
        self.assertNotRegex(yaml.safe_dump(agent), TOKEN_REF)
        self.assertNotIn("create-github-app-token", yaml.safe_dump(agent))
        self.assertEqual(step("agent", "Run fallback agent")["env"]["PI_PREFERRED_MODEL"], "${{ vars.PI_PREFERRED_MODEL }}")

    def test_secret_check_fails_when_a_key_is_added_to_the_agent_job(self):
        text = WORKFLOW_PATH.read_text()
        anchor = "          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
        self.assertEqual(text.count(anchor), 1)
        for leaked in ("SOCKET_API_TOKEN", "ADMIN_APP_PRIVATE_KEY"):
            jobs = load_jobs(text.replace(anchor, anchor + f"          LEAK: ${{{{ secrets.{leaked} }}}}\n"))
            self.assertNotEqual(secrets_of(jobs["agent"]), MODEL_KEYS)

    def test_remediation_jobs_have_timeouts(self):
        for name in ("fix", "agent", "verify", "pr"):
            self.assertIsInstance(JOBS[name].get("timeout-minutes"), int, name)
        self.assertGreater(JOBS["agent"]["timeout-minutes"], step("agent", "Run fallback agent")["timeout-minutes"])

    def test_agent_job_does_not_save_caches(self):
        self.assertIs(step("agent", "Setup Go")["with"]["cache"], False)
        self.assertIs(step("agent", "Setup Bun")["with"]["no-cache"], True)

    def test_agent_gets_the_prompt_and_private_modules_as_data(self):
        agent = step("agent", "Run fallback agent")
        self.assertIn("security-workflows-ref", agent["env"]["PROMPT_URL"])
        self.assertIn("pi --print --no-session --approve", agent["run"])
        self.assertIn('@"$RUNNER_TEMP/fix-prompt.md"', agent["run"])
        self.assertNotIn("CURSOR", WORKFLOW_PATH.read_text())
        self.assertEqual(step("agent", "Download private Go modules")["with"]["name"], "go-private-modules")
        self.assertIn("cache/download/github.com/kernel", step("fix", "Download private Go modules")["run"])
        self.assertIn("cache/download/github.com/kernel", step("agent", "Restore private Go modules")["run"])

    def test_credentialed_jobs_never_run_the_agent(self):
        self.assertEqual(secrets_of(JOBS["fix"]), {"ADMIN_APP_ID", "ADMIN_APP_PRIVATE_KEY", "SOCKET_API_TOKEN"})
        self.assertEqual(secrets_of(JOBS["verify"]), {"SOCKET_API_TOKEN"})
        self.assertEqual(secrets_of(JOBS["pr"]), {"ADMIN_APP_ID", "ADMIN_APP_PRIVATE_KEY"})
        read_token = step("fix", "Generate private module read token")["with"]
        self.assertEqual({k: v for k, v in read_token.items() if k.startswith("permission-")}, {"permission-contents": "read"})
        self.assertNotIn("owner", read_token)
        self.assertNotIn("repositories", read_token)
        self.assertEqual(JOBS["agent"]["needs"], "fix")
        self.assertEqual(JOBS["verify"]["needs"], ["fix", "agent"])
        for name in ("fix", "verify", "pr"):
            self.assertNotIn("pi-coding-agent", yaml.safe_dump(JOBS[name]))

    def test_publish_job_never_runs_repository_code(self):
        pr = JOBS["pr"]
        self.assertEqual(pr["needs"], ["triage", "fix", "verify"])
        self.assertIn("needs.verify.outputs.publish == 'true'", pr["if"])
        runs = "\n".join(entry.get("run", "") for entry in pr["steps"])
        self.assertNotRegex(runs, r"(?m)^\s*(go|bun|npm|npx|node|pi|make|socket|uv|pip)\b")
        for entry in pr["steps"]:
            self.assertNotIn("continue-on-error", entry)
        mint = index("pr", "Generate app token")
        self.assertLess(index("pr", "Apply validated changes"), mint)
        for entry in pr["steps"][:mint]:
            self.assertNotRegex(yaml.safe_dump(entry), TOKEN_REF)
        self.assertEqual(mint, len(pr["steps"]) - 2)


class SnapshotSteps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.base = init_repo(self.repo)
        self.work = self.root / "remediation"
        self.work.mkdir()
        self.output = self.root / "output"
        self.env = {"RUNNER_TEMP": str(self.root), "GITHUB_OUTPUT": str(self.output), "AGENT_BASE": self.base}

    def tearDown(self):
        self.tmp.cleanup()

    def run_snapshot(self, job: str) -> subprocess.CompletedProcess:
        name = "Snapshot Socket changes" if job == "fix" else "Snapshot agent changes"
        result = run_step(step(job, name), self.repo, self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def test_socket_changes_skip_the_agent(self):
        (self.repo / "package-lock.json").write_text('{"lockfileVersion": 3, "left-pad": "1.3.0"}\n')
        (self.repo / "socket-fix-apply.json").write_text("{}\n")
        self.run_snapshot("fix")
        self.assertEqual(self.output.read_text(), "has_changes=true\n")
        self.assertEqual((self.work / "changed-files.txt").read_text().split(), ["package-lock.json"])

    def test_no_socket_changes_run_the_agent(self):
        self.run_snapshot("fix")
        self.assertEqual(self.output.read_text(), "run_agent=true\n")

    def test_agent_snapshot_captures_committed_and_uncommitted_tracked_changes(self):
        (self.repo / "package.json").write_text('{"dependencies": {"left-pad": "1.3.0"}}\n')
        git(self.repo, "commit", "-qam", "agent commit")
        (self.repo / "package-lock.json").write_text('{"lockfileVersion": 3, "left-pad": "1.3.0"}\n')
        (self.repo / "bun.lock").write_text("untracked\n")
        (self.repo / "remediation-context.json").write_text("{}\n")
        self.run_snapshot("agent")
        self.assertEqual(self.output.read_text(), "has_changes=true\n")
        self.assertEqual((self.work / "changed-files.txt").read_text().split(), ["package-lock.json", "package.json"])
        patch = (self.work / "changes.patch").read_text()
        self.assertNotIn("bun.lock", patch)
        self.assertNotIn("remediation-context.json", patch)

    def test_agent_snapshot_without_changes(self):
        (self.repo / "fix-result.json").write_text("{}\n")
        self.run_snapshot("agent")
        self.assertFalse(self.output.exists())


class Gates(unittest.TestCase):
    """Runs the verify job's and the publish job's real gate scripts against a fresh checkout."""

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

    def stage(self, files: dict[str, str] | None = None, executable: bool = False, symlink: str | None = None) -> None:
        source = self.root / "source"
        git(self.root, "clone", "-q", str(self.repo), str(source))
        for path, content in (files or {}).items():
            (source / path).write_text(content)
            if executable:
                (source / path).chmod(0o755)
        if symlink:
            (source / symlink).unlink()
            (source / symlink).symlink_to("index.js")
        git(source, "add", "-A")
        (self.work / "changes.patch").write_text(git(source, "diff", "--cached", "--binary", "--no-renames"))
        (self.work / "changed-files.txt").write_text(git(source, "diff", "--cached", "--name-only", "--no-renames"))

    def run_gate(self, gate: str) -> subprocess.CompletedProcess:
        fresh = self.root / f"fresh-{gate}"
        git(self.root, "clone", "-q", str(self.repo), str(fresh))
        git(fresh, "checkout", "-q", "--detach")
        git(fresh, "branch", "-q", "-D", "main")
        entry = step("verify", "Validate remediation diff") if gate == "verify" else step("pr", "Apply validated changes")
        self.fresh = fresh
        return run_step(entry, fresh, self.env)

    def assert_both_reject(self, message: str) -> None:
        for gate in ("verify", "pr"):
            result = self.run_gate(gate)
            self.assertNotEqual(result.returncode, 0, gate)
            self.assertIn(message, result.stdout + result.stderr, gate)

    def test_publishes_validated_dependency_changes(self):
        self.stage({"package-lock.json": '{"lockfileVersion": 3, "left-pad": "1.3.0"}\n'})
        self.assertEqual(self.run_gate("verify").returncode, 0)
        result = self.run_gate("pr")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git(self.fresh, "branch", "--show-current").strip(), "security/vuln-remediation")
        self.assertEqual(git(self.fresh, "show", "--name-only", "--format=", "HEAD").split(), ["package-lock.json"])

    def test_rejects_files_outside_the_allowlist(self):
        self.stage({"index.js": "console.log(2)\n"})
        self.assert_both_reject("only dependency manifests and lockfiles may change")

    def test_rejects_executable_files(self):
        self.stage({"package-lock.json": "#!/bin/sh\n"}, executable=True)
        self.assertIn("100755", (self.work / "changes.patch").read_text())
        self.assert_both_reject("executable files are not allowed")

    def test_publish_mode_check_rejects_symlinks(self):
        self.stage(symlink="package-lock.json")
        self.assertEqual(self.run_gate("verify").returncode, 0)
        result = self.run_gate("pr")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("regular, non-executable files", result.stdout + result.stderr)

    def test_rejects_patch_that_differs_from_its_file_list(self):
        self.stage({"package-lock.json": '{"lockfileVersion": 3}\n'})
        (self.work / "changed-files.txt").write_text("package.json\n")
        self.assert_both_reject("does not match")


if __name__ == "__main__":
    unittest.main()
