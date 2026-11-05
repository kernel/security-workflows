#!/usr/bin/env python3
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/container-remediation.yml"
DISALLOWED_PATHS = ROOT / ".github/workflows/container-scan/disallowed-paths.sh"
TOKEN_REF = re.compile(r"GH_TOKEN|GITHUB_TOKEN|steps\.[\w-]+\.outputs\.token|secrets\.ADMIN_APP")


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def disallowed(paths):
    out = subprocess.run(
        ["bash", str(DISALLOWED_PATHS)], input="".join(f"{p}\0" for p in paths),
        check=True, capture_output=True, text=True,
    ).stdout
    return [p for p in out.split("\0") if p]


class ContainerRemediationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.safe_load(WORKFLOW.read_text())
        cls.jobs = cls.workflow["jobs"]

    def steps(self, job):
        return self.jobs[job]["steps"]

    def step(self, job, name):
        return next(s for s in self.steps(job) if s.get("name") == name)

    def index(self, job, name):
        return self.steps(job).index(self.step(job, name))

    def test_actions_are_pinned_and_checkouts_do_not_persist_credentials(self):
        for job in self.jobs.values():
            for step in job["steps"]:
                if "uses" not in step:
                    continue
                self.assertRegex(step["uses"], r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
                if step["uses"].startswith("actions/checkout@"):
                    self.assertIs(step["with"]["persist-credentials"], False)
                    self.assertNotIn("token", step["with"])

    def test_agent_jobs_have_read_only_credentials(self):
        for job, agent in (("triage", "Triage findings"), ("fix", "Apply fixes")):
            self.assertEqual(self.jobs[job]["permissions"], {"contents": "read"})
            step = self.step(job, agent)
            self.assertIn("pi --print --no-session --approve", step["run"])
            self.assertIn('--model "$PI_PREFERRED_MODEL"', step["run"])
            self.assertNotRegex(yaml.safe_dump(step), TOKEN_REF)
            self.assertEqual(step["env"]["PI_PREFERRED_MODEL"], "${{ vars.PI_PREFERRED_MODEL }}")
        for job in ("triage", "fix"):
            for step in self.steps(job):
                self.assertNotIn("claude", yaml.safe_dump(step))
                self.assertNotRegex(yaml.safe_dump(step.get("with", {})), r"permission-[\w-]+: write")

    def test_module_token_is_read_only_and_revoked_before_the_agent(self):
        mint = self.step("fix", "Generate Go module read token")
        self.assertEqual(mint["with"]["permission-contents"], "read")
        self.assertEqual(
            {k for k in mint["with"] if k.startswith("permission-")}, {"permission-contents"})
        download = self.step("fix", "Download Go modules")
        self.assertEqual(download["env"]["GH_TOKEN"], "${{ steps.module-token.outputs.token }}")
        self.assertRegex(download["run"], r"gh api --method DELETE /installation/token\n\s*fi\n$")
        self.assertNotIn("git config", download["run"])
        self.assertLess(self.index("fix", "Download Go modules"), self.index("fix", "Apply fixes"))
        self.assertIs(self.step("fix", "Setup Go")["with"]["cache"], False)
        for step in self.steps("fix")[self.index("fix", "Download Go modules") + 1:]:
            self.assertNotRegex(yaml.safe_dump(step), TOKEN_REF)

    def test_fix_snapshots_and_validates_after_the_agent(self):
        order = ["Apply fixes", "Snapshot publishable changes", "Verify changes", "Upload validated changes"]
        self.assertEqual([self.index("fix", n) for n in order], sorted(self.index("fix", n) for n in order))
        snapshot = self.step("fix", "Snapshot publishable changes")["run"]
        self.assertIn('git reset -q --soft "$AGENT_BASE"\ngit add -A', snapshot)
        self.assertIn("git reset -q --hard\ngit clean -fdq", snapshot)
        self.assertIn("go build ./...", self.step("fix", "Verify changes")["run"])

    def test_publish_never_runs_the_agent_or_repository_code(self):
        publish = self.jobs["publish"]
        self.assertEqual(publish["needs"], "fix")
        self.assertEqual(publish["permissions"], {"contents": "read"})
        runs = "".join(s.get("run", "") for s in publish["steps"])
        self.assertNotRegex(runs, r"(?m)^\s*(go|pi|npm|npx|node|make|bash -c)\b")
        dump = yaml.safe_dump(publish)
        self.assertNotRegex(dump, r"ANTHROPIC|OPENAI|continue-on-error|always\(\)")
        mint = self.step("publish", "Generate app token")
        self.assertEqual(
            {k: v for k, v in mint["with"].items() if k.startswith("permission-")},
            {"permission-contents": "write", "permission-pull-requests": "write"})
        self.assertLess(self.index("publish", "Apply validated changes"), self.index("publish", "Generate app token"))
        for step in self.steps("publish")[:self.index("publish", "Generate app token")]:
            self.assertNotRegex(yaml.safe_dump(step), TOKEN_REF)
        push = self.step("publish", "Create or update PR")["run"]
        self.assertIn('git push --force-with-lease="$BRANCH:$UPDATE_SHA" origin "$BRANCH"', push)

    def test_allowlist(self):
        self.assertEqual(
            disallowed([
                "go.mod", "go.sum", "packages/api/go.mod", "packages/api/go.sum",
                "Dockerfile", "packages/api/Dockerfile", "Dockerfile.dev", "packages/x/ecs.Dockerfile",
                "packages/api/main.go", "trivy-results.json", ".github/workflows/ci.yml",
                "packages/api/lib/dockerfiles/templates.go", "go.mod.bak", "scripts/Dockerfile.sh/run",
            ]),
            ["packages/api/main.go", "trivy-results.json", ".github/workflows/ci.yml",
             "packages/api/lib/dockerfiles/templates.go", "go.mod.bak", "scripts/Dockerfile.sh/run"])


class ShellStepTests(unittest.TestCase):
    """Runs the workflow's real snapshot and publish shell against local repos."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.temp = self.root / "runner-temp"
        (self.temp / "container-remediation").mkdir(parents=True)
        (self.temp / "disallowed-paths.sh").write_text(DISALLOWED_PATHS.read_text())
        self.repo = self.root / "repo"
        self.repo.mkdir()
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "config", "user.email", "test@example.com")
        git(self.repo, "config", "user.name", "Test")
        (self.repo / "api").mkdir()
        (self.repo / "api/go.mod").write_text("module example.com/api\n\ngo 1.22\n\nrequire golang.org/x/net v0.1.0\n")
        (self.repo / "api/main.go").write_text("package main\n\nfunc main() {}\n")
        (self.repo / "Dockerfile").write_text("FROM alpine:3.20.0\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        self.base = git(self.repo, "rev-parse", "HEAD").strip()
        self.jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]

    def tearDown(self):
        self.tmp.cleanup()

    def run_step(self, job, name, **env):
        script = next(s["run"] for s in self.jobs[job]["steps"] if s.get("name") == name)
        output = self.root / "output"
        output.write_text("")
        result = subprocess.run(
            ["bash", "-e", "-c", script], cwd=self.repo, capture_output=True, text=True,
            env={**os.environ, "RUNNER_TEMP": str(self.temp), "GITHUB_OUTPUT": str(output), **env},
        )
        return result, output.read_text()

    def bump_go_mod(self):
        (self.repo / "api/go.mod").write_text("module example.com/api\n\ngo 1.22\n\nrequire golang.org/x/net v0.2.0\n")

    def test_snapshot_keeps_only_allowlisted_changes(self):
        self.bump_go_mod()
        (self.repo / "Dockerfile").write_text("FROM alpine:3.20.1\n")
        (self.repo / "api/main.go").write_text("package main\n\nfunc main() { panic(1) }\n")
        (self.repo / "evil.sh").write_text("curl example.com\n")
        git(self.repo, "add", "evil.sh")
        git(self.repo, "commit", "-q", "-m", "agent commit")
        result, output = self.run_step("fix", "Snapshot publishable changes", AGENT_BASE=self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("changed=true", output)
        patch = (self.temp / "changes.patch").read_text()
        self.assertIn("api/go.mod", patch)
        self.assertIn("Dockerfile", patch)
        self.assertNotIn("main.go", patch)
        self.assertNotIn("evil.sh", patch)
        self.assertEqual(git(self.repo, "rev-parse", "HEAD").strip(), self.base)
        self.assertFalse((self.repo / "evil.sh").exists())
        self.assertEqual(sorted(git(self.repo, "diff", "--cached", "--name-only").split()), ["Dockerfile", "api/go.mod"])

    def test_snapshot_without_publishable_changes(self):
        (self.repo / "api/main.go").write_text("package main\n")
        result, output = self.run_step("fix", "Snapshot publishable changes", AGENT_BASE=self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("changed=true", output)

    def publish_patch(self, mutate):
        mutate()
        git(self.repo, "add", "-A")
        patch = git(self.repo, "diff", "--cached", "--binary", "--no-renames")
        git(self.repo, "reset", "-q", "--hard")
        git(self.repo, "clean", "-fdq")
        (self.temp / "container-remediation/changes.patch").write_text(patch)
        return self.run_step("publish", "Apply validated changes", MAIN_SHA=self.base, BRANCH="security/container-remediation")

    def test_publish_commits_allowlisted_patch(self):
        result, _ = self.publish_patch(self.bump_go_mod)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(git(self.repo, "branch", "--show-current").strip(), "security/container-remediation")
        self.assertEqual(git(self.repo, "show", "--name-only", "--format=%an", "HEAD").split(), ["kernel-internal[bot]", "api/go.mod"])

    def test_publish_rejects_disallowed_paths(self):
        result, _ = self.publish_patch(lambda: (self.repo / "api/main.go").write_text("package main\n"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside the container remediation allowlist", result.stdout)

    def test_publish_rejects_symlinks(self):
        result, _ = self.publish_patch(lambda: (self.repo / "api/go.sum").symlink_to("/etc/passwd"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("only contain regular files", result.stdout)

    def test_publish_rejects_replace_directives(self):
        for replace in ("replace golang.org/x/net => ../net\n",
                        "replace (\n\tgolang.org/x/net => example.com/fork v0.2.0\n)\n"):
            with self.subTest(replace=replace):
                go_mod = self.repo / "api/go.mod"
                result, _ = self.publish_patch(lambda: go_mod.write_text(go_mod.read_text() + replace))
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("may not add replace directives", result.stdout)
                git(self.repo, "switch", "-q", "--detach", self.base)


if __name__ == "__main__":
    unittest.main()
