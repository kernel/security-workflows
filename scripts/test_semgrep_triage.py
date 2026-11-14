import io
import json
import os
import re
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import semgrep_triage  # noqa: E402


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/semgrep.yml"

FINDINGS = [
    {"path": "api/handler.go", "start": {"line": 40}, "end": {"line": 42}},
    {"path": "api/exec.go", "start": {"line": 7}, "end": {"line": 7}},
]
COMMENTABLE = {"api/handler.go": [[30, 50]], "api/exec.go": [[1, 20]]}


def comment(path="api/handler.go", line=41, body="Injection risk."):
    return {"path": path, "line": line, "body": body}


def select(comments, omitted=0, existing=()):
    with redirect_stdout(io.StringIO()):
        return semgrep_triage.select_comments({"comments": comments, "omitted": omitted},
                                              FINDINGS, COMMENTABLE, list(existing))


class FakeGitHub:
    def __init__(self, files=(), comments=()):
        self._files = list(files)
        self._comments = list(comments)
        self.reviews = []

    def files(self, number):
        return self._files

    def review_comments(self, number):
        return self._comments

    def create_review(self, number, review):
        self.reviews.append((number, review))


class CommentableLinesTest(unittest.TestCase):
    def test_hunk_ranges_on_the_new_side(self):
        files = [
            {"filename": "a.go", "patch": "@@ -1,3 +1,4 @@\n x\n+y\n@@ -20 +21,2 @@ func\n+z"},
            {"filename": "deleted.go", "patch": "@@ -1,2 +0,0 @@\n-a\n-b"},
            {"filename": "binary.png"},
        ]
        self.assertEqual(semgrep_triage.commentable_lines(files), {"a.go": [[1, 4], [21, 22]]})


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class FindingsOnHeadTest(unittest.TestCase):
    def test_old_line(self):
        # Base added 3 lines at 2, replaced 2 lines at 20 with 1, and deleted 2 lines after 30.
        hunks = [(1, 0, 2, 3), (17, 2, 20, 1), (28, 2, 30, 0)]
        self.assertEqual(semgrep_triage.old_line(1, hunks), 1)
        self.assertIsNone(semgrep_triage.old_line(3, hunks))
        self.assertEqual(semgrep_triage.old_line(10, hunks), 7)
        self.assertIsNone(semgrep_triage.old_line(20, hunks))
        self.assertEqual(semgrep_triage.old_line(25, hunks), 23)
        self.assertEqual(semgrep_triage.old_line(30, hunks), 28)
        self.assertEqual(semgrep_triage.old_line(31, hunks), 31)


class GatherTest(unittest.TestCase):
    path = "app.py"

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name) / "repo"
        self.root.mkdir()
        git(self.root, "init", "-q", "-b", "main")
        git(self.root, "config", "user.email", "test@example.com")
        git(self.root, "config", "user.name", "Test")
        self.write(["def ping(host):", "    return host", "", "", "def other():", "    pass"])
        git(self.root, "add", "-A")
        git(self.root, "commit", "-qm", "base")
        git(self.root, "switch", "-qc", "pr")
        self.write(["def ping(host):", "    return run(host, shell=True)", "", "", "def other():", "    pass"])
        git(self.root, "commit", "-qam", "pr")
        self.head = git(self.root, "rev-parse", "HEAD")
        git(self.root, "switch", "-q", "main")
        self.write(["import subprocess", "", "", "def ping(host):", "    return host", "", "", "def other():",
                    "    subprocess.run(other, shell=True)"])
        git(self.root, "commit", "-qam", "main moved on")
        # GitHub's refs/pull/N/merge: base as first parent, PR head as second.
        git(self.root, "merge", "-q", "--no-ff", "-m", "merge", "pr")
        self.assertEqual(git(self.root, "rev-parse", "HEAD^2"), self.head)

    def write(self, lines):
        file = self.root / self.path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("\n".join(lines) + "\n")

    def finding(self, line):
        return {"path": self.path, "check_id": "shell",
                "start": {"line": line, "col": 5}, "end": {"line": line, "col": 9}}

    def test_moves_findings_onto_the_pr_head_and_writes_pr_context(self):
        merge_lines = (self.root / self.path).read_text().splitlines()
        self.assertEqual(merge_lines[4], "    return run(host, shell=True)")
        results = self.root / "semgrep-results.json"
        # Line 5 is the PR's change; line 9 only exists because the base branch added it.
        results.write_text(json.dumps({"results": [self.finding(5), self.finding(9)], "errors": []}))
        patch = "@@ -1,2 +1,2 @@\n def ping(host):\n-    return host\n+    return run(host, shell=True)"
        gh = FakeGitHub(files=[{"filename": self.path, "patch": patch}],
                        comments=[{"path": self.path, "line": 2, "original_line": 2,
                                   "user": {"login": "cursor[bot]"}, "body": "not passed on"}])
        out = self.root.parent / "triage"
        cwd = os.getcwd()
        os.chdir(self.root)
        try:
            semgrep_triage.gather(gh, 7, out, results, self.head)
        finally:
            os.chdir(cwd)
        moved = json.loads(results.read_text())
        self.assertEqual(moved["errors"], [])
        self.assertEqual([(f["start"]["line"], f["end"]["line"]) for f in moved["results"]], [(2, 2)])
        head_lines = git(self.root, "show", f"{self.head}:{self.path}").splitlines()
        self.assertEqual(head_lines[1], "    return run(host, shell=True)")
        self.assertEqual(json.loads((out / "commentable-lines.json").read_text()), {self.path: [[1, 2]]})
        self.assertEqual(json.loads((out / "existing-comments.json").read_text()),
                         [{"path": self.path, "line": 2, "original_line": 2, "author": "cursor[bot]"}])


class PathspecCharacterGatherTest(GatherTest):
    # Semgrep paths are file names, not pathspecs: a leading ":" is pathspec magic and "[id]" a glob.
    path = ":[id].py"


class ParseResultTest(unittest.TestCase):
    def test_plain_and_fenced_json(self):
        for text in ('{"comments": []}', '```json\n{"comments": [], "omitted": 2}\n```\n'):
            self.assertEqual(semgrep_triage.parse_result(text)["comments"], [])

    def test_rejects_prose_and_bad_shapes(self):
        for text in ("No actionable security findings.", '{"comments": {}}', "[]",
                     '{"comments": [], "omitted": -1}', '{"comments": [], "omitted": true}'):
            with self.assertRaises(ValueError, msg=text):
                semgrep_triage.parse_result(text)


class SelectCommentsTest(unittest.TestCase):
    def test_keeps_comments_on_findings_inside_the_diff(self):
        self.assertEqual(select([comment(), comment("api/exec.go", 7)]),
                         ([comment(), comment("api/exec.go", 7)], 0))

    def test_drops_comments_off_a_finding_or_outside_the_diff(self):
        kept, _ = select([comment(line=43), comment("api/other.go", 41), comment("api/exec.go", 7)])
        self.assertEqual(kept, [comment("api/exec.go", 7)])
        commentable = {"api/handler.go": [[30, 40]]}
        with redirect_stdout(io.StringIO()):
            kept, _ = semgrep_triage.select_comments({"comments": [comment()], "omitted": 0},
                                                     FINDINGS, commentable, [])
        self.assertEqual(kept, [])

    def test_skips_lines_that_already_have_a_comment_from_anyone(self):
        existing = [
            {"path": "api/handler.go", "line": 41, "original_line": 41, "author": "cursor[bot]"},
            {"path": "api/exec.go", "line": None, "original_line": 7, "author": "someone"},
        ]
        self.assertEqual(select([comment(), comment("api/exec.go", 7)], existing=existing), ([], 0))

    def test_posts_one_comment_per_line(self):
        self.assertEqual(select([comment(), comment(body="Again.")]), ([comment()], 0))

    def test_drops_malformed_comments(self):
        bad = [None, {"path": "api/handler.go", "line": "41", "body": "x"},
               {"path": "api/handler.go", "line": True, "body": "x"},
               {"path": "api/handler.go", "line": 41, "body": "  "}]
        self.assertEqual(select(bad), ([], 0))

    def test_caps_comments_and_counts_the_rest_as_omitted(self):
        comments = [comment(line=n) for n in (40, 41, 42)] + [comment("api/exec.go", 7)]
        findings = FINDINGS + [{"path": "api/handler.go", "start": {"line": 30}, "end": {"line": 35}}]
        with redirect_stdout(io.StringIO()):
            kept, omitted = semgrep_triage.select_comments(
                {"comments": comments + [comment(line=n) for n in (30, 31)], "omitted": 3},
                findings, COMMENTABLE, [])
        self.assertEqual(kept, (comments + [comment(line=30)])[:semgrep_triage.MAX_COMMENTS])
        self.assertEqual(omitted, 4)


class PostTest(unittest.TestCase):
    def run_post(self, output, existing=()):
        gh = FakeGitHub(comments=existing)
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            (workdir / "agent-output.txt").write_text(output)
            (workdir / "commentable-lines.json").write_text(json.dumps(COMMENTABLE))
            results = workdir / "semgrep-results.json"
            results.write_text(json.dumps({"results": FINDINGS}))
            out = io.StringIO()
            with redirect_stdout(out):
                code = semgrep_triage.post(gh, 7, "headsha", workdir, results)
        return code, gh.reviews, out.getvalue()

    def test_posts_one_comment_review_on_the_head_commit(self):
        code, reviews, _ = self.run_post(json.dumps({"comments": [comment()], "omitted": 0}))
        self.assertEqual(code, 0)
        self.assertEqual(reviews, [(7, {"commit_id": "headsha", "event": "COMMENT", "comments": [comment()]})])

    def test_notes_omitted_findings_in_the_review_body(self):
        _, reviews, _ = self.run_post(json.dumps({"comments": [comment()], "omitted": 2}))
        self.assertIn("2 more actionable Semgrep findings", reviews[0][1]["body"])

    def test_rechecks_existing_comments_before_posting(self):
        existing = [{"path": "api/handler.go", "line": 41, "original_line": 41, "user": {"login": "x"}}]
        code, reviews, out = self.run_post(json.dumps({"comments": [comment()]}), existing)
        self.assertEqual((code, reviews), (0, []))
        self.assertIn("No actionable security findings.", out)

    def test_fails_without_a_valid_result(self):
        code, reviews, out = self.run_post("I could not finish.")
        self.assertEqual((code, reviews), (1, []))
        self.assertIn("::error::", out)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        self.steps = workflow["jobs"]["triage"]["steps"]
        self.names = [s.get("name") for s in self.steps]

    def step(self, name):
        return self.steps[self.names.index(name)]

    def test_agent_step_has_no_github_token_or_write_tools(self):
        agent = self.step("Triage findings")
        text = json.dumps(agent)
        self.assertNotIn("GH_TOKEN", text)
        self.assertNotIn("GITHUB_TOKEN", text)
        self.assertNotIn("github.token", text)
        self.assertIn("--tools read,grep,find,ls ", agent["run"])
        self.assertIn("--no-approve", agent["run"])
        self.assertNotIn("--approve ", agent["run"])

    def test_checkout_does_not_persist_the_token(self):
        checkout = self.step("Checkout repository")
        self.assertIs(checkout["with"]["persist-credentials"], False)

    def test_findings_move_to_the_pr_head_that_comments_are_posted_on(self):
        job = yaml.safe_load(WORKFLOW.read_text())["jobs"]["triage"]
        self.assertEqual(job["env"]["HEAD_SHA"], "${{ github.event.pull_request.head.sha }}")
        self.assertEqual(self.step("Checkout repository")["with"]["fetch-depth"], 2)
        gather = self.step("Gather PR comments")["run"]
        self.assertIn('--head "$HEAD_SHA"', gather)
        self.assertLess(gather.index(" gather "), gather.index('git checkout -q --detach "$HEAD_SHA"'))
        self.assertIn('--head "$HEAD_SHA"', self.step("Post review")["run"])

    def test_only_runner_steps_get_the_token_and_model_keys_stay_in_the_agent_step(self):
        for step in self.steps:
            env = step.get("env", {})
            if "GH_TOKEN" in env:
                self.assertIn(step["name"], ("Gather PR comments", "Post review"))
            self.assertFalse(any("secrets." in str(v) for v in env.values()), step["name"])
        self.assertLess(self.names.index("Gather PR comments"), self.names.index("Triage findings"))
        self.assertLess(self.names.index("Triage findings"), self.names.index("Post review"))

    def test_model_credentials_exist_only_while_the_agent_runs(self):
        agent = self.names.index("Triage findings")
        self.assertEqual(self.names[agent - 1], "Model credentials")
        self.assertEqual(self.names[agent + 1], "Stop model credentials")
        action = "kernel/security-workflows/.github/actions/llm-credentials@main"
        self.assertEqual(self.step("Model credentials")["uses"], action)
        self.assertEqual(self.step("Stop model credentials")["with"], {"stop": True})
        jobs = yaml.safe_load(WORKFLOW.read_text())["jobs"]
        self.assertEqual(jobs["triage"]["permissions"], {"contents": "read", "pull-requests": "write", "id-token": "write"})
        for name in ("scan", "too-many-findings"):
            self.assertNotIn("id-token", jobs[name]["permissions"])


class MutableActionTagRuleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        steps = yaml.safe_load(WORKFLOW.read_text())["jobs"]["scan"]["steps"]
        cls.script = next(s for s in steps if s.get("name") == "Run Semgrep")["run"]
        rule_text = cls.script.split("<<'RULE'\n", 1)[1].split("\nRULE\n", 1)[0]
        (rule,) = yaml.safe_load(rule_text)["rules"]
        cls.allowed = [p["pattern-not-regex"] for p in rule["patterns"][2]["metavariable-pattern"]["patterns"]]

    def flagged(self, uses):
        return not any(re.search(regex, uses) for regex in self.allowed)

    def test_replaces_the_registry_rule(self):
        self.assertIn("--config p/github-actions", self.script)
        self.assertIn("--exclude-rule yaml.github-actions.security.github-actions-mutable-action-tag.github-actions-mutable-action-tag", self.script)
        self.assertIn('--config "$RUNNER_TEMP/github-actions-mutable-action-tag.yml"', self.script)

    def test_allows_exact_tags_shas_and_same_repo_actions(self):
        for uses in (
            "actions/checkout@v4.4.0",
            "kernel/security-workflows/.github/actions/llm-credentials@v1.2.3",
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "$/.github/actions/build",
            "./.github/actions/build",
            "docker://alpine:3",
        ):
            self.assertFalse(self.flagged(uses), uses)

    def test_flags_floating_tags_and_branches(self):
        for uses in ("actions/checkout@v4", "actions/checkout@v4.4", "actions/checkout@main", "actions/setup-node@v4.4.0-beta.1"):
            self.assertTrue(self.flagged(uses), uses)


if __name__ == "__main__":
    unittest.main()
