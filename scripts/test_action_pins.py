import tempfile
import textwrap
import unittest
from pathlib import Path

from action_pins import repo_problems

TAGGED = "11d5960a326750d5838078e36cf38b85af677262"
UNTAGGED = "af490855f90e83f89dcaf4ea18da962ec294350e"
LOCK = f"""
version: 'v0.0.3'
workflows:
    '.github/workflows/ci.yml':
        - 'actions/checkout@v4.4.0'
        - 'actions/checkout@{TAGGED}'
        - 'kernel/security-workflows@{UNTAGGED}'
    '.github/workflows/caller.yml': []
dependencies:
    'actions/checkout@v4.4.0':
        ref: 'v4.4.0'
        commit: 'sha1-{TAGGED}'
    'actions/checkout@{TAGGED}':
        ref: 'v4.4.0'
        commit: 'sha1-{TAGGED}'
    'kernel/security-workflows@{UNTAGGED}':
        ref: 'main'
        commit: 'sha1-{UNTAGGED}'
"""


class RepoProblemsTest(unittest.TestCase):
    def check(self, uses, lock=LOCK, allow_sha_pins=False, path=".github/workflows/ci.yml"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".github/workflows").mkdir(parents=True)
            if lock is not None:
                (root / ".github/workflows/actions.lock").write_text(lock)
            (root / ".github/workflows/caller.yml").write_text(
                "on: push\njobs:\n  x:\n    uses: kernel/security-workflows/.github/workflows/semgrep.yml@main\n"
            )
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            steps = "".join(f"\n      - uses: {u}" for u in uses)
            if path.endswith("action.yml"):
                target.write_text(f"runs:\n  using: composite\n  steps:{steps.replace(chr(10) + '      ', chr(10) + '    ')}\n")
            else:
                target.write_text(f"on: push\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:{steps}\n")
            return repo_problems(root, allow_sha_pins)

    def test_accepts_exact_tags_untagged_shas_and_local_actions(self):
        uses = [
            "actions/checkout@v4.4.0",
            f"kernel/security-workflows/.github/actions/llm-credentials@{UNTAGGED}",
            "$/.github/actions/build",
            "./.github/actions/build",
            "docker://alpine:3",
        ]
        self.assertEqual(self.check(uses), [])

    def test_rejects_floating_branch_unlocked_and_tagged_sha_refs(self):
        for uses in (
            "actions/checkout@v4",
            "actions/checkout@main",
            "actions/checkout@v4.5.0",
            f"actions/checkout@{TAGGED}",
        ):
            self.assertEqual(len(self.check([uses])), 1, uses)

    def test_allow_sha_pins_accepts_locked_tagged_shas_only(self):
        self.assertEqual(self.check([f"actions/checkout@{TAGGED}"], allow_sha_pins=True), [])
        self.assertEqual(len(self.check(["actions/checkout@v4"], allow_sha_pins=True)), 1)

    def test_workflows_must_be_onboarded(self):
        (problem,) = self.check(["actions/checkout@v4.4.0"], path=".github/workflows/new.yml")
        self.assertIn("not onboarded", problem)
        (problem,) = self.check(["actions/checkout@v4.4.0"], lock=None)
        self.assertIn("not onboarded", problem)

    def test_in_repo_actions_need_a_locked_exact_ref(self):
        path = ".github/actions/build/action.yml"
        self.assertEqual(self.check(["actions/checkout@v4.4.0"], path=path), [])
        self.assertEqual(len(self.check(["actions/checkout@v4"], path=path)), 1)

    def test_reusable_workflow_calls_are_ignored(self):
        self.assertEqual(self.check([]), [])


if __name__ == "__main__":
    unittest.main()
