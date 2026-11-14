"""Checks that workflow `uses:` refs are exact releases recorded in actions.lock.

Run as a script to check every workflow and in-repo action of a checkout:

    python3 action_pins.py [--allow-sha-pins] [ROOT]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / ".github/workflows/actions.lock"
EXACT_TAG = re.compile(r"v\d+\.\d+\.\d+")
SHA = re.compile(r"[0-9a-f]{40}")


def ref_problem(uses: str, entries: list[str] | None, lock: dict, allow_sha_pins: bool = False) -> str | None:
    """Return why `uses` isn't an exact, locked ref, or None if it is.

    `entries` is the file's list under `workflows:` in actions.lock, or None for an in-repo
    action file, whose dependencies are recorded under the workflows that call it.
    """
    if uses.startswith(("$/", "./", "docker://")):
        return None
    name, _, ref = uses.partition("@")
    if not (EXACT_TAG.fullmatch(ref) or SHA.fullmatch(ref)):
        return f"{uses}: ref must be an exact vX.Y.Z tag or a full commit SHA"
    key = "/".join(name.split("/")[:2]) + "@" + ref
    if key not in (lock.get("dependencies") or {}) or (entries is not None and key not in entries):
        return f"{uses}: no actions.lock entry for {key}"
    locked_ref = lock["dependencies"][key]["ref"]
    if SHA.fullmatch(ref) and EXACT_TAG.fullmatch(locked_ref) and not allow_sha_pins:
        return f"{uses}: {ref[:7]} is release {locked_ref}; reference the tag instead"
    return None


def lock_problem(workflow: Path, uses: str) -> str | None:
    """Return why `uses` in `workflow` isn't an exact, locked ref, or None if it is.

    A ref must be an exact vX.Y.Z tag, or a full commit SHA for a commit with no release
    tag. Either way the workflow must be onboarded in actions.lock with an entry for that
    exact ref. `$/` actions always run at the workflow's own commit.
    """
    if uses.startswith("$/"):
        return None
    lock = yaml.safe_load(LOCKFILE.read_text())
    entries = lock["workflows"].get(str(workflow.relative_to(ROOT)), [])
    return ref_problem(uses, entries, lock)


def step_uses(doc: dict) -> list[str]:
    """Every step-level `uses:` in a workflow or composite action document."""
    steps = [s for job in (doc.get("jobs") or {}).values() for s in job.get("steps") or []]
    steps += (doc.get("runs") or {}).get("steps") or []
    return [s["uses"] for s in steps if isinstance(s, dict) and isinstance(s.get("uses"), str)]


def repo_problems(root: Path, allow_sha_pins: bool = False) -> list[str]:
    """Check every workflow and in-repo action under `root`."""
    lockfile = root / ".github/workflows/actions.lock"
    lock = yaml.safe_load(lockfile.read_text()) if lockfile.exists() else {}
    workflows = lock.get("workflows") or {}
    files = sorted(p for p in (root / ".github/workflows").glob("*.y*ml"))
    actions = sorted((root / ".github").glob("actions/**/action.y*ml"))
    problems = []
    for path in files + actions:
        rel = str(path.relative_to(root))
        uses = step_uses(yaml.safe_load(path.read_text()) or {})
        external = [u for u in uses if not u.startswith(("$/", "./", "docker://"))]
        is_workflow = path in files
        if is_workflow and external and rel not in workflows:
            problems.append(f"{rel}: not onboarded in actions.lock; run `gh actions-lock`")
            continue
        entries = workflows.get(rel) if is_workflow else None
        for u in uses:
            if problem := ref_problem(u, entries, lock, allow_sha_pins):
                problems.append(f"{rel}: {problem}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=".", type=Path)
    parser.add_argument("--allow-sha-pins", action="store_true",
                        help="accept SHA pins of tagged releases (generator-owned workflows)")
    args = parser.parse_args()
    problems = repo_problems(args.root.resolve(), args.allow_sha_pins)
    for p in problems:
        print(f"::error::{p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
