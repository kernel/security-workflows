"""Checks that workflow `uses:` refs are exact releases recorded in actions.lock."""
from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LOCKFILE = ROOT / ".github/workflows/actions.lock"
EXACT_TAG = re.compile(r"v\d+\.\d+\.\d+")
SHA = re.compile(r"[0-9a-f]{40}")


def lock_problem(workflow: Path, uses: str) -> str | None:
    """Return why `uses` in `workflow` isn't an exact, locked ref, or None if it is.

    A ref must be an exact vX.Y.Z tag, or a full commit SHA for a commit with no release
    tag. Either way the workflow must be onboarded in actions.lock with an entry for that
    exact ref. `$/` actions always run at the workflow's own commit.
    """
    if uses.startswith("$/"):
        return None
    name, _, ref = uses.partition("@")
    if not (EXACT_TAG.fullmatch(ref) or SHA.fullmatch(ref)):
        return f"{uses}: ref must be an exact vX.Y.Z tag or a full commit SHA"
    lock = yaml.safe_load(LOCKFILE.read_text())
    key = "/".join(name.split("/")[:2]) + "@" + ref
    if key not in lock["workflows"].get(str(workflow.relative_to(ROOT)), []):
        return f"{uses}: {workflow.name} has no actions.lock entry for {key}"
    locked_ref = lock["dependencies"][key]["ref"]
    if SHA.fullmatch(ref) and EXACT_TAG.fullmatch(locked_ref):
        return f"{uses}: {ref[:7]} is release {locked_ref}; reference the tag instead"
    return None
