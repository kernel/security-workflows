#!/usr/bin/env python3
"""Socket-centric vulnerability remediation helpers.

This module is intentionally dependency-free so it can run in GitHub Actions
without bootstrapping a Python environment beyond the system interpreter.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ARTIFACT_NAMES = {
    "socket-report.json",
    "socket-raw.json",
    "socket-extracted.json",
    "triage-result.json",
    "fix-result.json",
    "socket-fix-plan.json",
    "remediation-context.json",
    "confirmation-result.json",
    "changed-files.txt",
}

GO_DEP_FILES = {"go.mod", "go.sum"}
NODE_DEP_FILES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "bun.lockb",
}
PYTHON_DEP_FILES = {
    "pyproject.toml",
    "poetry.lock",
    "uv.lock",
    "Pipfile",
    "Pipfile.lock",
}

REQUIREMENTS_RE = re.compile(r"(^|/)requirements[^/]*\.txt$")
MAX_ALLOWED_FILE_SIZE = 5 * 1024 * 1024


def load_json(path: Path, default: Any = None) -> Any:
    if not path.exists():
        return default
    with path.open() as f:
        return json.load(f)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def run_git(args: list[str], cwd: Path) -> str | None:
    try:
        return subprocess.check_output(["git", *args], cwd=cwd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        return None


def package_name_from_socket_key(ecosystem: str, short_name: str, url: str | None) -> str:
    if ecosystem == "golang" and url:
        match = re.search(r"/golang/package/(.+?)(?:/overview|[?#]|$)", url)
        if match:
            return match.group(1)
    return short_name


def normalize_socket_cli_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    nested = report.get("alerts") or {}
    if not isinstance(nested, dict):
        return alerts

    for ecosystem, packages in nested.items():
        if not isinstance(packages, dict):
            continue
        normalized_ecosystem = "go" if ecosystem == "golang" else ecosystem
        for package_key, versions in packages.items():
            if not isinstance(versions, dict):
                continue
            for version, alert in versions.items():
                if not isinstance(alert, dict):
                    continue
                url = alert.get("url")
                alerts.append(
                    {
                        "source": "socket-cli",
                        "category": "vulnerability" if "cve" in str(alert.get("type", "")).lower() else "supplyChainRisk",
                        "type": alert.get("type"),
                        "action": alert.get("policy"),
                        "severity": alert.get("severity") or alert.get("policy"),
                        "ecosystem": normalized_ecosystem,
                        "package": package_name_from_socket_key(ecosystem, package_key, url),
                        "version": version,
                        "manifest": alert.get("manifest") or [],
                        "cve": alert.get("cve"),
                        "ghsa": alert.get("ghsa"),
                        "url": url,
                        "reachability": alert.get("reachability"),
                        "dependency_scope": alert.get("dependencyScope"),
                        "dependency_use": alert.get("dependencyUse"),
                        "upgrade_version": alert.get("upgradeVersion") or alert.get("fixedVersion"),
                    }
                )
    return alerts


def normalize_dashboard_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    for row in rows:
        package_version = row.get("Package") or row.get("Package Name & Version") or ""
        package_name, _, version = package_version.rpartition("@")
        alerts.append(
            {
                "source": "socket-dashboard",
                "key": row.get("Key"),
                "category": row.get("Category"),
                "type": row.get("Type"),
                "action": row.get("Action"),
                "severity": str(row.get("Severity") or "").lower() or None,
                "ecosystem": row.get("Ecosystem"),
                "package": package_name or package_version,
                "version": version or None,
                "repository": row.get("Repository"),
                "branch": row.get("Branch"),
                "manifest": row.get("Manifest") or row.get("Manifest File") or None,
                "cve": row.get("CVE") or None,
                "ghsa": row.get("GHSA") or None,
                "cvss": row.get("CVSS") or None,
                "epss": row.get("EPSS") or None,
                "dependency_type": row.get("Dependency Type") or None,
                "dependency_scope": row.get("Dependency Scope") or None,
                "dependency_use": row.get("Dependency Use") or None,
                "reachability": row.get("Reachability") or None,
                "upgrade_version": row.get("Upgrade Version") or None,
            }
        )
    return alerts


def normalize_input(data: Any) -> dict[str, Any]:
    if isinstance(data, dict) and "alerts" in data and isinstance(data["alerts"], dict):
        alerts = normalize_socket_cli_report(data)
    elif isinstance(data, dict) and "alerts" in data and isinstance(data["alerts"], list):
        alerts = data["alerts"]
    elif isinstance(data, list):
        alerts = normalize_dashboard_rows(data)
    else:
        alerts = []
    return {"alerts": alerts}


def fix_plan_state(plan_entry: dict[str, Any]) -> str:
    return str(plan_entry.get("type") or "")


def build_context(remediation_input: dict[str, Any], fix_plan: dict[str, Any] | None = None, max_fixes: int | None = None) -> dict[str, Any]:
    fix_plan = fix_plan or {}
    plan_by_id = fix_plan.get("fixDetails") or fix_plan.get("fixes") or {}
    default_plan_state = str(fix_plan.get("type") or "")
    items: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for alert in remediation_input.get("alerts", []):
        vuln_id = alert.get("ghsa") or alert.get("cve")
        is_cve = "cve" in str(alert.get("type", "")).lower() or bool(vuln_id)
        if not is_cve:
            deferred.append({**alert, "decision": "defer", "reason": "Non-CVE alert is not handled by dependency remediation."})
            continue
        if not vuln_id:
            deferred.append({**alert, "decision": "defer", "reason": "Missing CVE/GHSA identifier required for Socket fix planning."})
            continue

        plan_entry = plan_by_id.get(vuln_id) or {}
        state = fix_plan_state(plan_entry) or (default_plan_state if plan_entry else "")
        if not state:
            deferred.append({**alert, "decision": "defer", "reason": "Socket did not return a fix plan for this vulnerability."})
            continue
        if state not in {"fixFound", "partialFixFound", "only-direct-dependency-upgrades"}:
            deferred.append({**alert, "decision": "defer", "reason": f"Socket fix planner returned {state}."})
            continue

        if str(alert.get("dependency_scope") or "").lower() == "development":
            deferred.append({**alert, "decision": "defer", "reason": "Development-scope dependency is reported but not auto-fixed."})
            seen_ids.add(vuln_id)
            continue
        reachability = str(alert.get("reachability") or "").lower()
        if reachability and reachability not in {"reachable", "potentially reachable", "potentially_reachable"}:
            deferred.append({**alert, "decision": "defer", "reason": f"Reachability is {alert.get('reachability')}; auto-remediation is limited to reachable or potentially reachable vulnerabilities."})
            seen_ids.add(vuln_id)
            continue

        manifest = alert.get("manifest")
        if isinstance(manifest, list):
            manifests = [m for m in manifest if m]
        elif manifest:
            manifests = [manifest]
        else:
            manifests = []
        if not manifests and plan_entry:
            fixes = ((plan_entry.get("value") or {}).get("fixDetails") or {}).get("fixes") or []
            for fix in fixes:
                manifests.extend(fix.get("manifestFiles") or [])
        if not manifests:
            deferred.append({**alert, "decision": "defer", "reason": "No manifest path available for fix."})
            continue

        items.append(
            {
                "decision": "fix",
                "id": vuln_id,
                "cve": alert.get("cve"),
                "ghsa": alert.get("ghsa"),
                "package": alert.get("package"),
                "ecosystem": alert.get("ecosystem"),
                "old_version": alert.get("version") or version_from_plan(plan_entry),
                "target_version": alert.get("upgrade_version") or target_version_from_plan(plan_entry),
                "manifests": sorted(set(manifests)),
                "socket_plan_state": state,
                "allowed_direct_dependencies": responsible_direct_dependencies(plan_entry),
                "confirmation_method": "socket-post-plan",
            }
        )
        seen_ids.add(vuln_id)

    for vuln_id, plan_entry in sorted_plan_entries(plan_by_id):
        if vuln_id in seen_ids:
            continue
        state = fix_plan_state(plan_entry) or default_plan_state
        if state not in {"fixFound", "partialFixFound", "only-direct-dependency-upgrades"}:
            continue
        direct_deps = responsible_direct_dependencies(plan_entry)
        items.append(
            {
                "decision": "fix",
                "id": vuln_id,
                "cve": vuln_id if str(vuln_id).startswith("CVE-") else None,
                "ghsa": vuln_id if str(vuln_id).startswith("GHSA-") else None,
                "package": ", ".join(direct_deps) or vuln_id,
                "ecosystem": None,
                "old_version": version_from_plan(plan_entry),
                "target_version": target_version_from_plan(plan_entry),
                "manifests": [],
                "socket_plan_state": state,
                "allowed_direct_dependencies": direct_deps,
                "confirmation_method": "socket-post-plan",
            }
        )

    if max_fixes is not None and max_fixes >= 0:
        deferred.extend(
            {**item, "decision": "defer", "reason": f"Deferred to keep this remediation PR limited to {max_fixes} fix(es)."}
            for item in items[max_fixes:]
        )
        items = items[:max_fixes]

    return {"fixes": items, "deferred": deferred}


def sorted_plan_entries(plan_by_id: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    entries = [
        (vuln_id, plan_entry)
        for vuln_id, plan_entry in plan_by_id.items()
        if isinstance(plan_entry, dict)
    ]
    return sorted(entries, key=lambda item: plan_complexity_score(item[0], item[1]))


def plan_complexity_score(vuln_id: str, plan_entry: dict[str, Any]) -> tuple[int, int, int, int, str]:
    direct_dependencies = [
        dependency
        for dependency in plan_entry.get("directDependencies") or []
        if isinstance(dependency, dict)
    ]
    direct_updates = sum(1 for dependency in direct_dependencies if dependency.get("fixedVersion"))
    transitive_updates = sum(len(dependency.get("transitiveFixes") or []) for dependency in direct_dependencies)
    package_count = len(responsible_direct_dependencies(plan_entry))

    # Prefer the fixes Socket is most likely to apply cleanly:
    # direct dependency bumps, fewer packages, fewer transitive edges.
    direct_priority = 0 if direct_updates > 0 else 1
    return (
        direct_priority,
        package_count or 999,
        transitive_updates,
        -direct_updates,
        vuln_id,
    )


def responsible_direct_dependencies(plan_entry: dict[str, Any]) -> list[str]:
    details = ((plan_entry.get("value") or {}).get("fixDetails") or {})
    raw = details.get("responsibleDirectDependencies") or {}
    names: set[str] = set()
    if isinstance(raw, dict):
        for key, value in raw.items():
            names.add(purl_to_name(key))
            if isinstance(value, list):
                names.update(purl_to_name(v) for v in value)
            elif isinstance(value, str):
                names.add(purl_to_name(value))
    direct_dependencies = plan_entry.get("directDependencies") or []
    if isinstance(direct_dependencies, list):
        for dependency in direct_dependencies:
            if isinstance(dependency, dict):
                names.add(purl_to_name(dependency.get("purl", "")))
                for transitive in dependency.get("transitiveFixes") or []:
                    if isinstance(transitive, dict):
                        names.add(purl_to_name(transitive.get("purl", "")))
    return sorted(n for n in names if n)


def target_version_from_plan(plan_entry: dict[str, Any]) -> str | None:
    for dependency in plan_entry.get("directDependencies") or []:
        if isinstance(dependency, dict):
            if dependency.get("fixedVersion"):
                return dependency["fixedVersion"]
            for transitive in dependency.get("transitiveFixes") or []:
                if isinstance(transitive, dict) and transitive.get("fixedVersion"):
                    return transitive["fixedVersion"]
    return None


def version_from_plan(plan_entry: dict[str, Any]) -> str | None:
    for dependency in plan_entry.get("directDependencies") or []:
        if isinstance(dependency, dict) and dependency.get("purl"):
            purl = dependency["purl"]
            if "@" in purl:
                return purl.rsplit("@", 1)[-1]
    return None


def purl_to_name(value: str) -> str:
    value = str(value)
    if value.startswith("pkg:"):
        value = value.split("/", 1)[-1]
    value = value.split("@", 1)[0]
    return value


def is_dependency_file(path: str) -> bool:
    name = Path(path).name
    if name in GO_DEP_FILES or name in NODE_DEP_FILES or name in PYTHON_DEP_FILES:
        return True
    return bool(REQUIREMENTS_RE.search(path))


def package_manager_for_dir(root: Path, directory: Path) -> str | None:
    package_json = directory / "package.json"
    if package_json.exists():
        try:
            package_manager = json.loads(package_json.read_text()).get("packageManager", "")
        except json.JSONDecodeError:
            package_manager = ""
        for manager in ("pnpm", "bun", "yarn", "npm"):
            if package_manager.startswith(manager + "@"):
                return manager

    locks = {
        "pnpm": directory / "pnpm-lock.yaml",
        "bun": directory / "bun.lock",
        "bunb": directory / "bun.lockb",
        "yarn": directory / "yarn.lock",
        "npm": directory / "package-lock.json",
    }
    present = [manager for manager, path in locks.items() if path.exists()]
    if "bun" in present or "bunb" in present:
        return "bun"
    if len(present) == 1:
        return present[0]
    return None


def allowed_node_lock_names(manager: str | None) -> set[str]:
    if manager == "pnpm":
        return {"package.json", "pnpm-lock.yaml"}
    if manager == "bun":
        return {"package.json", "bun.lock", "bun.lockb"}
    if manager == "yarn":
        return {"package.json", "yarn.lock"}
    if manager == "npm":
        return {"package.json", "package-lock.json", "npm-shrinkwrap.json"}
    return NODE_DEP_FILES


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]


def validate_diff(root: Path, changed_files: list[str], context: dict[str, Any] | None = None) -> ValidationResult:
    errors: list[str] = []
    context = context or {}
    allowed_direct_deps = {
        dep
        for fix in context.get("fixes", [])
        for dep in fix.get("allowed_direct_dependencies", [])
    }

    for path in changed_files:
        if not path or path.endswith("/"):
            continue
        rel = Path(path)
        name = rel.name
        full = root / rel

        if name in ARTIFACT_NAMES:
            errors.append(f"{path}: remediation artifact must not be committed")
            continue
        if not is_dependency_file(path):
            errors.append(f"{path}: only dependency manifests and lockfiles may change")
            continue
        if full.exists():
            try:
                mode = full.stat().st_mode
                if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                    errors.append(f"{path}: executable files are not allowed")
                if full.stat().st_size > MAX_ALLOWED_FILE_SIZE:
                    errors.append(f"{path}: file is too large for dependency remediation")
            except OSError as exc:
                errors.append(f"{path}: could not stat file: {exc}")

        if name in NODE_DEP_FILES:
            manager = package_manager_for_dir(root, full.parent)
            if name not in allowed_node_lock_names(manager):
                errors.append(f"{path}: lockfile does not match detected package manager {manager or 'unknown'}")

        if name == "package.json":
            errors.extend(validate_package_json_direct_deps(root, path, allowed_direct_deps))

    return ValidationResult(ok=not errors, errors=errors)


def validate_package_json_direct_deps(root: Path, path: str, allowed_direct_deps: set[str]) -> list[str]:
    current_path = root / path
    if not current_path.exists():
        return []
    old = run_git(["show", f"HEAD:{path}"], root)
    if old is None:
        return []
    try:
        before = json.loads(old)
        after = json.loads(current_path.read_text())
    except json.JSONDecodeError:
        return [f"{path}: invalid package.json"]

    errors: list[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        before_deps = set((before.get(section) or {}).keys())
        after_deps = set((after.get(section) or {}).keys())
        added = after_deps - before_deps
        unexpected = sorted(dep for dep in added if dep not in allowed_direct_deps)
        if unexpected:
            errors.append(f"{path}: new direct dependencies not present in Socket fix plan: {', '.join(unexpected)}")
    return errors


def fix_plan_ids(fix_plan: dict[str, Any] | None) -> set[str]:
    if not fix_plan:
        return set()
    raw = fix_plan.get("fixDetails") or fix_plan.get("fixes") or {}
    if isinstance(raw, dict):
        return set(raw.keys())
    return set()


def confirm_fix(root: Path, context: dict[str, Any], post_fix_plan: dict[str, Any] | None = None) -> dict[str, Any]:
    if post_fix_plan is not None:
        remaining_ids = fix_plan_ids(post_fix_plan)
        confirmed = []
        failures = []
        for fix in context.get("fixes", []):
            if fix.get("id") in remaining_ids:
                failures.append({"id": fix.get("id", ""), "reason": "Socket still reports a fix plan for this vulnerability after applying fixes."})
            else:
                confirmed.append({"id": fix.get("id", ""), "package": fix.get("package", ""), "old_version": fix.get("old_version") or "", "target_version": fix.get("target_version") or ""})
        return {"ok": not failures, "confirmed": confirmed, "failures": failures}

    failures: list[dict[str, str]] = []
    confirmed: list[dict[str, str]] = []
    for fix in context.get("fixes", []):
        old_version = fix.get("old_version")
        package = fix.get("package")
        if not old_version or not package:
            failures.append({"id": fix.get("id", ""), "reason": "Missing package or old version for confirmation."})
            continue
        haystacks = []
        for manifest in fix.get("manifests", []):
            manifest_path = root / manifest
            if manifest_path.exists():
                haystacks.append((manifest, manifest_path.read_text(errors="ignore")))
            sibling_locks = [
                manifest_path.parent / name
                for name in ("go.sum", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "uv.lock", "poetry.lock")
            ]
            for lock in sibling_locks:
                if lock.exists():
                    haystacks.append((str(lock.relative_to(root)), lock.read_text(errors="ignore")))

        needle_patterns = [
            old_version,
            f"{package}@{old_version}",
            f"{package} {old_version}",
        ]
        offenders = [
            path
            for path, content in haystacks
            if any(pattern and pattern in content for pattern in needle_patterns)
        ]
        if offenders:
            failures.append({"id": fix.get("id", ""), "reason": f"Old vulnerable version {old_version} still present in: {', '.join(sorted(set(offenders)))}"})
        else:
            confirmed.append({"id": fix.get("id", ""), "package": package, "old_version": old_version, "target_version": fix.get("target_version") or ""})
    return {"ok": not failures, "confirmed": confirmed, "failures": failures}


def render_pr_body(triage: dict[str, Any], fix_result: dict[str, Any], confirmation: dict[str, Any]) -> str:
    lines = [
        "## Vulnerability Remediation",
        "",
        "> This PR was generated by the Socket-centric vulnerability remediation workflow. Review the planned dependency changes and confirmation evidence before merging.",
        "",
        "### Fixed",
        "| CVE/GHSA | Package | Ecosystem | Old Version | New Version | Manifest | Confirmation |",
        "|---|---|---|---|---|---|---|",
    ]
    confirmed_ids = {item.get("id") for item in confirmation.get("confirmed", [])}
    for item in fix_result.get("fixed", []):
        vuln_id = item.get("ghsa") or item.get("cve") or item.get("id") or "Unavailable from detector"
        status = "confirmed" if vuln_id in confirmed_ids else "unconfirmed"
        lines.append(
            f"| {vuln_id} | {item.get('package','')} | {item.get('ecosystem','')} | {item.get('old_version','')} | {item.get('new_version','')} | {item.get('manifest','')} | {status} |"
        )
    if not fix_result.get("fixed"):
        lines.append("| (none) | | | | | | |")

    lines.extend([
        "",
        "### Deferred / Rejected",
        "| CVE/GHSA | Package | Reason |",
        "|---|---|---|",
    ])
    deferred = triage.get("deferred") or fix_result.get("reverted") or []
    for item in deferred:
        vuln_id = item.get("ghsa") or item.get("cve") or item.get("id") or "Unavailable from detector"
        lines.append(f"| {vuln_id} | {item.get('package','')} | {item.get('reason','')} |")
    if not deferred:
        lines.append("| (none) | | |")
    return "\n".join(lines) + "\n"


def summarize_fix_result(context: dict[str, Any], confirmation: dict[str, Any]) -> dict[str, Any]:
    confirmed_ids = {item.get("id") for item in confirmation.get("confirmed", [])}
    fixed = []
    reverted = []
    for item in context.get("fixes", []):
        if item.get("id") in confirmed_ids:
            fixed.append(
                {
                    "id": item.get("id"),
                    "cve": item.get("cve"),
                    "ghsa": item.get("ghsa"),
                    "package": item.get("package"),
                    "ecosystem": item.get("ecosystem"),
                    "old_version": item.get("old_version"),
                    "new_version": item.get("target_version") or "see lockfile",
                    "manifest": ", ".join(item.get("manifests", [])),
                }
            )
        else:
            reverted.append(
                {
                    "id": item.get("id"),
                    "cve": item.get("cve"),
                    "ghsa": item.get("ghsa"),
                    "package": item.get("package"),
                    "ecosystem": item.get("ecosystem"),
                    "reason": "Fix was not confirmed after dependency updates.",
                }
            )
    return {
        "fixed": fixed,
        "reverted": reverted,
        "summary": f"{len(fixed)} fixed, {len(reverted)} unconfirmed",
    }


def read_changed_files(root: Path, path: Path | None) -> list[str]:
    if path:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    output = run_git(["diff", "--name-only"], root) or ""
    return [line.strip() for line in output.splitlines() if line.strip()]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    normalize = sub.add_parser("normalize")
    normalize.add_argument("--input", required=True, type=Path)
    normalize.add_argument("--output", required=True, type=Path)

    context = sub.add_parser("build-context")
    context.add_argument("--input", required=True, type=Path)
    context.add_argument("--fix-plan", type=Path)
    context.add_argument("--max-fixes", type=int)
    context.add_argument("--output", required=True, type=Path)

    validate = sub.add_parser("validate-diff")
    validate.add_argument("--repo-root", type=Path, default=Path("."))
    validate.add_argument("--context", type=Path)
    validate.add_argument("--changed-files", type=Path)
    validate.add_argument("--output", type=Path)

    confirm = sub.add_parser("confirm")
    confirm.add_argument("--repo-root", type=Path, default=Path("."))
    confirm.add_argument("--context", required=True, type=Path)
    confirm.add_argument("--post-fix-plan", type=Path)
    confirm.add_argument("--output", required=True, type=Path)

    pr_body = sub.add_parser("render-pr-body")
    pr_body.add_argument("--triage", required=True, type=Path)
    pr_body.add_argument("--fix-result", required=True, type=Path)
    pr_body.add_argument("--confirmation", required=True, type=Path)
    pr_body.add_argument("--output", required=True, type=Path)

    summarize = sub.add_parser("summarize-fix")
    summarize.add_argument("--context", required=True, type=Path)
    summarize.add_argument("--confirmation", required=True, type=Path)
    summarize.add_argument("--output", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "normalize":
        write_json(args.output, normalize_input(load_json(args.input, {})))
        return 0
    if args.command == "build-context":
        write_json(args.output, build_context(load_json(args.input, {}), load_json(args.fix_plan, {}) if args.fix_plan else None, args.max_fixes))
        return 0
    if args.command == "validate-diff":
        result = validate_diff(args.repo_root, read_changed_files(args.repo_root, args.changed_files), load_json(args.context, {}) if args.context else {})
        if args.output:
            write_json(args.output, {"ok": result.ok, "errors": result.errors})
        if not result.ok:
            for error in result.errors:
                print(error, file=sys.stderr)
            return 1
        return 0
    if args.command == "confirm":
        result = confirm_fix(args.repo_root, load_json(args.context, {}), load_json(args.post_fix_plan, {}) if args.post_fix_plan else None)
        write_json(args.output, result)
        return 0 if result.get("ok") else 1
    if args.command == "render-pr-body":
        args.output.write_text(render_pr_body(load_json(args.triage, {}), load_json(args.fix_result, {}), load_json(args.confirmation, {})))
        return 0
    if args.command == "summarize-fix":
        write_json(args.output, summarize_fix_result(load_json(args.context, {}), load_json(args.confirmation, {})))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
