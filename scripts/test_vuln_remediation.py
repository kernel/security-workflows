#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import vuln_remediation as vr


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class RemediationFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        subprocess.check_call(["git", "init"], cwd=self.root, stdout=subprocess.DEVNULL)
        subprocess.check_call(["git", "config", "user.email", "test@example.com"], cwd=self.root)
        subprocess.check_call(["git", "config", "user.name", "Test"], cwd=self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def commit_all(self) -> None:
        subprocess.check_call(["git", "add", "."], cwd=self.root)
        subprocess.check_call(["git", "commit", "-m", "baseline"], cwd=self.root, stdout=subprocess.DEVNULL)


class NormalizeAndPolicyTests(unittest.TestCase):
    def test_normalizes_socket_cli_alerts_into_flat_alerts(self) -> None:
        report = {
            "alerts": {
                "golang": {
                    "grpc": {
                        "v1.79.1": {
                            "type": "criticalCVE",
                            "policy": "error",
                            "url": "https://socket.dev/golang/package/google.golang.org/grpc/overview/1.79.1",
                            "manifest": ["packages/api/go.mod"],
                            "cve": "CVE-2026-0001",
                            "upgradeVersion": "v1.81.1",
                        }
                    }
                }
            }
        }

        normalized = vr.normalize_input(report)

        self.assertEqual(normalized["alerts"][0]["package"], "google.golang.org/grpc")
        self.assertEqual(normalized["alerts"][0]["ecosystem"], "go")
        self.assertEqual(normalized["alerts"][0]["cve"], "CVE-2026-0001")

    def test_manager_defers_missing_identifiers_and_dev_scope(self) -> None:
        remediation_input = {
            "alerts": [
                {"type": "criticalCVE", "package": "missing-id", "manifest": "go.mod"},
                {"type": "cve", "cve": "CVE-2026-0002", "package": "dev-only", "manifest": "package.json", "dependency_scope": "Development"},
                {"type": "cve", "cve": "CVE-2026-0003", "package": "prod", "manifest": "go.mod"},
            ]
        }
        fix_plan = {
            "type": "only-direct-dependency-upgrades",
            "fixes": {
                "CVE-2026-0002": {"directDependencies": [{"purl": "pkg:npm/dev-only@1.0.0", "fixedVersion": "1.0.1"}]},
                "CVE-2026-0003": {"directDependencies": [{"purl": "pkg:golang/prod@1.0.0", "fixedVersion": "1.0.1"}]},
            },
        }

        context = vr.build_context(remediation_input, fix_plan)

        self.assertEqual([item["id"] for item in context["fixes"]], ["CVE-2026-0003"])
        self.assertEqual(len(context["deferred"]), 2)

    def test_manager_defers_without_socket_fix_plan(self) -> None:
        context = vr.build_context(
            {"alerts": [{"type": "cve", "cve": "CVE-2026-0005", "package": "prod", "manifest": "go.mod"}]},
            {},
        )

        self.assertEqual(context["fixes"], [])
        self.assertEqual(context["deferred"][0]["reason"], "Socket did not return a fix plan for this vulnerability.")

    def test_manager_uses_socket_plan_when_scan_alerts_lack_ids(self) -> None:
        context = vr.build_context(
            {"alerts": [{"type": "criticalCVE", "package": "google.golang.org/grpc", "version": "v1.79.1", "manifest": ["packages/api/go.mod"]}]},
            {
                "type": "only-direct-dependency-upgrades",
                "fixes": {
                    "GHSA-xxxx-yyyy-zzzz": {
                        "directDependencies": [
                            {"purl": "pkg:golang/google.golang.org/grpc@v1.79.1", "fixedVersion": "v1.81.1"}
                        ]
                    }
                },
            },
        )

        self.assertEqual(context["fixes"][0]["id"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(context["fixes"][0]["package"], "google.golang.org/grpc")
        self.assertEqual(context["fixes"][0]["target_version"], "v1.81.1")

    def test_manager_focuses_on_reachable_and_potentially_reachable(self) -> None:
        fix_plan = {
            "type": "only-direct-dependency-upgrades",
            "fixes": {
                "CVE-2026-0006": {"directDependencies": [{"purl": "pkg:npm/prod@1.0.0", "fixedVersion": "1.0.1"}]},
                "CVE-2026-0007": {"directDependencies": [{"purl": "pkg:npm/unreachable@1.0.0", "fixedVersion": "1.0.1"}]},
            },
        }

        context = vr.build_context(
            {
                "alerts": [
                    {"type": "cve", "cve": "CVE-2026-0006", "package": "prod", "manifest": "package.json", "reachability": "Potentially Reachable"},
                    {"type": "cve", "cve": "CVE-2026-0007", "package": "unreachable", "manifest": "package.json", "reachability": "Unreachable"},
                ]
            },
            fix_plan,
        )

        self.assertEqual([item["id"] for item in context["fixes"]], ["CVE-2026-0006"])
        self.assertIn("auto-remediation is limited", context["deferred"][0]["reason"])


class DiffValidatorTests(RemediationFixture):
    def test_rejects_infra_binary_artifacts_like_dns_and_unikraft(self) -> None:
        write(self.root / "go.mod", "module example.com/infra\n")
        self.commit_all()
        write(self.root / "dns/dns", "binary-ish")
        write(self.root / "unikraft/unikraft", "binary-ish")
        os.chmod(self.root / "dns/dns", 0o755)
        os.chmod(self.root / "unikraft/unikraft", 0o755)

        result = vr.validate_diff(self.root, ["dns/dns", "unikraft/unikraft"])

        self.assertFalse(result.ok)
        self.assertIn("dns/dns: only dependency manifests and lockfiles may change", result.errors)
        self.assertIn("unikraft/unikraft: only dependency manifests and lockfiles may change", result.errors)

    def test_rejects_website_source_churn_and_artifacts(self) -> None:
        write(self.root / "package.json", json.dumps({"packageManager": "pnpm@10.30.1", "dependencies": {"react": "19.0.0"}}))
        write(self.root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
        self.commit_all()
        write(self.root / "app/page.tsx", "export default function Page() { return null }\n")
        write(self.root / "fix-result.json", "{}\n")

        result = vr.validate_diff(self.root, ["app/page.tsx", "fix-result.json"])

        self.assertFalse(result.ok)
        self.assertIn("app/page.tsx: only dependency manifests and lockfiles may change", result.errors)
        self.assertIn("fix-result.json: remediation artifact must not be committed", result.errors)

    def test_rejects_hypeman_package_manager_mixing(self) -> None:
        write(self.root / "package.json", json.dumps({"packageManager": "pnpm@10.30.1", "dependencies": {"vite": "6.0.0"}}))
        write(self.root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
        self.commit_all()
        write(self.root / "package-lock.json", "{}\n")

        result = vr.validate_diff(self.root, ["package-lock.json"])

        self.assertFalse(result.ok)
        self.assertIn("package-lock.json: lockfile does not match detected package manager pnpm", result.errors)

    def test_rejects_unplanned_direct_dependency_addition(self) -> None:
        write(self.root / "package.json", json.dumps({"packageManager": "pnpm@10.30.1", "dependencies": {"vite": "6.0.0"}}))
        write(self.root / "pnpm-lock.yaml", "lockfileVersion: '9.0'\n")
        self.commit_all()
        write(self.root / "package.json", json.dumps({"packageManager": "pnpm@10.30.1", "dependencies": {"vite": "6.0.0", "left-pad": "1.3.0"}}))

        result = vr.validate_diff(self.root, ["package.json"], {"fixes": [{"allowed_direct_dependencies": ["vite"]}]})

        self.assertFalse(result.ok)
        self.assertIn("package.json: new direct dependencies not present in Socket fix plan: left-pad", result.errors)

    def test_accepts_clean_socket_planned_dependency_change(self) -> None:
        write(self.root / "go.mod", "module example.com/app\nrequire google.golang.org/grpc v1.79.1\n")
        write(self.root / "go.sum", "google.golang.org/grpc v1.79.1 h1:old\n")
        self.commit_all()
        write(self.root / "go.mod", "module example.com/app\nrequire google.golang.org/grpc v1.81.1\n")
        write(self.root / "go.sum", "google.golang.org/grpc v1.81.1 h1:new\n")

        result = vr.validate_diff(self.root, ["go.mod", "go.sum"])

        self.assertTrue(result.ok, result.errors)


class ConfirmationTests(RemediationFixture):
    def test_confirmation_fails_when_old_vulnerable_version_remains(self) -> None:
        write(self.root / "packages/api/go.mod", "module example.com/api\nrequire google.golang.org/grpc v1.79.1\n")
        self.commit_all()

        result = vr.confirm_fix(
            self.root,
            {
                "fixes": [
                    {
                        "id": "CVE-2026-0004",
                        "package": "google.golang.org/grpc",
                        "old_version": "v1.79.1",
                        "target_version": "v1.81.1",
                        "manifests": ["packages/api/go.mod"],
                    }
                ]
            },
        )

        self.assertFalse(result["ok"])
        self.assertIn("Old vulnerable version v1.79.1 still present", result["failures"][0]["reason"])

    def test_confirmation_succeeds_when_old_version_is_removed(self) -> None:
        write(self.root / "packages/api/go.mod", "module example.com/api\nrequire google.golang.org/grpc v1.81.1\n")
        self.commit_all()

        result = vr.confirm_fix(
            self.root,
            {
                "fixes": [
                    {
                        "id": "CVE-2026-0004",
                        "package": "google.golang.org/grpc",
                        "old_version": "v1.79.1",
                        "target_version": "v1.81.1",
                        "manifests": ["packages/api/go.mod"],
                    }
                ]
            },
        )

        self.assertTrue(result["ok"], result)

    def test_socket_post_plan_confirmation_fails_when_fix_still_planned(self) -> None:
        result = vr.confirm_fix(
            self.root,
            {"fixes": [{"id": "GHSA-xxxx-yyyy-zzzz", "package": "google.golang.org/grpc"}]},
            {"type": "only-direct-dependency-upgrades", "fixes": {"GHSA-xxxx-yyyy-zzzz": {}}},
        )

        self.assertFalse(result["ok"])
        self.assertIn("still reports a fix plan", result["failures"][0]["reason"])

    def test_socket_post_plan_confirmation_succeeds_when_fix_disappears(self) -> None:
        result = vr.confirm_fix(
            self.root,
            {"fixes": [{"id": "GHSA-xxxx-yyyy-zzzz", "package": "google.golang.org/grpc"}]},
            {"type": "only-direct-dependency-upgrades", "fixes": {}},
        )

        self.assertTrue(result["ok"], result)


if __name__ == "__main__":
    unittest.main()
