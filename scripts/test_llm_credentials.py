import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

import yaml

ACTION = Path(__file__).resolve().parents[1] / ".github/actions/llm-credentials"
SCRIPT = ACTION / "llm_credentials.sh"

# Stands in for curl and logs each request. GitHub's OIDC endpoint returns a numbered token naming
# its audience; OpenAI's token endpoint returns $FAKE_OPENAI_RESPONSE, or by default an access
# token naming the GitHub token it was given.
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys, urllib.parse
from pathlib import Path
args = sys.argv[1:]
url = next(a for a in args if a.startswith("http"))
headers = [args[i + 1] for i, a in enumerate(args) if a == "-H"]
body = sys.stdin.read() if "@-" in args else None
with open(os.environ["FAKE_CURL_LOG"], "a") as log:
    log.write(json.dumps({"url": url, "headers": headers, "body": body}) + "\n")
if os.environ.get("FAKE_CURL_FAIL"):
    sys.exit(22)
if url.startswith("https://auth.openai.com/"):
    default = json.dumps({"access_token": "access-for-" + json.loads(body)["subject_token"]})
    print(os.environ.get("FAKE_OPENAI_RESPONSE", default))
else:
    counter = Path(os.environ["FAKE_CURL_LOG"] + ".n")
    n = int(counter.read_text()) + 1 if counter.exists() else 1
    counter.write_text(str(n))
    audience = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["audience"][0]
    print(json.dumps({"value": f"jwt{n}-for-{audience}"}))
'''


class LlmCredentialsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "bin/curl").write_text(FAKE_CURL)
        (self.root / "bin/curl").chmod(0o755)
        self.token_file = self.root / "anthropic-token"
        self.auth = self.root / "pi/auth.json"
        self.env = {
            "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
            "RUNNER_TEMP": str(self.root),
            "FAKE_CURL_LOG": str(self.root / "curl.log"),
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://github.invalid/token?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
            "ANTHROPIC_IDENTITY_TOKEN_FILE": str(self.token_file),
            "OPENAI_IDENTITY_PROVIDER_ID": "idp_test",
            "OPENAI_SERVICE_ACCOUNT_ID": "user-test",
            "OPENAI_WIF_AUDIENCE": "https://api.openai.com/v1",
            "PI_CODING_AGENT_DIR": str(self.root / "pi"),
        }

    def run_script(self, *args, **env):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**self.env, **env},
                              capture_output=True, text=True)

    def requests(self):
        log = self.root / "curl.log"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_anthropic_writes_identity_token(self):
        self.assertEqual(self.run_script("refresh", "anthropic").returncode, 0)
        self.assertEqual(self.token_file.read_text(), "jwt1-for-https://api.anthropic.com")
        [oidc] = self.requests()
        self.assertEqual(oidc["url"], "https://github.invalid/token?api-version=2.0&audience=https%3A%2F%2Fapi.anthropic.com")
        self.assertEqual(oidc["headers"], ["Authorization: Bearer request-token"])

    def test_openai_exchanges_the_github_token(self):
        self.assertEqual(self.run_script("refresh", "openai").returncode, 0)
        oidc, exchange = self.requests()
        self.assertTrue(oidc["url"].endswith("&audience=https%3A%2F%2Fapi.openai.com%2Fv1"))
        self.assertEqual(oidc["headers"], ["Authorization: Bearer request-token"])
        self.assertEqual(exchange["url"], "https://auth.openai.com/oauth/token")
        self.assertEqual(exchange["headers"], ["Content-Type: application/json"])
        self.assertEqual(json.loads(exchange["body"]), {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
            "subject_token": "jwt1-for-https://api.openai.com/v1",
            "identity_provider_id": "idp_test",
            "service_account_id": "user-test",
        })
        self.assertEqual(json.loads(self.auth.read_text()),
                         {"openai": {"type": "api_key", "key": "access-for-jwt1-for-https://api.openai.com/v1"}})
        self.assertEqual(self.auth.stat().st_mode & 0o777, 0o600)

    def test_openai_keeps_other_auth_entries(self):
        self.auth.parent.mkdir()
        self.auth.write_text(json.dumps({"anthropic": {"type": "api_key", "key": "other"},
                                         "openai": {"type": "api_key", "key": "old"}}))
        self.assertEqual(self.run_script("refresh", "openai").returncode, 0)
        auth = json.loads(self.auth.read_text())
        self.assertEqual(auth["anthropic"], {"type": "api_key", "key": "other"})
        self.assertEqual(auth["openai"]["key"], "access-for-jwt1-for-https://api.openai.com/v1")

    def test_failed_refresh_keeps_working_credentials(self):
        self.run_script("refresh", "openai")
        self.run_script("refresh", "anthropic")
        before = {p: p.read_text() for p in (self.auth, self.token_file)}
        for provider in ("openai", "anthropic"):
            self.assertNotEqual(self.run_script("refresh", provider, FAKE_CURL_FAIL="1").returncode, 0)
        # The GitHub token is issued but OpenAI's response has no access token.
        for response in ("{}", '{"error": "invalid_grant"}'):
            self.assertNotEqual(self.run_script("refresh", "openai", FAKE_OPENAI_RESPONSE=response).returncode, 0)
        self.assertEqual({p: p.read_text() for p in before}, before)

    def test_start_refreshes_until_stopped(self):
        self.addCleanup(self.run_script, "stop")
        result = self.run_script("start", "anthropic", LLM_CREDENTIALS_INTERVAL="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.token_file.read_text(), "jwt1-for-https://api.anthropic.com")
        group = int((self.root / "llm-credentials.pid").read_text())
        deadline = time.time() + 10
        while self.token_file.read_text().startswith("jwt1-") and time.time() < deadline:
            time.sleep(0.2)
        self.assertNotEqual(self.token_file.read_text(), "jwt1-for-https://api.anthropic.com")

        stopped = self.run_script("stop")
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        with self.assertRaises(ProcessLookupError):
            os.killpg(group, 0)
        self.assertFalse(self.token_file.exists())
        self.assertFalse((self.root / "llm-credentials.pid").exists())

    def test_stop_removes_openai_entry_and_prints_log(self):
        self.auth.parent.mkdir()
        self.auth.write_text(json.dumps({"anthropic": {"type": "api_key", "key": "other"},
                                         "openai": {"type": "api_key", "key": "access"}}))
        (self.root / "llm-credentials.log").write_text("2026-11-09T00:00:00Z openai credential refresh failed\n")
        stopped = self.run_script("stop")
        self.assertEqual(stopped.returncode, 0, stopped.stderr)
        self.assertEqual(json.loads(self.auth.read_text()), {"anthropic": {"type": "api_key", "key": "other"}})
        self.assertIn("openai credential refresh failed", stopped.stdout)

    def test_stop_without_start_succeeds(self):
        self.assertEqual(self.run_script("stop").returncode, 0)

    def run_action(self, model, **overrides):
        step = yaml.safe_load((ACTION / "action.yml").read_text())["runs"]["steps"][0]
        fake = self.root / "fake-action"
        fake.mkdir(exist_ok=True)
        (fake / "llm_credentials.sh").write_text('echo "$@" > "$FAKE_CREDENTIALS_LOG"\n')
        env = {name: "id-" + name for name in step["env"]}
        env.update(PATH=os.environ["PATH"], MODEL=model, STOP="false", GITHUB_ACTION_PATH=str(fake),
                   GITHUB_ENV=str(self.root / "github-env"), FAKE_CREDENTIALS_LOG=str(self.root / "calls"))
        env.update(overrides)
        for name in ("calls", "github-env"):
            (self.root / name).unlink(missing_ok=True)
        result = subprocess.run(["bash", "-c", step["run"]], env=env, capture_output=True, text=True)
        read = lambda name: (self.root / name).read_text() if (self.root / name).exists() else ""
        return result, read("calls"), read("github-env")

    def test_action_starts_the_model_provider(self):
        _, calls, github_env = self.run_action("anthropic/claude-x")
        self.assertEqual(calls, "start anthropic\n")
        # Later steps run pi, whose Anthropic SDK needs the federation settings.
        self.assertEqual(github_env.splitlines(), [
            f"{name}=id-{name}" for name in ("ANTHROPIC_FEDERATION_RULE_ID", "ANTHROPIC_ORGANIZATION_ID",
                                             "ANTHROPIC_SERVICE_ACCOUNT_ID", "ANTHROPIC_IDENTITY_TOKEN_FILE")])

        _, calls, github_env = self.run_action("openai/gpt-x")
        self.assertEqual(calls, "start openai\n")
        self.assertEqual(github_env, "")

    def test_action_stops(self):
        result, calls, _ = self.run_action("", STOP="true")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, "stop\n")

    def test_action_requires_a_model(self):
        result, calls, _ = self.run_action("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("PI_PREFERRED_MODEL", result.stderr)
        self.assertEqual(calls, "")

    def test_action_requires_the_providers_ids(self):
        for model, name, hint in (("anthropic/claude-x", "ANTHROPIC_FEDERATION_RULE_ID", "anthropic-federation-rule-id"),
                                  ("openai/gpt-x", "OPENAI_WIF_AUDIENCE", "openai-audience")):
            result, calls, _ = self.run_action(model, **{name: ""})
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(hint, result.stderr)
            self.assertIn(f"{name} org variable", result.stderr)
            self.assertEqual(calls, "")

    def test_unknown_provider_fails(self):
        result = self.run_script("start", "google")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("google", result.stderr)


if __name__ == "__main__":
    unittest.main()
