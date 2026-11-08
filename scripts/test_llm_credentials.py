import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "llm_credentials.sh"

# Stands in for curl: GitHub's OIDC endpoint returns a token naming its audience, and OpenAI's
# token endpoint returns an access token naming the GitHub token it was given.
FAKE_CURL = r'''#!/usr/bin/env python3
import json, os, sys, urllib.parse
if os.environ.get("FAKE_CURL_FAIL"):
    sys.exit(22)
url = next(a for a in sys.argv[1:] if a.startswith("http"))
if url.startswith("https://auth.openai.com/"):
    body = json.loads(sys.stdin.read())
    print(json.dumps({"access_token": "access-for-" + body["subject_token"]}))
else:
    audience = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["audience"][0]
    print(json.dumps({"value": "jwt-for-" + audience}))
'''


class LlmCredentialsTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "bin").mkdir()
        (self.root / "bin/curl").write_text(FAKE_CURL)
        (self.root / "bin/curl").chmod(0o755)
        self.env = {
            "PATH": f"{self.root / 'bin'}:{os.environ['PATH']}",
            "ACTIONS_ID_TOKEN_REQUEST_URL": "https://github.invalid/token?api-version=2.0",
            "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "request-token",
            "ANTHROPIC_IDENTITY_TOKEN_FILE": str(self.root / "anthropic-token"),
            "OPENAI_IDENTITY_PROVIDER_ID": "idp_test",
            "OPENAI_SERVICE_ACCOUNT_ID": "user-test",
            "OPENAI_WIF_AUDIENCE": "https://api.openai.com/v1",
            "PI_CODING_AGENT_DIR": str(self.root / "pi"),
        }

    def run_script(self, *args, **env):
        return subprocess.run(["bash", str(SCRIPT), *args], env={**self.env, **env},
                              capture_output=True, text=True)

    def test_anthropic_writes_identity_token(self):
        self.assertEqual(self.run_script("refresh", "anthropic").returncode, 0)
        self.assertEqual((self.root / "anthropic-token").read_text(), "jwt-for-https://api.anthropic.com")

    def test_openai_writes_access_token_to_pi_auth(self):
        self.assertEqual(self.run_script("refresh", "openai").returncode, 0)
        auth = self.root / "pi/auth.json"
        self.assertEqual(json.loads(auth.read_text()),
                         {"openai": {"type": "api_key", "key": "access-for-jwt-for-https://api.openai.com/v1"}})
        self.assertEqual(auth.stat().st_mode & 0o777, 0o600)

    def test_failed_refresh_keeps_working_credentials(self):
        self.run_script("refresh", "openai")
        self.run_script("refresh", "anthropic")
        before = {p: p.read_text() for p in (self.root / "pi/auth.json", self.root / "anthropic-token")}
        for provider in ("openai", "anthropic"):
            self.assertNotEqual(self.run_script("refresh", provider, FAKE_CURL_FAIL="1").returncode, 0)
        self.assertEqual({p: p.read_text() for p in before}, before)

    def test_unknown_provider_fails(self):
        result = self.run_script("start", "google")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("google", result.stderr)


if __name__ == "__main__":
    unittest.main()
