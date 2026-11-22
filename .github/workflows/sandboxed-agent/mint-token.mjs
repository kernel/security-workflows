#!/usr/bin/env node

// Prints a GitHub App installation token limited to one repository and a fixed set of
// permissions. The sbx daemon runs this on the runner whenever the sandbox's GitHub credential
// needs refreshing, so the private key never enters the sandbox.
//
//   mint-token.mjs CONFIG_JSON
//
// CONFIG_JSON holds appId, installationId, repository, permissions, keyFile and tokensFile.
// Every token is appended to tokensFile so the workflow can revoke them when the job ends.

import { createSign } from "node:crypto";
import { appendFileSync, readFileSync } from "node:fs";

const config = JSON.parse(readFileSync(process.argv[2], "utf8"));
const { appId, installationId, repository, permissions, keyFile, tokensFile } = config;
if (!appId || !installationId || !repository || !permissions || !keyFile || !tokensFile) {
  throw new Error("appId, installationId, repository, permissions, keyFile and tokensFile are required");
}

const now = Math.floor(Date.now() / 1000);
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const unsigned = `${encode({ alg: "RS256", typ: "JWT" })}.${encode({ iat: now - 60, exp: now + 9 * 60, iss: appId })}`;
const signer = createSign("RSA-SHA256");
signer.update(unsigned);
const jwt = `${unsigned}.${signer.sign(readFileSync(keyFile, "utf8").replaceAll("\\n", "\n"), "base64url")}`;

const response = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
  method: "POST",
  headers: {
    Accept: "application/vnd.github+json",
    Authorization: `Bearer ${jwt}`,
    "X-GitHub-Api-Version": "2022-11-28",
    "User-Agent": "sandboxed-agent",
  },
  body: JSON.stringify({ repositories: [repository], permissions }),
});
if (!response.ok) {
  throw new Error(`GitHub App token request failed with HTTP ${response.status}`);
}
const result = await response.json();
if (!result.token) {
  throw new Error("GitHub App token response had no token");
}
appendFileSync(tokensFile, `${result.token}\n`, { mode: 0o600 });
process.stderr.write(`minted a token for ${repository} with ${JSON.stringify(result.permissions)}\n`);
process.stdout.write(result.token);
