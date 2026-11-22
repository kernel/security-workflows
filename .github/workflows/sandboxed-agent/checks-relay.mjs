#!/usr/bin/env node

// Read-only view of a commit's check runs and statuses for the agent. The GitHub App has no
// checks permission and the sandbox proxy replaces any GitHub credential the agent sends, so
// this relay answers with the job's read-only GITHUB_TOKEN, read from stdin.
//
//   GET /check-runs/<sha>   check runs on the commit, latest attempt of each
//   GET /status/<sha>       the commit's combined status
//
// Environment: GITHUB_REPOSITORY, CHECKS_RELAY_PORT.

import { readFileSync } from "node:fs";
import { createServer } from "node:http";

const token = readFileSync(0, "utf8").trim();
const { GITHUB_REPOSITORY: repository, CHECKS_RELAY_PORT: port } = process.env;
if (!token || !repository || !port) {
  throw new Error("a token on stdin, GITHUB_REPOSITORY and CHECKS_RELAY_PORT are required");
}

const routes = {
  "check-runs": (sha) => `commits/${sha}/check-runs?filter=latest&per_page=100`,
  status: (sha) => `commits/${sha}/status`,
};

createServer(async (request, response) => {
  const match = /^\/(check-runs|status)\/([0-9a-f]{40})$/.exec(request.url ?? "");
  if (request.method !== "GET" || !match) {
    response.writeHead(404).end();
    return;
  }
  try {
    const upstream = await fetch(`https://api.github.com/repos/${repository}/${routes[match[1]](match[2])}`, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sandboxed-agent-checks-relay",
      },
    });
    response.writeHead(upstream.status, { "Content-Type": "application/json" }).end(await upstream.text());
  } catch (error) {
    console.error(error.message);
    response.writeHead(502).end();
  }
}).listen(Number(port), "127.0.0.1");
