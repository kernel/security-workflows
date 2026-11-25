#!/bin/bash
# Merges the agent's pull request once Cursor Bugbot and every other check have passed on its
# head commit. Runs on the runner, outside the sandbox, so the agent can't skip it.
#
#   merge-gate.sh PR_NUMBER
#
# GH_TOKEN reads checks and statuses (the job's GITHUB_TOKEN). MERGE_TOKEN is an app token that
# can merge. CHECKS_TIMEOUT_MINUTES bounds the wait for pending checks (default 30).
set -euo pipefail

pr=$1
: "${GH_TOKEN:?}" "${MERGE_TOKEN:?}" "${GITHUB_REPOSITORY:?}"
deadline=$(( $(date +%s) + ${CHECKS_TIMEOUT_MINUTES:-30} * 60 ))

state=$(gh pr view "$pr" --repo "$GITHUB_REPOSITORY" --json state --jq .state)
if [ "$state" != OPEN ]; then
  echo "::error::Pull request #$pr is $state; the agent must leave merging to the workflow" >&2
  exit 1
fi
head=$(gh pr view "$pr" --repo "$GITHUB_REPOSITORY" --json headRefOid --jq .headRefOid)

while :; do
  runs=$(gh api "repos/$GITHUB_REPOSITORY/commits/$head/check-runs?filter=latest&per_page=100")
  pending=$(jq -r '[.check_runs[] | select(.status != "completed") | .name] | join(", ")' <<<"$runs")
  bugbot=$(jq -r '[.check_runs[] | select(.name == "Cursor Bugbot")] | sort_by(.completed_at) | last | .status // "missing"' <<<"$runs")
  if [ -z "$pending" ] && [ "$bugbot" != missing ]; then
    break
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "::error::Checks on $head still pending: ${pending:-Cursor Bugbot has not started}" >&2
    exit 1
  fi
  sleep 30
done

bugbot=$(jq -r '[.check_runs[] | select(.name == "Cursor Bugbot")] | sort_by(.completed_at) | last | .conclusion // ""' <<<"$runs")
failed=$(jq -r '[.check_runs[] | select(.conclusion | IN("success", "neutral", "skipped") | not) | "\(.name)=\(.conclusion)"] | join(", ")' <<<"$runs")
status=$(gh api "repos/$GITHUB_REPOSITORY/commits/$head/status")
if [ "$bugbot" != success ] || [ -n "$failed" ]; then
  echo "::error::Not merging #$pr: Cursor Bugbot=${bugbot:-missing}; failed checks: ${failed:-none}" >&2
  exit 1
fi
if [ "$(jq -r .total_count <<<"$status")" -gt 0 ] && [ "$(jq -r .state <<<"$status")" != success ]; then
  echo "::error::Not merging #$pr: commit statuses are $(jq -r .state <<<"$status")" >&2
  exit 1
fi

GH_TOKEN=$MERGE_TOKEN gh pr merge "$pr" --repo "$GITHUB_REPOSITORY" --squash --delete-branch --match-head-commit "$head"
state=$(gh pr view "$pr" --repo "$GITHUB_REPOSITORY" --json state --jq .state)
if [ "$state" != MERGED ]; then
  echo "::error::Pull request #$pr is $state after merging" >&2
  exit 1
fi
echo "Merged #$pr at $head"
