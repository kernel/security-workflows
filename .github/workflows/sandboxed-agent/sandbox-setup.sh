#!/bin/bash
# Runs inside the sandbox, as its agent user, before the caller's setup. Installs Node.js, Pi and
# Pi Web Access, and the gh and trigger-bugbot helpers, and sets the commit identity.
#
# Needs CHECKS_RELAY_URL, the runner's read-only check-run relay.
set -euo pipefail

: "${CHECKS_RELAY_URL:?}"
export PI_TELEMETRY=0

# Node.js 22, verified against nodejs.org's checksums.
tmp=$(mktemp -d)
base=https://nodejs.org/dist/latest-v22.x
curl -fsSL "$base/SHASUMS256.txt" -o "$tmp/SHASUMS256.txt"
tarball=$(awk '/linux-x64\.tar\.xz$/ { print $2 }' "$tmp/SHASUMS256.txt")
curl -fsSL "$base/$tarball" -o "$tmp/$tarball"
(cd "$tmp" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c --quiet)
sudo tar -xJf "$tmp/$tarball" -C /usr/local --strip-components=1
rm -rf "$tmp"
node --version

sudo npm install -g --ignore-scripts --silent @earendil-works/pi-coding-agent
pi install npm:pi-web-access@latest
pi --version

git config --global user.name "kernel-internal[bot]"
git config --global user.email "260533166+kernel-internal[bot]@users.noreply.github.com"

# The sandbox's GitHub credential is the app's, which can't read check runs. `gh pr checks`
# reads them from the relay instead; every other gh command is passed through.
sudo tee /usr/local/bin/gh >/dev/null <<EOF
#!/bin/bash
set -euo pipefail
if [ "\${1:-}" = pr ] && [ "\${2:-}" = checks ]; then
  shift 2
  sha=\$(/usr/bin/gh pr view "\$@" --json headRefOid --jq .headRefOid)
  runs=\$(curl -fsS "$CHECKS_RELAY_URL/check-runs/\$sha")
  jq -r '.check_runs[] | [.name, .status, (.conclusion // "-")] | @tsv' <<<"\$runs"
  if jq -e '[.check_runs[] | select(.status != "completed")] | length > 0' <<<"\$runs" >/dev/null; then
    exit 8
  fi
  jq -e '[.check_runs[] | select(.conclusion | IN("success", "neutral", "skipped") | not)] | length == 0' <<<"\$runs" >/dev/null
  exit
fi
exec /usr/bin/gh "\$@"
EOF

sudo tee /usr/local/bin/trigger-bugbot >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail
: "${CURSOR_API_KEY:?CURSOR_API_KEY is not set in this sandbox}"
pr_number="${1:-}"
if [ -z "$pr_number" ] || [[ "$pr_number" = -* ]]; then
  echo "A pull request number is required" >&2
  exit 1
fi
pr_url="$(gh pr view "$pr_number" --json url --jq .url)"
response="$(curl --silent --show-error --fail-with-body \
  --request POST \
  --url https://api.cursor.com/bugbot/review \
  --user "$CURSOR_API_KEY:" \
  --header 'Content-Type: application/json' \
  --data "$(jq -cn --arg prUrl "$pr_url" '{prUrl: $prUrl}')")"
jq -e '.outcome == "success"' <<<"$response" >/dev/null
jq -r '"Queued Cursor Bugbot review (request_id: \(.request_id))"' <<<"$response"
EOF
sudo chmod 755 /usr/local/bin/gh /usr/local/bin/trigger-bugbot
